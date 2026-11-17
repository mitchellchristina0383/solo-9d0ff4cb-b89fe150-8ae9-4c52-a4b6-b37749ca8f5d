"""证书持久化与轮换核心逻辑。

存储布局（DATA_DIR，默认 /data/certs）::

    current.json            指向当前现役版本，原子替换
    .rotate.lock            跨进程互斥锁（fcntl.flock）
    v0/cert.pem  key.pem  meta.json
    v1/...
    tmpXXXX/                失败轮换留下的临时目录，启动时可忽略/清理

设计要点：
* 新版本先完整写入临时目录并 fsync，再原子替换 current.json；
  任何校验或保存失败都不会触碰现役版本。
* 轮换采用 CAS（expected_version）：较早发起、写入时已落后的轮换
  会被拒绝，不能覆盖较晚已成功的版本。
* SSLContext 仅从文件加载，因此先在临时文件上试加载，失败即中止。
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import fcntl
import json
import os
import ssl
import tempfile
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

REQUIRED_DNS_NAME = "api.local"
MAX_PEM_BYTES = 64 * 1024


class CertificateError(ValueError):
    """证书内容或私钥不满足换证条件。"""


class StaleVersionError(Exception):
    """expected_version 已落后于现役版本（CAS 冲突）。"""


@dataclasses.dataclass(frozen=True)
class VersionInfo:
    version: int
    fingerprint_sha256: str
    subject_cn: str
    serial_number: str
    not_valid_before: str
    not_valid_after: str
    san_dns_names: tuple[str, ...]
    created_at: str

    @classmethod
    def from_meta(cls, version: int, meta: dict) -> "VersionInfo":
        return cls(
            version=version,
            fingerprint_sha256=meta["fingerprint_sha256"],
            subject_cn=meta.get("subject_cn", ""),
            serial_number=str(meta.get("serial_number", "")),
            not_valid_before=meta["not_valid_before"],
            not_valid_after=meta["not_valid_after"],
            san_dns_names=tuple(meta.get("san_dns_names", ())),
            created_at=meta["created_at"],
        )

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# --------------------------------------------------------------------------- #
# PEM 解析与校验
# --------------------------------------------------------------------------- #

def _read_pem(blob: bytes, field: str) -> bytes:
    if not isinstance(blob, (bytes, bytearray)):
        raise CertificateError(f"{field} 必须是 PEM 字节流")
    data = bytes(blob).strip()
    if not data:
        raise CertificateError(f"{field} 为空")
    if len(data) > MAX_PEM_BYTES:
        raise CertificateError(f"{field} 超过 {MAX_PEM_BYTES} 字节上限")
    if b"-----BEGIN" not in data:
        raise CertificateError(f"{field} 不是 PEM 格式")
    return data


def parse_chain(cert_pem: bytes) -> list[x509.Certificate]:
    data = _read_pem(cert_pem, "证书")
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError as exc:
        raise CertificateError(f"证书 PEM 解析失败: {exc}") from exc
    if not certs:
        raise CertificateError("证书 PEM 中没有任何证书")
    return list(certs)


def parse_private_key(key_pem: bytes):
    data = _read_pem(key_pem, "私钥")
    try:
        return serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise CertificateError(f"私钥 PEM 解析失败（需为无加密 PEM）: {exc}") from exc


def _public_key_der(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _dns_san_covers_api_local(names: Iterable[str]) -> bool:
    for name in names:
        if name == REQUIRED_DNS_NAME:
            return True
        # 通配证书 *.local 覆盖 api.local
        if name.startswith("*.") and REQUIRED_DNS_NAME.endswith(name[1:]) and (
            REQUIRED_DNS_NAME.count(".") == name.count(".")
        ):
            return True
    return False


def validate_certificate(cert_pem: bytes, key_pem: bytes) -> tuple[x509.Certificate, list[x509.Certificate]]:
    """校验证书链与私钥，返回 (叶子证书, 完整链)。

    校验项：
      1. PEM 可解析；
      2. 私钥与叶子证书公钥匹配；
      3. 叶子证书 SAN 覆盖 api.local；
      4. 当前时间处于证书有效期内。
    """
    chain = parse_chain(cert_pem)
    leaf = chain[0]
    key = parse_private_key(key_pem)

    # 2. 私钥匹配
    try:
        key_public_der = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception as exc:  # pragma: no cover - 理论上不会发生
        raise CertificateError(f"私钥无法导出公钥: {exc}") from exc
    if key_public_der != _public_key_der(leaf):
        raise CertificateError("私钥与叶子证书的公钥不匹配")

    # 3. SAN 覆盖 api.local
    try:
        san_ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        dns_names = []
    if not _dns_san_covers_api_local(dns_names):
        raise CertificateError(
            f"证书 SAN 不覆盖 {REQUIRED_DNS_NAME}（当前 SAN: {dns_names or '无'}）"
        )

    # 4. 有效期
    now = _dt.datetime.now(_dt.timezone.utc)
    # cryptography >= 42 提供 *_utc 属性
    if not (leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc):
        raise CertificateError(
            "证书不在有效期内: "
            f"{leaf.not_valid_before_utc.isoformat()} ~ {leaf.not_valid_after_utc.isoformat()}，"
            f"当前 {now.isoformat()}"
        )

    return leaf, chain


def fingerprint_sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def build_meta(leaf: x509.Certificate, version: int) -> dict:
    try:
        san_ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = tuple(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        dns_names = ()
    cn_attrs = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {
        "version": version,
        "fingerprint_sha256": fingerprint_sha256(leaf),
        "subject_cn": cn_attrs[0].value if cn_attrs else "",
        "serial_number": str(leaf.serial_number),
        "not_valid_before": leaf.not_valid_before_utc.isoformat(),
        "not_valid_after": leaf.not_valid_after_utc.isoformat(),
        "san_dns_names": list(dns_names),
        "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }


def try_build_ssl_context(cert_pem: bytes, key_pem: bytes, data_dir: Path) -> None:
    """用临时文件试加载 OpenSSL SSLContext，提前暴露链/密码算法层面的问题。"""
    tmp_dir = data_dir / ".tmpctx"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    cert_file = key_file = None
    try:
        with tempfile.NamedTemporaryFile(dir=tmp_dir, prefix="cert-", suffix=".pem", delete=False) as fh:
            fh.write(cert_pem)
            cert_file = fh.name
        with tempfile.NamedTemporaryFile(dir=tmp_dir, prefix="key-", suffix=".pem", delete=False) as fh:
            fh.write(key_pem)
            key_file = fh.name
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    except ssl.SSLError as exc:
        raise CertificateError(f"OpenSSL 加载证书链失败: {exc}") from exc
    finally:
        for path in (cert_file, key_file):
            if path:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass


# --------------------------------------------------------------------------- #
# 持久化存储
# --------------------------------------------------------------------------- #

class CertificateStore:
    def __init__(self, data_dir: str | os.PathLike = "/data/certs"):
        self.data_dir = Path(data_dir)
        self.versions_dir = self.data_dir / "versions"
        self.current_file = self.data_dir / "current.json"
        self.lock_file = self.data_dir / ".rotate.lock"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.versions_dir.mkdir(parents=True, exist_ok=True)

    # ---------------- 基础工具 ---------------- #

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _lock(self):
        # flock 在文件描述句柄关闭时自动释放；上下文管理器保证异常安全
        fh = open(self.lock_file, "a+")
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        return fh

    def _read_current_version(self) -> int | None:
        try:
            raw = self.current_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        return int(json.loads(raw)["version"])

    def _write_current_pointer(self, version: int) -> None:
        tmp = self.data_dir / "current.json.new"
        tmp.write_text(json.dumps({"version": version}), encoding="utf-8")
        self._fsync_dir(self.data_dir)
        os.replace(tmp, self.current_file)
        self._fsync_dir(self.data_dir)

    def read_state(self) -> VersionInfo | None:
        version = self._read_current_version()
        if version is None:
            return None
        meta_path = self.versions_dir / f"v{version}" / "meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        return VersionInfo.from_meta(version, meta)

    def current_paths(self) -> tuple[Path, Path]:
        version = self._read_current_version()
        if version is None:
            raise FileNotFoundError("尚未初始化任何证书版本")
        base = self.versions_dir / f"v{version}"
        return base / "cert.pem", base / "key.pem"

    # ---------------- 初始自签演示证书 ---------------- #

    def bootstrap(self) -> VersionInfo:
        """若没有任何现役版本，生成覆盖 api.local 的自签演示证书（v0）。"""
        lock = self._lock()
        try:
            existing = self.read_state()
            if existing is not None:
                return existing
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "api.local demo bootstrap")]
            )
            now = _dt.datetime.now(_dt.timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - _dt.timedelta(days=1))
                .not_valid_after(now + _dt.timedelta(days=3650))
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(REQUIRED_DNS_NAME)]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            info = self._persist_locked(cert, cert_pem, key_pem, expected_version=None)
            return info
        finally:
            lock.close()

    # ---------------- 轮换 ---------------- #

    def _persist_locked(
        self,
        leaf: x509.Certificate,
        cert_pem: bytes,
        key_pem: bytes,
        expected_version: int | None,
    ) -> VersionInfo:
        """调用方必须已持有锁。所有落盘步骤完成后才切换 current.json。"""
        current_version = self._read_current_version()
        if expected_version is not None and expected_version != current_version:
            raise StaleVersionError(
                f"expected_version={expected_version}，现役版本已为 {current_version}"
            )

        new_version = 0 if current_version is None else current_version + 1
        tmp_name = tempfile.mkdtemp(prefix=f".tmp-v{new_version}-", dir=self.versions_dir)
        tmp_dir = Path(tmp_name)
        final_dir = self.versions_dir / f"v{new_version}"
        try:
            (tmp_dir / "cert.pem").write_bytes(cert_pem)
            (tmp_dir / "key.pem").write_bytes(key_pem)
            meta = build_meta(leaf, new_version)
            (tmp_dir / "meta.json").write_text(
                json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            # 试构建 SSLContext，失败则整个临时目录作废，现役版本不动
            try_build_ssl_context(cert_pem, key_pem, self.data_dir)
            for name in ("cert.pem", "key.pem", "meta.json"):
                with open(tmp_dir / name, "rb") as fh:
                    os.fsync(fh.fileno())
            self._fsync_dir(tmp_dir)
            # new_version 始终 > 现役版本，故 final_dir 若存在只可能是
            # 上次“目录已替换、指针未写成”的孤儿，可安全清理
            if final_dir.exists():
                import shutil

                shutil.rmtree(final_dir)
            os.replace(tmp_dir, final_dir)
            self._fsync_dir(self.versions_dir)
            self._write_current_pointer(new_version)
            return VersionInfo.from_meta(new_version, meta)
        except BaseException:
            # 清理半成品，保证旧版完整可用
            try:
                for child in tmp_dir.iterdir():
                    child.unlink()
                tmp_dir.rmdir()
            except FileNotFoundError:
                pass
            raise

    def rotate(
        self,
        cert_pem: bytes,
        key_pem: bytes,
        expected_version: int | None = None,
    ) -> tuple[VersionInfo, bool]:
        """校验并轮换证书。

        返回 (新版本信息, 是否实际替换)。指纹与现役相同则为幂等 no-op。
        校验在锁外完成（CPU 密集且不触碰共享状态）；CAS 判定在锁内复核。
        """
        leaf, chain = validate_certificate(cert_pem, key_pem)
        cert_pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in chain)
        key_pem = _read_pem(key_pem, "私钥")

        lock = self._lock()
        try:
            current_version = self._read_current_version()
            if expected_version is not None and expected_version != current_version:
                raise StaleVersionError(
                    f"expected_version={expected_version}，现役版本已为 {current_version}"
                )
            state = self.read_state()
            if state is not None and fingerprint_sha256(leaf) == state.fingerprint_sha256:
                return state, False
            info = self._persist_locked(leaf, cert_pem, key_pem, expected_version)
            return info, True
        finally:
            lock.close()

    def cleanup_temp(self) -> None:
        """启动时清理上次失败遗留的临时目录。"""
        for child in self.versions_dir.iterdir():
            if child.is_dir() and child.name.startswith(".tmp-"):
                for f in child.iterdir():
                    f.unlink()
                child.rmdir()
        tmp_ctx = self.data_dir / ".tmpctx"
        if tmp_ctx.exists():
            for f in tmp_ctx.iterdir():
                f.unlink()
            tmp_ctx.rmdir()


def generate_self_signed_cert(
    dns_names: list[str],
    days_valid: int = 365,
    key_type: str = "rsa",
) -> tuple[bytes, bytes, x509.Certificate]:
    """测试辅助：生成自签证书（PEM cert, PEM key, cert 对象）。"""
    if key_type == "ec":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cn = dns_names[0] if dns_names else "api.local"
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = _dt.datetime.now(_dt.timezone.utc)
    if days_valid < 0:
        # 测试辅助：构造已过期证书，两个时间点都在过去且保持先后顺序
        not_before = now + _dt.timedelta(days=days_valid - 1)
        not_after = now + _dt.timedelta(days=days_valid)
    else:
        not_before = now - _dt.timedelta(days=1)
        not_after = now + _dt.timedelta(days=days_valid)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in dns_names]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem, cert
