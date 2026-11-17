"""CertificateStore 单元测试：校验规则、原子轮换、CAS、并发交错。"""

from __future__ import annotations

import datetime as _dt
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# 支持 `python -I`：隔离模式忽略 PYTHONPATH，显式加入外部依赖目录（若存在）
_deps = Path("/tmp/pydeps")
if _deps.is_dir():
    sys.path.insert(0, str(_deps))

from app.cert_store import (  # noqa: E402
    CertificateError,
    CertificateStore,
    StaleVersionError,
    generate_self_signed_cert,
)


def make_cert(dns_names, days=365, key_type="rsa"):
    cert_pem, key_pem, cert = generate_self_signed_cert(dns_names, days, key_type)
    return cert_pem, key_pem, cert


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = CertificateStore(self.tmp)

    def test_01_bootstrap_creates_v0(self):
        info = self.store.bootstrap()
        self.assertEqual(info.version, 0)
        self.assertTrue(info.san_dns_names.__contains__("api.local"))
        # 再次 bootstrap 必须幂等
        again = self.store.bootstrap()
        self.assertEqual(again.version, 0)
        self.assertEqual(again.fingerprint_sha256, info.fingerprint_sha256)
        # current.json 指向 v0，文件齐全
        pointer = json.loads((Path(self.tmp) / "current.json").read_text())
        self.assertEqual(pointer["version"], 0)
        for name in ("cert.pem", "key.pem", "meta.json"):
            self.assertTrue((Path(self.tmp) / "versions/v0" / name).is_file())

    def test_02_rotate_success_and_versions_advance(self):
        self.store.bootstrap()
        cert_pem, key_pem, _ = make_cert(["api.local"])
        info, changed = self.store.rotate(cert_pem, key_pem)
        self.assertTrue(changed)
        self.assertEqual(info.version, 1)
        cert2, key2, _ = make_cert(["api.local", "example.com"])
        info2, changed2 = self.store.rotate(cert2, key2)
        self.assertTrue(changed2)
        self.assertEqual(info2.version, 2)
        self.assertEqual(self.store.read_state().version, 2)
        # 旧版本仍完整保留在磁盘
        self.assertTrue((Path(self.tmp) / "versions/v1/cert.pem").is_file())

    def test_03_private_key_mismatch_rejected(self):
        self.store.bootstrap()
        cert_pem, _, _ = make_cert(["api.local"])
        _, other_key, _ = make_cert(["api.local"])
        with self.assertRaises(CertificateError) as cm:
            self.store.rotate(cert_pem, other_key)
        self.assertIn("不匹配", str(cm.exception))
        self.assertEqual(self.store.read_state().version, 0)

    def test_04_san_missing_api_local_rejected(self):
        self.store.bootstrap()
        cert_pem, key_pem, _ = make_cert(["other.example"])
        with self.assertRaises(CertificateError) as cm:
            self.store.rotate(cert_pem, key_pem)
        self.assertIn("SAN", str(cm.exception))
        self.assertEqual(self.store.read_state().version, 0)

    def test_05_wildcard_san_accepted(self):
        self.store.bootstrap()
        cert_pem, key_pem, _ = make_cert(["*.local"])
        info, changed = self.store.rotate(cert_pem, key_pem)
        self.assertTrue(changed)
        self.assertEqual(info.version, 1)

    def test_06_expired_cert_rejected(self):
        self.store.bootstrap()
        cert_pem, key_pem, _ = make_cert(["api.local"], days=-10)
        with self.assertRaises(CertificateError) as cm:
            self.store.rotate(cert_pem, key_pem)
        self.assertIn("有效期", str(cm.exception))
        self.assertEqual(self.store.read_state().version, 0)

    def test_07_not_yet_valid_rejected(self):
        # 手工造一张 not_before 在未来的证书
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        self.store.bootstrap()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.local")])
        now = _dt.datetime.now(_dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + _dt.timedelta(days=2))
            .not_valid_after(now + _dt.timedelta(days=30))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("api.local")]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        from cryptography.hazmat.primitives import serialization

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with self.assertRaises(CertificateError):
            self.store.rotate(cert_pem, key_pem)
        self.assertEqual(self.store.read_state().version, 0)

    def test_08_garbage_pem_rejected(self):
        self.store.bootstrap()
        for bad_cert, bad_key in (
            (b"not a pem", b"-----BEGIN PRIVATE KEY-----\nxxxx\n-----END PRIVATE KEY-----\n"),
            (b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", b"nope"),
        ):
            with self.assertRaises(CertificateError):
                self.store.rotate(bad_cert, bad_key)
        self.assertEqual(self.store.read_state().version, 0)

    def test_09_cas_stale_version_rejected(self):
        self.store.bootstrap()  # v0
        cert1, key1, _ = make_cert(["api.local"])
        info1, _ = self.store.rotate(cert1, key1)  # v1
        self.assertEqual(info1.version, 1)
        # 较早发起（expected=0）的换证此时到达 → 必须 409/Stale
        cert2, key2, _ = make_cert(["api.local"])
        with self.assertRaises(StaleVersionError):
            self.store.rotate(cert2, key2, expected_version=0)
        # 现役仍是 v1，未被晚到的请求覆盖
        self.assertEqual(self.store.read_state().version, 1)
        # 用正确的 expected_version 可以继续
        info2, changed = self.store.rotate(cert2, key2, expected_version=1)
        self.assertTrue(changed)
        self.assertEqual(info2.version, 2)

    def test_10_idempotent_same_fingerprint(self):
        self.store.bootstrap()
        cert_pem, key_pem, _ = make_cert(["api.local"])
        info1, changed1 = self.store.rotate(cert_pem, key_pem)
        self.assertTrue(changed1)
        # 同一份证书再次提交 → no-op，版本不增长
        info2, changed2 = self.store.rotate(cert_pem, key_pem)
        self.assertFalse(changed2)
        self.assertEqual(info2.version, 1)

    def test_11_failed_save_leaves_current_intact(self):
        self.store.bootstrap()
        before = json.loads((Path(self.tmp) / "current.json").read_text())
        # 私钥不匹配 → 在写盘前失败
        cert_pem, _, _ = make_cert(["api.local"])
        _, other_key, _ = make_cert(["api.local"])
        with self.assertRaises(CertificateError):
            self.store.rotate(cert_pem, other_key)
        after = json.loads((Path(self.tmp) / "current.json").read_text())
        self.assertEqual(before, after)
        # 没有遗留临时目录
        leftovers = [
            p.name
            for p in (Path(self.tmp) / "versions").iterdir()
            if p.name.startswith(".tmp-")
        ]
        self.assertEqual(leftovers, [])

    def test_12_concurrent_rotations_no_lost_or_duplicate_versions(self):
        """交错场景：N 个线程并发换证，每个都带“自己发起时看到的版本”。

        只有第一个成功，其余全部 StaleVersionError，最终版本号只 +1，
        证明较早发起者无法覆盖较晚成功者。
        """
        self.store.bootstrap()
        n = 5
        start = threading.Barrier(n)
        results: list[Exception | object] = []

        def worker():
            cert_pem, key_pem, _ = make_cert(["api.local"])
            start.wait()
            try:
                results.append(self.store.rotate(cert_pem, key_pem, expected_version=0))
            except Exception as exc:  # noqa: BLE001
                results.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = [r for r in results if not isinstance(r, Exception)]
        stale = [r for r in results if isinstance(r, StaleVersionError)]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(stale), 4)
        self.assertEqual(self.store.read_state().version, 1)
        # 磁盘上不存在 v2，且没有临时残留
        self.assertFalse((Path(self.tmp) / "versions/v2").exists())

    def test_13_ec_certificate_supported(self):
        self.store.bootstrap()
        cert_pem, key_pem, _ = make_cert(["api.local"], key_type="ec")
        info, changed = self.store.rotate(cert_pem, key_pem)
        self.assertTrue(changed)
        cert_path, key_path = self.store.current_paths()
        # OpenSSL 能直接加载新版本文件
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    def test_14_save_stage_failure_keeps_current_and_cleans_temp(self):
        """模拟落盘后的 OpenSSL 试加载失败：指针不变、临时目录被清理。"""
        import app.cert_store as cs

        self.store.bootstrap()
        before = json.loads((Path(self.tmp) / "current.json").read_text())
        original = cs.try_build_ssl_context

        def boom(cert_pem, key_pem, data_dir):
            raise cs.CertificateError("模拟 OpenSSL 拒绝该证书链")

        cs.try_build_ssl_context = boom
        try:
            cert_pem, key_pem, _ = make_cert(["api.local"])
            with self.assertRaises(cs.CertificateError):
                self.store.rotate(cert_pem, key_pem)
        finally:
            cs.try_build_ssl_context = original

        after = json.loads((Path(self.tmp) / "current.json").read_text())
        self.assertEqual(before, after)
        self.assertEqual(self.store.read_state().version, 0)
        leftovers = list((Path(self.tmp) / "versions").glob(".tmp-*"))
        self.assertEqual(leftovers, [])
        # 恢复后正常轮换仍可成功
        cert_pem, key_pem, _ = make_cert(["api.local"])
        info, changed = self.store.rotate(cert_pem, key_pem)
        self.assertTrue(changed)
        self.assertEqual(info.version, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
