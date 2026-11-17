"""端到端测试：真实进程启动 uvicorn 管理面与 TLS 演示服务。

覆盖：
  E2E-1 启动即用自签演示证书，/docs 可访问，指纹与管理面一致；
  E2E-2 经管理 API 成功换证，新握手呈现新证书指纹；
  E2E-3 换证期间在途慢请求不中断，且整条连接始终使用旧证书；
  E2E-4 交错换证（CAS）：晚到的旧 expected_version 被 409 拒绝；
  E2E-5 校验失败（私钥不匹配 / SAN 不符 / 过期）返回 400，旧证书继续服务；
  E2E-6 重启 TLS 服务后使用最后完整保存的版本。
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
# 支持 `python -I`：隔离模式忽略 PYTHONPATH，显式加入外部依赖目录（若存在）
_deps = Path("/tmp/pydeps")
if _deps.is_dir():
    sys.path.insert(0, str(_deps))

from app.cert_store import fingerprint_sha256, generate_self_signed_cert  # noqa: E402
from tests.helpers import (  # noqa: E402
    http_get,
    post_rotate,
    slow_request_on_dedicated_connection,
    tls_handshake_fingerprint,
)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class E2ETestCase(unittest.TestCase):
    procs: list[subprocess.Popen] = []
    log_handles: list = []
    data_dir: str = ""
    mgmt_port = 0
    tls_port = 0
    log_dir = ""

    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="certrotate-e2e-data-")
        cls.log_dir = tempfile.mkdtemp(prefix="certrotate-e2e-logs-")
        cls.mgmt_port = free_port()
        cls.tls_port = free_port()
        base_env = os.environ.copy()
        base_env["CERT_DATA_DIR"] = cls.data_dir
        base_env["CERT_POLL_INTERVAL"] = "0.3"
        # 把当前解释器可用的路径（含隔离模式下显式加入的依赖目录）传给子进程
        extra_paths = [str(REPO_ROOT)] + [
            p for p in sys.path if p and Path(p).is_dir() and p != str(REPO_ROOT)
        ]
        base_env["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(extra_paths))

        cls._spawn(
            [sys.executable, "-m", "uvicorn", "app.main:app",
             "--host", "127.0.0.1", "--port", str(cls.mgmt_port)],
            base_env,
            "mgmt.log",
        )
        cls._wait_http(f"http://127.0.0.1:{cls.mgmt_port}/health", timeout=30)

        cls._spawn(
            [sys.executable, "-m", "app.tls_service"],
            {**base_env, "TLS_HOST": "127.0.0.1", "TLS_PORT": str(cls.tls_port)},
            "tls.log",
        )
        cls._wait_tls(timeout=30)

    @classmethod
    def _spawn(cls, cmd, env, log_name):
        log = open(Path(cls.log_dir) / log_name, "wb")
        cls.log_handles.append(log)
        proc = subprocess.Popen(
            cmd, cwd=str(REPO_ROOT), env=env, stdout=log, stderr=subprocess.STDOUT
        )
        cls.procs.append(proc)
        return proc

    @classmethod
    def _wait_http(cls, url, timeout=20):
        import urllib.request

        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline:
            try:
                urllib.request.urlopen(url, timeout=2).read()
                return
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                time.sleep(0.3)
        raise RuntimeError(f"管理面未就绪: {last_err}")

    @classmethod
    def _wait_tls(cls, timeout=20):
        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline:
            try:
                tls_handshake_fingerprint(cls.tls_port)
                return
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                time.sleep(0.3)
        raise RuntimeError(f"TLS 服务未就绪: {last_err}")

    @classmethod
    def tearDownClass(cls):
        for proc in cls.procs:
            proc.terminate()
        for proc in cls.procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        for handle in cls.log_handles:
            handle.close()

    def _wait_handshake_fp(self, expected_fp: str, timeout: float = 10.0) -> None:
        deadline = time.time() + timeout
        seen = ""
        while time.time() < deadline:
            try:
                seen = tls_handshake_fingerprint(self.tls_port)
                if seen == expected_fp:
                    return
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.3)
        self.fail(f"新握手未在 {timeout}s 内呈现期望指纹，最后见到: {seen}")

    def _new_cert(self, dns=("api.local",), days=365):
        cert_pem, key_pem, cert = generate_self_signed_cert(list(dns), days)
        return cert_pem, key_pem, fingerprint_sha256(cert)

    # ------------------------------------------------------------------ #

    def test_01_docs_and_bootstrap_fingerprint(self):
        # /docs Swagger UI 可访问
        status, body = http_get(self.mgmt_port, "/docs")
        self.assertEqual(status, 200)
        self.assertIn("swagger", body.lower())
        status, spec = http_get(self.mgmt_port, "/openapi.json")
        self.assertEqual(status, 200)
        self.assertIn("/certificates/rotate", spec["paths"])
        self.assertIn("/certificates/current", spec["paths"])

        status, current = http_get(self.mgmt_port, "/certificates/current")
        self.assertEqual(status, 200)
        self.assertEqual(current["version"], 0)
        self.assertEqual(
            tls_handshake_fingerprint(self.tls_port),
            current["fingerprint_sha256"],
        )

    def test_02_successful_rotation_takes_effect_on_new_handshakes(self):
        _, before = http_get(self.mgmt_port, "/certificates/current")
        cert_pem, key_pem, new_fp = self._new_cert()

        status, payload = post_rotate(self.mgmt_port, cert_pem, key_pem)
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["changed"])
        self.assertEqual(payload["current"]["version"], before["version"] + 1)
        self.assertEqual(payload["current"]["fingerprint_sha256"], new_fp)

        self._wait_handshake_fp(new_fp)
        status, current = http_get(self.mgmt_port, "/certificates/current")
        self.assertEqual(current["fingerprint_sha256"], new_fp)

    def test_03_inflight_request_completes_on_old_cert(self):
        # 先确认当前基线
        _, current = http_get(self.mgmt_port, "/certificates/current")
        old_fp = current["fingerprint_sha256"]
        self._wait_handshake_fp(old_fp)

        # 在专用连接上发起 6 秒慢请求，连接保持打开
        import threading

        result = {}

        def runner():
            result["value"] = slow_request_on_dedicated_connection(self.tls_port, 6)

        t = threading.Thread(target=runner)
        t.start()
        time.sleep(1.0)  # 确保请求已在服务端处理中

        # 慢请求进行期间换证
        cert_pem, key_pem, new_fp = self._new_cert()
        status, payload = post_rotate(self.mgmt_port, cert_pem, key_pem)
        self.assertEqual(status, 200, payload)

        # 新握手立即（轮询周期内）使用新证书
        self._wait_handshake_fp(new_fp, timeout=8)

        # 等待在途请求完成
        t.join(timeout=15)
        self.assertIn("value", result, "慢请求线程异常结束")
        peer_fp, status_code, response = result["value"]
        self.assertEqual(status_code, 200)
        self.assertIn(b'"status": "ok"', response)
        # 整条连接握手时拿到的是旧证书 → 在途请求未被换证打断
        self.assertEqual(peer_fp, old_fp)
        self.assertNotEqual(old_fp, new_fp)

    def test_04_interleaved_rotation_cas_conflict(self):
        _, current = http_get(self.mgmt_port, "/certificates/current")
        base_version = current["version"]

        # A：基于现役版本，成功
        cert_a, key_a, fp_a = self._new_cert()
        status, payload = post_rotate(
            self.mgmt_port, cert_a, key_a, expected_version=base_version
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["current"]["version"], base_version + 1)
        self._wait_handshake_fp(fp_a)

        # B：较早发起（仍拿着 base_version），此时才到达 → 409，不能覆盖 A
        cert_b, key_b, fp_b = self._new_cert()
        status, payload = post_rotate(
            self.mgmt_port, cert_b, key_b, expected_version=base_version
        )
        self.assertEqual(status, 409, payload)
        self.assertEqual(payload["detail"]["current_version"], base_version + 1)

        # 现役仍是 A 的版本与指纹
        _, current = http_get(self.mgmt_port, "/certificates/current")
        self.assertEqual(current["version"], base_version + 1)
        self.assertEqual(current["fingerprint_sha256"], fp_a)
        self.assertEqual(tls_handshake_fingerprint(self.tls_port), fp_a)

        # B 用最新 expected_version 重试则成功
        status, payload = post_rotate(
            self.mgmt_port, cert_b, key_b, expected_version=base_version + 1
        )
        self.assertEqual(status, 200, payload)
        self._wait_handshake_fp(fp_b)

    def test_05_validation_failures_keep_old_cert_serving(self):
        _, current = http_get(self.mgmt_port, "/certificates/current")
        old_fp = current["fingerprint_sha256"]

        good_cert, _, _ = self._new_cert()
        _, wrong_key, _ = self._new_cert()
        bad_san_cert, bad_san_key, _ = self._new_cert(dns=("wrong.host",))
        expired_cert, expired_key, _ = self._new_cert(days=-5)

        cases = [
            (good_cert, wrong_key, "不匹配"),
            (bad_san_cert, bad_san_key, "SAN"),
            (expired_cert, expired_key, "有效期"),
        ]
        for cert_pem, key_pem, keyword in cases:
            status, payload = post_rotate(self.mgmt_port, cert_pem, key_pem)
            self.assertEqual(status, 400, (keyword, payload))
            self.assertIn(keyword, payload["detail"])

        # 管理面与 TLS 都仍是旧版本
        _, current = http_get(self.mgmt_port, "/certificates/current")
        self.assertEqual(current["fingerprint_sha256"], old_fp)
        self.assertEqual(tls_handshake_fingerprint(self.tls_port), old_fp)

        # 无临时残留；版本列表未增长
        leftovers = list(Path(self.data_dir).glob("versions/.tmp-*"))
        self.assertEqual(leftovers, [])
        status, listing = http_get(self.mgmt_port, "/certificates/versions")
        self.assertEqual(status, 200)
        self.assertEqual(listing["versions"][-1]["fingerprint_sha256"], old_fp)

        # 健康检查仍正常
        import ssl as _ssl
        import urllib.request

        ctx = _ssl._create_unverified_context()
        body = urllib.request.urlopen(
            f"https://127.0.0.1:{self.tls_port}/health", context=ctx, timeout=5
        ).read()
        self.assertIn(b"ok", body)

    def test_06_restart_uses_last_fully_saved_version(self):
        _, current = http_get(self.mgmt_port, "/certificates/current")
        expected_fp = current["fingerprint_sha256"]
        expected_version = current["version"]

        # 找到 TLS 进程并重启
        tls_proc = self.procs[-1]
        tls_proc.terminate()
        tls_proc.wait(timeout=10)
        self.procs.pop()
        self.log_handles.pop().close()

        env = os.environ.copy()
        env["CERT_DATA_DIR"] = self.data_dir
        env["CERT_POLL_INTERVAL"] = "0.3"
        env["TLS_HOST"] = "127.0.0.1"
        env["TLS_PORT"] = str(self.tls_port)
        env["PYTHONPATH"] = os.pathsep.join(
            dict.fromkeys(
                [str(REPO_ROOT)]
                + [p for p in sys.path if p and Path(p).is_dir() and p != str(REPO_ROOT)]
            )
        )
        self._spawn([sys.executable, "-m", "app.tls_service"], env, "tls-restart.log")
        self._wait_tls(timeout=30)

        # 重启后直接呈现最后完整保存的版本
        self.assertEqual(tls_handshake_fingerprint(self.tls_port), expected_fp)
        _, current = http_get(self.mgmt_port, "/certificates/current")
        self.assertEqual(current["version"], expected_version)
        self.assertEqual(current["fingerprint_sha256"], expected_fp)

        # 磁盘上 current.json 与版本目录完整
        pointer = json.loads((Path(self.data_dir) / "current.json").read_text())
        self.assertEqual(pointer["version"], expected_version)
        base = Path(self.data_dir) / f"versions/v{expected_version}"
        for name in ("cert.pem", "key.pem", "meta.json"):
            self.assertTrue((base / name).is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
