"""面向 api.local 的 HTTPS 演示服务。

关键能力：
* 使用标准库 ssl.SSLContext，从 CertificateStore 的现役版本文件加载证书；
* 后台线程轮询 current.json，发现新版本即构建新 SSLContext 并原子替换，
  已建立的 TLS 连接仍持有旧 context，会用旧证书把在途请求处理完，
  只有新握手使用新证书；
* /slow 端点模拟耗时请求，用于验证换证不中断在途请求；
* 重载失败时保留上一个可用 context，服务不中断。
"""

from __future__ import annotations

import http.server
import json
import os
import ssl
import threading
import time
from pathlib import Path

from .cert_store import CertificateStore

POLL_INTERVAL = float(os.environ.get("CERT_POLL_INTERVAL", "0.5"))


class RotatingSSLContext:
    """持有当前 SSLContext，按 current.json 版本号热切换。"""

    def __init__(self, store: CertificateStore):
        self._store = store
        self._lock = threading.Lock()
        self._context: ssl.SSLContext | None = None
        self._loaded_version: int | None = None
        self.reload(initial=True)

    @property
    def loaded_version(self) -> int | None:
        return self._loaded_version

    def get(self) -> ssl.SSLContext:
        with self._lock:
            assert self._context is not None
            return self._context

    def reload(self, initial: bool = False) -> bool:
        """检查现役版本是否变化并重新加载。返回是否发生了切换。"""
        try:
            version = self._store._read_current_version()
            if version is None:
                return False
            if not initial and version == self._loaded_version:
                return False
            cert_path, key_path = self._store.current_paths()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # 显式给出最小版本，避免演示环境与系统默认值差异
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
            with self._lock:
                old = self._context
                self._context = ctx
                self._loaded_version = version
            # 旧 context 不主动关闭：正在处理的连接仍在使用它，
            # 等连接结束后由 GC/OpenSSL 自行释放。
            del old
            return True
        except (ssl.SSLError, OSError, FileNotFoundError, json.JSONDecodeError, KeyError) as exc:
            # 落盘已是原子操作，这里主要防御外部误删；保留旧 context 继续服务
            print(f"[tls] 证书重载失败，保留版本 {self._loaded_version}: {exc!r}", flush=True)
            return False

    def watch_forever(self) -> None:
        while True:
            time.sleep(POLL_INTERVAL)
            try:
                if self.reload():
                    print(f"[tls] 已热切换到证书版本 {self._loaded_version}", flush=True)
            except Exception as exc:  # 守护线程绝不能死
                print(f"[tls] 轮询异常（已忽略）: {exc!r}", flush=True)


class DemoHandler(http.server.BaseHTTPRequestHandler):
    server_version = "CertRotateDemo/1.0"

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib 命名
        if self.path in ("/", "/health"):
            self._json(200, {"status": "ok", "service": "https-demo"})
        elif self.path.startswith("/slow"):
            # ?seconds=3，默认 3 秒，上限 30 秒
            from urllib.parse import parse_qs, urlparse

            qs = parse_qs(urlparse(self.path).query)
            try:
                seconds = min(max(float(qs.get("seconds", ["3"])[0]), 0), 30)
            except ValueError:
                seconds = 3
            time.sleep(seconds)
            self._json(200, {"status": "ok", "slept_seconds": seconds})
        else:
            self._json(404, {"detail": "not found"})

    def log_message(self, fmt: str, *args) -> None:  # 安静一点
        print(f"[tls] {self.address_string()} {fmt % args}", flush=True)


class ThreadingHTTPServerTLS(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, rotating_ctx: RotatingSSLContext):
        super().__init__(addr, handler)
        self._rotating_ctx = rotating_ctx

    def get_request(self):
        # 每次新连接用“当前最新”的 context 包装；连接建立后 context
        # 再被替换也不影响这条连接（SSLObject 已固化自己的证书配置）。
        sock, addr = self.socket.accept()
        ctx = self._rotating_ctx.get()
        try:
            tls_sock = ctx.wrap_socket(sock, server_side=True)
        except Exception:
            sock.close()
            raise
        return tls_sock, addr


def serve(data_dir: str, host: str = "0.0.0.0", port: int = 8443) -> None:
    store = CertificateStore(data_dir)
    store.cleanup_temp()
    store.bootstrap()
    rotating_ctx = RotatingSSLContext(store)

    watcher = threading.Thread(
        target=rotating_ctx.watch_forever, name="cert-watcher", daemon=True
    )
    watcher.start()

    server = ThreadingHTTPServerTLS((host, port), DemoHandler, rotating_ctx)
    print(
        f"[tls] HTTPS 演示服务监听 {host}:{port}，"
        f"现役证书版本 v{rotating_ctx.loaded_version}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    serve(
        data_dir=os.environ.get("CERT_DATA_DIR", "/data/certs"),
        host=os.environ.get("TLS_HOST", "0.0.0.0"),
        port=int(os.environ.get("TLS_PORT", "8443")),
    )
