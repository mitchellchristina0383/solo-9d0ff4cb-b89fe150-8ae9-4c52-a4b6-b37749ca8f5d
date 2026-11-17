"""测试辅助：multipart 上传、TLS 握手指纹采集。"""

from __future__ import annotations

import hashlib
import http.client
import socket
import ssl
import uuid
from typing import Optional


def build_multipart(
    fields: dict[str, bytes | str],
    plain_fields: dict[str, str] | None = None,
) -> tuple[bytes, str]:
    """构造 multipart/form-data 请求体。

    fields: 文件字段（带 filename）；plain_fields: 普通表单字段（无 filename）。
    """
    boundary = f"----certrotate{uuid.uuid4().hex}"
    body = bytearray()
    for name, value in fields.items():
        if isinstance(value, str):
            value = value.encode()
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(
            f'Content-Disposition: form-data; name="{name}"; filename="{name}.pem"\r\n'.encode()
        )
        body.extend(b"Content-Type: application/x-pem-file\r\n\r\n")
        body.extend(value)
        body.extend(b"\r\n")
    for name, value in (plain_fields or {}).items():
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        body.extend(value.encode())
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())
    return bytes(body), boundary


def post_rotate(
    port: int,
    cert_pem: bytes,
    key_pem: bytes,
    expected_version: Optional[int] = None,
) -> tuple[int, dict]:
    plain = {"expected_version": str(expected_version)} if expected_version is not None else None
    body, boundary = build_multipart(
        {"cert": cert_pem, "key": key_pem}, plain_fields=plain
    )
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    conn.request(
        "POST",
        "/certificates/rotate",
        body=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    resp = conn.getresponse()
    import json

    payload = json.loads(resp.read().decode())
    conn.close()
    return resp.status, payload


def http_get(port: int, path: str) -> tuple[int, dict | str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    raw = resp.read().decode()
    conn.close()
    if "application/json" in resp.getheader("Content-Type", ""):
        import json

        return resp.status, json.loads(raw)
    return resp.status, raw


def tls_handshake_fingerprint(port: int, server_hostname: str = "api.local") -> str:
    """发起一次新握手并返回服务器叶子证书的 SHA256 指纹（hex）。"""
    ctx = ssl._create_unverified_context()
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_hostname) as ssock:
            der = ssock.getpeercert(binary_form=True)
    return hashlib.sha256(der).hexdigest()


def slow_request_on_dedicated_connection(port: int, seconds: float) -> tuple[str, int, bytes]:
    """在独立连接上发起 /slow，返回 (握手时服务器证书指纹, HTTP 状态码, 响应体)。

    连接在换证前建立，整个慢请求期间保持不关闭，用于验证在途请求
    始终由旧证书所在连接处理完成。
    """
    ctx = ssl._create_unverified_context()
    raw = socket.create_connection(("127.0.0.1", port), timeout=15)
    try:
        ssock = ctx.wrap_socket(raw, server_hostname="api.local")
        peer_fp = hashlib.sha256(ssock.getpeercert(binary_form=True)).hexdigest()
        request = (
            f"GET /slow?seconds={seconds} HTTP/1.1\r\n"
            "Host: api.local\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        ssock.sendall(request)
        chunks = []
        while True:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        response = b"".join(chunks)
        status_line = response.split(b"\r\n", 1)[0].decode()
        status_code = int(status_line.split()[1])
        ssock.close()
        return peer_fp, status_code, response
    finally:
        try:
            raw.close()
        except OSError:
            pass
