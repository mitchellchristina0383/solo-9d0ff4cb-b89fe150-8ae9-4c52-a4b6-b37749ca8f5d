"""证书轮换管理接口（FastAPI）。

端点：
* GET  /docs                     Swagger UI，可直接上传 PEM
* GET  /health                   存活探针
* GET  /certificates/current     现役证书版本与指纹
* GET  /certificates/versions    已保存版本列表
* POST /certificates/rotate      上传 PEM 证书链与私钥执行换证

换证规则（详见 app.cert_store.validate_certificate）：
  1. PEM 可解析，私钥为无加密 PKCS#1/PKCS#8；
  2. 私钥与叶子证书公钥匹配；
  3. 叶子证书 SAN 覆盖 api.local（支持 *.local 通配）；
  4. 证书当前处于有效期内。
并发规则：
  * 表单字段 expected_version 用于 CAS：若现役版本已不是该值，返回 409，
    较早发起的换证无法覆盖较晚已成功的版本；
  * 不传 expected_version 时按“锁内复核当前版本”正常轮换。
"""

from __future__ import annotations

import os

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from .cert_store import (
    CertificateError,
    CertificateStore,
    StaleVersionError,
)

DATA_DIR = os.environ.get("CERT_DATA_DIR", "/data/certs")
MAX_UPLOAD = 64 * 1024

app = FastAPI(
    title="api.local 证书轮换管理 API",
    description="上传 PEM 证书链与私钥，在不中断在途请求的前提下热轮换 HTTPS 证书。",
    version="1.0.0",
)
store = CertificateStore(DATA_DIR)


class RotateResponse(BaseModel):
    changed: bool
    current: dict
    detail: str


@app.on_event("startup")
def _startup() -> None:
    # 管理面启动即确保存在 v0 自签演示证书；TLS 服务自身也会 bootstrap，
    # 两者共享同一个 /data/certs 卷，bootstrap 是幂等的。
    store.cleanup_temp()
    store.bootstrap()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/certificates/current")
def current_certificate() -> dict:
    state = store.read_state()
    if state is None:  # 理论上 startup 已 bootstrap
        raise HTTPException(status_code=503, detail="尚无可用证书")
    return state.to_dict()


@app.get("/certificates/versions")
def list_versions() -> dict:
    versions = []
    for meta_path in sorted(
        store.versions_dir.glob("v*/meta.json"),
        key=lambda p: int(p.parent.name[1:]),
    ):
        import json

        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        versions.append(meta)
    return {"count": len(versions), "versions": versions}


@app.post("/certificates/rotate", response_model=RotateResponse)
async def rotate_certificate(
    cert: UploadFile = File(..., description="PEM 证书链（叶子在前，可选含中间 CA）"),
    key: UploadFile = File(..., description="PEM 私钥（无加密）"),
    expected_version: int | None = Form(
        default=None,
        description="CAS：客户端发起时看到的现役版本号；若已被更新则拒绝（409）",
    ),
) -> RotateResponse:
    cert_pem = await cert.read()
    key_pem = await key.read()
    if len(cert_pem) > MAX_UPLOAD or len(key_pem) > MAX_UPLOAD:
        raise HTTPException(status_code=413, detail="上传文件超过 64KiB 上限")

    try:
        info, changed = store.rotate(cert_pem, key_pem, expected_version=expected_version)
    except StaleVersionError as exc:
        state = store.read_state()
        raise HTTPException(
            status_code=409,
            detail={
                "error": str(exc),
                "current_version": state.version if state else None,
            },
        ) from exc
    except CertificateError as exc:
        # 任何校验/保存失败：现役版本未被触碰，旧证书继续服务
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"证书保存失败，旧版继续服务: {exc}") from exc

    return RotateResponse(
        changed=changed,
        current=info.to_dict(),
        detail=("证书已轮换" if changed else "证书指纹与现役相同，未产生新版本"),
    )
