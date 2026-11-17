# api.local 证书热轮换演示（FastAPI + Python ssl）

值班场景：给 `api.local` 的 HTTPS 入口换证，不中断正在处理的请求。

## 组成

| 组件 | 技术 | 端口 | 职责 |
| --- | --- | --- | --- |
| `mgmt` | FastAPI + uvicorn | 8000 | 管理接口，`/docs` 上传 PEM 证书/私钥、查看现役指纹 |
| `tls` | Python 标准库 `ssl` + `http.server` | 8443 | `api.local` HTTPS 演示服务，轮询热加载证书 |
| 共享卷 `cert-data` | Docker volume | — | 原子化的证书版本存储 `/data/certs` |

## 快速开始

```bash
docker compose up --build
# 管理接口（Swagger UI，可直接上传文件）：
#   http://localhost:8000/docs
# HTTPS 演示服务（自签证书）：
curl -k https://localhost:8443/health
curl -k https://localhost:8443/slow?seconds=5
```

首次启动自动生成覆盖 `api.local` 的自签演示证书 `v0`。

## 换证规则（不满足任意一条即 400，旧证书继续服务）

1. PEM 可解析，私钥为无加密 PEM；
2. 私钥与叶子证书公钥匹配；
3. 叶子证书 SAN 覆盖 `api.local`（支持 `*.local` 通配）；
4. 证书当前处于有效期内；
5. 落盘前再用 `ssl.SSLContext.load_cert_chain` 试加载，OpenSSL 不接受即拒绝。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/certificates/current` | 现役版本号、SHA256 指纹、有效期、SAN |
| GET | `/certificates/versions` | 所有已完整保存的版本 |
| POST | `/certificates/rotate` | multipart 上传 `cert`（PEM 链）、`key`（PEM 私钥）、可选 `expected_version` |

```bash
curl -k -X POST http://localhost:8000/certificates/rotate \
  -F cert=@new.pem -F key=@new.key
# 乐观锁/CAS：发起时看到的版本号，过期则 409
curl -k -X POST http://localhost:8000/certificates/rotate \
  -F cert=@new.pem -F key=@new.key -F expected_version=2
```

## 不中断与一致性设计

- **新握手用新证，老连接跑完老请求**：TLS 服务每条新连接从当前
  `SSLContext` 包装；上下文热切换后，已建立连接仍持有旧上下文。
  `ThreadingHTTPServer` 每连接一线程，`/slow` 可验证在途请求不受影响。
- **原子落盘**：新版本先写临时目录（含 fsync）并试加载，再
  `os.replace` 切换 `current.json`；失败清理半成品，绝不触碰现役版本。
- **交错保护（CAS）**：`expected_version` 与现役版本不符返回 409；
  较早发起的换证无法覆盖较晚已成功的版本。并发写由 `fcntl.flock` 串行化。
- **重启语义**：进程重启后读取最后完整保存的 `current.json` 指向的版本。

## 测试

```bash
pip install -r requirements.txt
PYTHONPATH=. python -m unittest tests.test_cert_store -v   # 单元/并发
PYTHONPATH=. python -m unittest tests.test_e2e -v          # 端到端（真实进程）
```

E2E 覆盖：换证生效、在途慢请求不中断、CAS 交错 409、三类校验失败回退、重启恢复。

## 目录

```
app/cert_store.py   校验、版本化持久化、CAS、并发锁
app/tls_service.py  ssl 热加载 HTTPS 服务（/health、/slow）
app/main.py         FastAPI 管理接口
tests/              单元与端到端测试
docker-compose.yml  mgmt + tls 双服务，共享 cert-data 卷
```
