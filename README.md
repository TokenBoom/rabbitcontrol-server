# RabbitControl Server (`TokenBoom/rabbitcontrol-server`)

RabbitControl 独立服务端仓库，包含 **Rust 后端（信令 + 零拷贝 mTLS 中继 + PKI/认证）** 与 **React Web 管理后台**。

## 目录结构

```text
rabbitcontrol-server/
├── README.md
├── LICENSE
├── Dockerfile                     ← 多阶段多架构（linux/amd64 + linux/arm64）构建
├── docker-compose.yml             ← PostgreSQL (+ 可选 Redis profile) + rc-server 编排示例
├── .env.example                   ← 全量环境变量模板
├── .github/workflows/
│   ├── ci.yml                     ← Backend / Admin Web / Docker 构建校验 CI
│   └── docker-release.yml         ← 打 v* tag 自动构建双架构镜像推送 Docker Hub 并创建 Release
├── docs/
│   ├── 00-architecture-draft.md   ← 架构设计与技术选型
│   └── 02-protocol-and-api.md     ← 信令 / UDP 探测 / mTLS Relay / REST API 协议规范
├── backend/                       ← 独立 Rust 服务端 (`rc-server`)
│   ├── Cargo.toml
│   ├── migrations/                ← PostgreSQL migrations
│   └── src/                       ← store / ephemeral / auth / pki / signal / relay / api / net
└── web/                           ← React 19 + TypeScript + Vite 管理后台
```

## 核心能力

- **Rendezvous 信令（`:21116/tcp`，TLS 1.3）**：原生长度前缀 JSON 帧，负责设备绑定、9 位设备码签发与在线管理、UDP 打洞协调（`punch_coord`）与强制 mTLS 中继下发（`relay_ready`）。
- **UDP STUN-lite 探测（`:21116/udp` 主端口 + `:21119/udp` 副端口）**：`RCSP` v1/v2 → `RCSA` 固定报文探测客户端双栈公网 UDP 地址，副端口仅回显 `RCSA` 供客户端判别 NAT 类型（Cone vs Symmetric）。
- **Zero-Copy TCP Relay（`:21117/tcp`，强制 TLS 1.3 mTLS）**：校验证书 SAN `urn:rabbitcontrol:user:{uid}:device:{did}`，在 Linux 上通过 `splice(2)` 内核管道零拷贝转发，非 Linux 自动回退有界用户态拷贝。
- **用户体系、PKI 与 Admin REST API（`:21118/tcp`）**：邮箱登录/注册、Ed25519 Refresh 轮换与多代重放检测、Root CA & 7 天设备证书 CSR 签发、管理员首次登录强制改密与网页端注册开关。

## 环境变量配置

所有运行参数均支持命令行参数或环境变量传入（CLI 优先；Docker/Compose 中的空字符串会自动安全回退到默认值）：

| 环境变量 | 对应参数 | 默认值 | 说明 |
|---|---|---|---|
| `DATABASE_URL` / `RC_DATABASE_URL` | `--database-url` | 必填 | PostgreSQL 连接串（优先 `DATABASE_URL`） |
| `REDIS_URL` / `RC_REDIS_URL` | `--redis-url` | 空（内存回退） | 可选 Redis 连接串（启用分布式缓存与吊销同步） |
| `RC_HTTP_ADDR` | `--http` | `0.0.0.0:21118` | Admin/Auth/PKI REST API 与 Web UI 监听地址（设置 `RC_WEB_ADDR` 时仅保留客户端 API） |
| `RC_WEB_ADDR` | `--web-addr` | 空（合设于 `:21118`） | 可选独立明文 HTTP 监听地址（如 `127.0.0.1:21119` 或容器内 `0.0.0.0:21119`），专供 Nginx TLS 反代托管管理后台与 Admin API |
| `RC_SIGNAL_ADDR` | `--signal` | `0.0.0.0:21116` | TLS 1.3 信令与 UDP 探测监听地址 |
| `RC_UDP_PROBE_ALT_ADDR` | `--udp-probe-alt` | 同 `--signal` IP、端口 `signal+3`（即 `0.0.0.0:21119`） | 第二 UDP STUN-lite 回显端口（仅回复 `RCSA`，不覆写主端点；支持 `disabled` / `none` 关闭） |
| `RC_RELAY_ADDR` | `--relay` | `0.0.0.0:21117` | 强制 TLS 1.3 mTLS 中继监听地址 |
| `RC_LISTEN_BACKLOG` | `--listen-backlog` | `4096` | 所有 TCP 监听器的内核全连接队列上限（需 `>= 1`） |
| `RC_PUBLIC_HOST` | `--public-host` | 自动回退 | 下发给客户端的公网主机名或 IP（并写入服务端 TLS 证书 SAN） |
| `RC_TLS_SAN` | `--tls-san` | 空 | 额外证书 SAN（逗号分隔 DNS 或 IP） |
| `RC_PLAIN_HTTP` | `--plain-http` | `false` | 仅当置于 TLS 反向代理之后时设为 `true`（支持 `true/false/1/0/yes/no/on/off`） |
| `RC_WEB_DIR` | `--web-dir` | 容器内 `/app/web` | 管理后台静态构建产物目录（本地运行可设为 `web/dist`） |
| `RC_INIT_ADMIN_EMAIL` | `--init-admin-email` | `admin@rabbitcontrol.local` | 首次建库无管理员时自动生成的初始管理员邮箱（随机密码打印在首启日志） |
| `RC_ADMIN_TOKEN` | `--admin-token` | 空 | 可选静态管理员 Bearer Token |
| `RC_CORS_ORIGIN` | `--cors-origin` | 空（同源） | 允许的 CORS 来源（逗号分隔或 `*`） |
| `RUST_LOG` / `RC_LOG` | — | `info,rc_server=info,tower_http=info` | 日志过滤规则（`RUST_LOG` 优先，`RC_LOG` 兜底） |

## Docker 构建与运行

```bash
# 1. 本地构建镜像
docker build -t rabbitcontrol-server:local .

# 2. 使用 docker compose 启动（复制并按需修改 .env.example）
cp .env.example .env
docker compose up -d
# 若需启用可选 Redis：
docker compose --profile redis up -d

# 3. 直接使用预构建 Docker Hub 镜像运行
docker run -d --name rc-server \
  -p 21116:21116/tcp -p 21116:21116/udp -p 21119:21119/udp -p 21117:21117/tcp -p 21118:21118/tcp \
  -e DATABASE_URL="postgres://user:pass@pg-host:5432/rabbitcontrol" \
  -e RC_PUBLIC_HOST="your-server-ip-or-domain" \
  <dockerhub-user>/rabbitcontrol-server:v0.1.3
```

## 公网部署与 Nginx 反代管理后台（推荐拆分端口）

若需在公网以正规 HTTPS 域名访问 Web 管理后台，同时保持 `:21118`（桌面客户端内置 Root CA 自动 TOFU 锚定）、`:21116`（TLS 1.3 信令 + UDP 探测）与 `:21117`（强制 mTLS 中继）正常服务：

1. 在 `.env` 中保持 `RC_PLAIN_HTTP=false`，设置 `RC_PUBLIC_HOST=rc.example.com` 与 `RC_WEB_ADDR=0.0.0.0:21119`（二进制直跑可设 `127.0.0.1:21119`）；
2. 在 `docker-compose.yml` 仅向宿主机回环映射 `127.0.0.1:21119:21119/tcp`；
3. 此时 `:21118` 仅提供客户端 API（无静态网页与 Admin 接口），`:21119` 以纯明文 HTTP 专供 Nginx `:443` 反代托管管理后台与 Admin API：

```nginx
server {
    listen 443 ssl http2;
    server_name admin.example.com;

    ssl_certificate     /etc/letsencrypt/live/admin.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/admin.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:21119;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

> **安全提醒**：经 Nginx 反代后，`rc-server` 在 `:21119` 看到的源 IP 恒为 `127.0.0.1`。建议在 Nginx `:443` 的 `/api/v1/auth/` 或整站配置 `limit_req` 限流（或对管理后台域名做源 IP 白名单），避免公网爆破把本地回环限流桶打满。

## 自动发布（Tag → Docker Hub & GitHub Release）

推送 `v*` 标签（例如 `git tag -a v0.1.3 -m "Release v0.1.3" && git push origin v0.1.3`）会触发 [.github/workflows/docker-release.yml](.github/workflows/docker-release.yml)：

- 使用组织/仓库 Secrets `DOCKERHUB_USERNAME` 与 `DOCKERHUB_TOKEN` 登录 Docker Hub；
- 在原生 runner 上并行构建 `linux/amd64` 与 `linux/arm64` 多阶段镜像并推送 digest；
- 自动合并多架构 Manifest（打上 `vX.Y.Z`、`X.Y.Z`、`X.Y`、`latest` 标签）并创建对应 GitHub Release。

## 本地验证

```bash
# Rust 后端
cd backend
cargo fmt -- --check
RUSTFLAGS="-D warnings" cargo clippy --all-targets -- -D warnings
cargo test

# Web 管理后台
cd ../web
npm ci
npx tsc --noEmit
npm run build
```

详见 [docs/00-architecture-draft.md](docs/00-architecture-draft.md) 与 [docs/02-protocol-and-api.md](docs/02-protocol-and-api.md)。
