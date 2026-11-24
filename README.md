# RabbitControl Server (`TokenBoom/rabbitcontrol-server`)

RabbitControl 独立服务端仓库，包含 **Rust 后端（信令 + 零拷贝 mTLS 中继 + PKI/认证）** 与 **React Web 管理后台**。

## 目录结构

```text
rabbitcontrol-server/
├── README.md
├── LICENSE
├── docs/
│   ├── 00-architecture-draft.md   ← 架构设计与技术选型
│   └── 02-protocol-and-api.md     ← 信令 / UDP 探测 / mTLS Relay / REST API 协议规范
├── backend/                       ← 独立 Rust 服务端 (`rc-server`)
│   ├── Cargo.toml
│   ├── migrations/                ← PostgreSQL migrations
│   └── src/                       ← store / ephemeral / auth / pki / signal / relay / api
└── web/                           ← React 19 + TypeScript + Vite 管理后台
```

## 核心能力

- **Rendezvous 信令（`:21116/tcp`，TLS 1.3）**：原生长度前缀 JSON 帧，负责设备绑定、9 位设备码签发与在线管理、UDP 打洞协调（`punch_coord`）与强制 mTLS 中继下发（`relay_ready`）。
- **UDP STUN-lite 探测（`:21116/udp`）**：`RCSP` / `RCSA` 固定报文探测客户端公网 UDP 地址。
- **Zero-Copy TCP Relay（`:21117/tcp`，强制 TLS 1.3 mTLS）**：校验证书 SAN `urn:rabbitcontrol:user:{uid}:device:{did}`，在 Linux 上通过 `splice(2)` 内核管道零拷贝转发，非 Linux 自动回退有界用户态拷贝。
- **用户体系、PKI 与 Admin REST API（`:21118/tcp`）**：邮箱登录/注册、Ed25519 Refresh 轮换与多代重放检测、Root CA & 7 天设备证书 CSR 签发、管理员首次登录强制改密与网页端注册开关。

## 本地验证

```bash
# Rust 后端
cd backend
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test

# Web 管理后台
cd ../web
npm ci
npx tsc --noEmit
npm run build
```

详见 [docs/00-architecture-draft.md](docs/00-architecture-draft.md) 与 [docs/02-protocol-and-api.md](docs/02-protocol-and-api.md)。
