# RabbitControl Rust Server Protocol & API Specification (v1)

> Status: **Active (Phase 1)**
> Applies to: `server/backend/` (`rc-server`, standalone Rust workspace)

This document defines the exact wire protocols, storage contracts, and HTTP REST API exposed by the RabbitControl Rust server (`rc-server`):

1. **Ports & Architecture Summary** (NO WebSocket)
2. **Native TCP Framed Signaling Protocol** (`:21116/tcp`, `[u32 BE len][UTF-8 JSON]`)
3. **UDP STUN-lite Public Endpoint Probe Protocol** (`:21116/udp`, `RCSP` / `RCSA`)
4. **Zero-Copy TCP Relay Protocol** (`:21117/tcp`, `RCR1` handshake + Linux `splice(2)` raw stream)
5. **Axum 0.8 REST API** (`:21118/tcp`, `/api/v1/*`)
6. **Storage Architecture** (PostgreSQL `sqlx` + Optional Redis / Default `DashMap`)
7. **Account Auth, Admin Bootstrapping, Owner Self-Control & Mandatory Relay mTLS**
8. **Unified Error Code Contract** (`TokenBoom/rabbitcontrol-spec`)

---

## 1. Ports & Default Endpoints

| Service | Default Listen | Transport | Purpose |
|---|---|---|---|
| Native TCP Signaling | `:21116` | TCP (`TCP_NODELAY=true`, TLS 1.3 default; `--no-tls` opt-out) | Framed JSON signaling (**NO WebSocket**): device/owner registration (`access_token`, `device_pubkey`), `UpdateAssistState`, `DeviceStatusChanged`, P2P punch coordination (`punch_coord` with dual-stack endpoints & NAT hints) & `OwnerGrantTicket` issuance, relay token allocation, device/user kick |
| UDP STUN-lite Probe (Primary) | `:21116` | UDP | Dual-stack public `IP:Port` discovery (`RCSP` v1/v2 → `RCSA`) and `EphemeralStore` NAT mapping publication |
| UDP STUN-lite Probe (Secondary) | `:21119` (configurable via `--udp-probe-alt` / `RC_UDP_PROBE_ALT_ADDR`; defaults to `--signal` IP + port+3, `"disabled"`/`"none"` to disable) | UDP | Echo-only `RCSA` probe target for client-side Cone vs Symmetric NAT classification; shares per-IP rate limiter and **never** overwrites `EphemeralStore` |
| mTLS TCP Relay | `:21117` | TCP (`TCP_NODELAY=true`, mandatory TLS 1.3 mTLS) | Mutual-TLS authenticated full-duplex relay with `RCR1` header & SAN (`urn:rabbitcontrol:user:{uid}:device:{did}`) binding + serial revocation check |
| Axum 0.8 REST API / Admin Web | `:21118` | HTTP/1.1 (TLS-capable via `rc-server`) | Health check, Root CA fetch, Auth/Refresh/ChangePassword/Logout, CSR device cert issue, My Devices bind/rename/unbind, plus Admin routes & Admin Web UI unless `--web-addr` / `RC_WEB_ADDR` is set |
| Split Admin Web UI / Admin REST API (optional) | `--web-addr` / `RC_WEB_ADDR` | Plain HTTP/1.1 (reverse proxy only) | When configured, serves `RC_WEB_DIR` SPA static bundle + `/api/v1/health`, `/api/v1/pki/ca`, `/api/v1/auth/{login,refresh,logout,change-password}`, `/api/v1/me`, and all admin endpoints (`/api/v1/admin/*`, `/api/v1/stats`, `/api/v1/devices*`, `/api/v1/sessions*`); `:21118` drops admin routes & SPA hosting (`ClientApiOnly`) |

---

## 2. Native TCP Framed Signaling Protocol (`:21116/tcp`)

Signaling runs directly over TCP with `TCP_NODELAY = true`. **WebSocket is NOT used.**

### 2.1 Wire Framing

Every message in both directions is length-prefixed:

```text
+-------------------------------+----------------------------------------+
| Length (u32 big-endian, 4 B)  | UTF-8 JSON Payload (Length bytes)      |
| valid range: 1..=65536        | {"type": "...", ...}                   |
+-------------------------------+----------------------------------------+
```

- `length == 0` or `length > 65536` is a protocol error; the peer connection is closed.
- Payloads are tagged JSON objects discriminated by `"type"` (`snake_case`).
- **Backpressure isolation**: each connected peer is backed by a bounded `tokio::sync::mpsc::Sender<SignalMsg>` channel; hub fan-out uses non-blocking `try_send` so a stalled peer can never block other peers.

### 2.2 Session Lifecycle

1. Immediately after TCP connect, the client **MUST** send a `register` frame within the handshake timeout (default `10s`). Any other first frame is rejected with `error` (`code = "expected_register"`) and the connection is closed.
2. The server resolves/issues a permanent 9-digit `device_id` (`100000000..=999999999`) idempotently by `device_key` via `DeviceStore`.
   - If the device is marked `disabled = true`, the server replies with `error` (`code = "device_disabled"`) and closes the connection.
   - If the client also supplied `device_id` and it does not match the stored `device_id` for `device_key`, the server replies with `error` (`code = "device_id_mismatch"`) and closes.
   - If another TCP connection is already registered under the same `device_id`, the older connection is sent `kicked` (`reason = "replaced_by_new_connection"`) and closed.
3. On success, the server marks the device online in `EphemeralStore` and replies with `registered`.

### 2.3 Message Types

#### `register` (Client -> Server)

```json
{
  "type": "register",
  "device_id": "123456789",
  "device_key": "ed25519:7a9f2c...",
  "hostname": "macbook-pro",
  "os": "macos",
  "app_version": "0.1.10",
  "arch": "arm64",
  "device_group": "default",
  "lan_addrs": ["192.168.1.10:50000"],
  "access_token": "<optional-jwt>",
  "device_pubkey": "<optional-ed25519-hex>",
  "allow_remote_assist": false,
  "allow_remote_control": true,
  "mac_addr": "aa:bb:cc:dd:ee:ff",
  "wol_enabled": true,
  "nat_type": "cone",
  "nat_port_delta": 0
}
```

- `device_key` (required): stable unique identifier (1–256 chars).
- `device_id` (optional): if provided, verified against the resolved permanent 9-digit ID.
- `hostname`, `os`, `app_version` (≤32 UTF-8 bytes), `arch` (≤32 UTF-8 bytes), `device_group` (alias `"group"`), `lan_addrs`: optional metadata (backward-compatible with older clients; empty strings preserve previously stored values).
- `allow_remote_control` (optional bool): gates **all** incoming remote control connections (including same-account owner self-control). When explicitly provided (`Some(v)`), persisted immediately. When omitted (`None`, older clients), newly registered devices default via `default_allow_remote_control_for_os(os)` (`false` when `os` contains `android` or `ios` case-insensitively, `true` otherwise), while existing devices preserve their stored DB value (converging to `false` if their previously empty `os` is populated with an Android/iOS OS).
- `allow_remote_assist` (optional bool): gates non-owner third-party assistance (effective only when `allow_remote_control == true`).
- `mac_addr` (optional string): primary Ethernet/Wi-Fi unicast MAC address for Wake-on-LAN (`:` or `-` separated 6 hex bytes, normalized to lowercase `"aa:bb:cc:dd:ee:ff"`). All-zero (`00:00:00:00:00:00`), broadcast (`ff:ff:ff:ff:ff:ff`), and multicast (`(b0 & 0x01) != 0`) MACs are strictly rejected with `error` (`code = "invalid_input"`). When omitted or empty, previously stored `mac_addr` is preserved.
- `wol_enabled` (optional bool): whether this device allows Wake-on-LAN remote wake by its account owner (defaults to `false`; omitted preserves the stored DB value).
- `nat_type` (optional string): client-classified NAT behavior (`"unknown"`, `"cone"`, `"symmetric_seq"`, `"symmetric_random"`, normalized case-insensitively; unrecognized values are safely ignored as `None`).
- `nat_port_delta` (optional `i16`): observed sequential NAT port allocation step, clamped to `-1024..=1024`.
- `device_status_changed` broadcasts and `/api/v1/me/devices`, `/api/v1/devices` views also expose `app_version`, `arch`, `allow_remote_assist`, `allow_remote_control`, and `wol_capable` (`wol_enabled && valid(mac_addr)`). Raw `mac_addr` is **never** exposed in device list or status broadcasts.

#### `update_assist_state` (Client -> Server)

Updates the device's remote-assist, remote-control, and/or Wake-on-LAN configuration in real time, persisting to `DeviceStore`, updating active peer state, and broadcasting `device_status_changed` to same-account online peers.

```json
{
  "type": "update_assist_state",
  "allow_remote_assist": false,
  "allow_remote_control": true,
  "mac_addr": "aa:bb:cc:dd:ee:ff",
  "wol_enabled": true
}
```

- `allow_remote_assist` (optional bool): whether non-owner third-party assistance is allowed; when omitted (`None`), preserves the existing stored value without modification.
- `allow_remote_control` (optional bool): when provided (`Some(v)`), persists and updates `allow_remote_control`; when omitted (`None`, older clients), preserves the existing stored value without modification.
- `mac_addr` (optional string): optional unicast MAC address (`aa:bb:cc:dd:ee:ff`); validated with the same strict rules as `register`.
- `wol_enabled` (optional bool): optional Wake-on-LAN opt-in flag; omitted preserves the existing stored value.
- At least one of `allow_remote_assist`, `allow_remote_control`, `mac_addr`, or `wol_enabled` must be present (otherwise the server responds with `error` `code = "invalid_payload"`). If persistence fails or affects 0 rows, the server returns an `error` frame without mutating in-memory peer state or broadcasting `device_status_changed`.

#### `device_status_changed` (Server -> Same-Account Online Peers)

```json
{
  "type": "device_status_changed",
  "device_id": "123456789",
  "online": true,
  "hostname": "macbook-pro",
  "alias": "Work Mac",
  "os": "macos",
  "app_version": "0.1.10",
  "arch": "arm64",
  "allow_remote_assist": false,
  "allow_remote_control": true,
  "wol_capable": true
}
```

Pushed to other online peers belonging to the same `owner_user_id` on register (online), disconnect/kick (offline), `update_assist_state`, and `heartbeat` (when `wol_capable` changes). `wol_capable` is `true` iff `wol_enabled == true` and a valid unicast `mac_addr` is stored; raw `mac_addr` is never included. On REST `PATCH /api/v1/me/devices/{id}`, `device_status_changed` is pushed both to other same-account online peers **and** to the target device itself (if online) so the device can synchronize its local policy cache without stale overwrite on reconnect.

#### `registered` (Server -> Client)

```json
{
  "type": "registered",
  "device_id": "123456789",
  "formatted_id": "123 456 789",
  "server_time": "2026-11-22T10:00:00Z",
  "udp_probe_addr": "172.16.1.2:21116",
  "udp_probe_alt_addr": "172.16.1.2:21119",
  "udp_probe_token": "0123456789abcdef0123456789abcdef",
  "relay_addr": "172.16.1.2:21117"
}
```

- `udp_probe_alt_addr` (optional string, omitted when disabled): secondary UDP STUN-lite echo-only endpoint (`:21119/udp` by default) used to distinguish Cone vs Symmetric NAT.
- `udp_probe_token` (optional string): 32-char lowercase hex encoding of a random 16-byte per-connection probe token used in `RCSP v2` packets for constant-time cross-IP/dual-stack endpoint authentication.

#### `heartbeat` (Client -> Server)

Refreshes online TTL in `EphemeralStore`, updates `last_seen_at`, `last_lan_addrs`, and `last_public_ip` in `DeviceStore`, and optionally synchronizes `mac_addr` / `wol_enabled` and NAT telemetry (`nat_type`, `nat_port_delta`).

```json
{
  "type": "heartbeat",
  "lan_addrs": ["192.168.1.10:50000"],
  "mac_addr": "aa:bb:cc:dd:ee:ff",
  "wol_enabled": true,
  "nat_type": "cone",
  "nat_port_delta": 0
}
```

- `mac_addr` (optional string) and `wol_enabled` (optional bool): backward-compatible optional fields; omitted preserves stored values. Invalid non-empty `mac_addr` returns `error` (`code = "invalid_input"`).
- `nat_type` / `nat_port_delta` (optional): updates the peer's in-memory NAT profile using the same whitelist/clamping rules as `register`.

#### `heartbeat_ack` (Server -> Client)

```json
{
  "type": "heartbeat_ack",
  "server_time": "2026-11-22T10:00:25Z",
  "public_udp_addr": "203.0.113.10:51234",
  "online_peers": 42
}
```

#### `connect_request` (Client -> Server)

Initiates P2P hole-punching coordination with `target_id`.

```json
{
  "type": "connect_request",
  "target_id": "987654321",
  "session_id": "optional-session-id",
  "lan_addrs": ["192.168.1.10:50000"],
  "nonce": "a1b2c3d4",
  "nat_type": "cone",
  "nat_port_delta": 0
}
```

- `nat_type` / `nat_port_delta` (optional): updates the caller's in-memory NAT profile before issuing `punch_coord`.
- If `target_id` is offline, the server responds only to the requester with `peer_offline`.
- If `target_id` is online, the server reads both sides' observed public UDP endpoints (`get_public_udp` and dual-stack `get_public_udp_all`) from `EphemeralStore`, allocates a one-time fallback `relay_token` in `EphemeralStore`, and pushes `punch_coord` to **both** the client (`role = "client"`) and target host (`role = "host"`).

#### `punch_coord` (Server -> Both Peers)

```json
{
  "type": "punch_coord",
  "session_id": "f3a1c9...",
  "role": "client",
  "peer_id": "987654321",
  "peer_public_udp_addr": "198.51.100.22:60123",
  "peer_public_udp_addrs": ["[2001:db8::22]:60124", "198.51.100.22:60123"],
  "self_public_udp_addr": "203.0.113.10:51234",
  "peer_nat_type": "symmetric_seq",
  "peer_nat_port_delta": 3,
  "peer_lan_addrs": ["192.168.1.20:50000"],
  "nonce": "a1b2c3d4",
  "relay_token": "9f8e7d6c...",
  "relay_addr": "172.16.1.2:21117"
}
```

- `peer_public_udp_addr`: legacy primary observed public UDP address of the peer (kept for backward compatibility).
- `peer_public_udp_addrs` (optional array, omitted when empty): all non-expired dual-stack public UDP addresses of the peer (IPv6 + IPv4, deduplicated).
- `self_public_udp_addr` (optional string): the recipient's own observed public UDP address (for hairpin / same-public-IP detection).
- `peer_nat_type` / `peer_nat_port_delta` (optional): the peer's normalized NAT classification and port step hint.

#### `relay_alloc` (Client -> Server)

Explicitly requests a fresh one-time TCP Relay token when P2P hole-punching fails or is bypassed.

```json
{
  "type": "relay_alloc",
  "target_id": "987654321",
  "session_id": "f3a1c9..."
}
```

- If `target_id` is offline, responds with `peer_offline`.
- Otherwise stores a new `RelayTokenRecord` in `EphemeralStore` and pushes `relay_ready` to **both** peers.

#### `relay_ready` (Server -> Both Peers)

```json
{
  "type": "relay_ready",
  "session_id": "f3a1c9...",
  "role": "client",
  "peer_id": "987654321",
  "relay_token": "4b5c6d7e...",
  "relay_addr": "172.16.1.2:21117",
  "expires_in_sec": 60
}
```

#### `peer_offline` (Server -> Client)

```json
{
  "type": "peer_offline",
  "target_id": "987654321",
  "session_id": "f3a1c9..."
}
```

#### `wol_request` (Client -> Server)

Requests the server to wake an offline device owned by the **same authenticated user account** via Wake-on-LAN.

```json
{
  "type": "wol_request",
  "request_id": "optional-req-id",
  "target_device_id": "987654321"
}
```

- **Authorization & safety gates**:
  - Caller MUST be authenticated on signaling (`owner_user_id = Some(uid)`) and the target device MUST belong to the exact same `owner_user_id`. Unauthenticated callers receive `wol_ack` (`ok = false, method = "none", code = "unauthorized"`); unknown target devices receive `code = "device_not_found"`; cross-account targets receive `code = "forbidden"`; disabled targets receive `code = "device_disabled"`.
  - **Two-layer bounded rate limiting**:
    1. Per-caller bounded sliding window (evaluated immediately after authenticating caller and **before** target DB lookups, mitigating device ID enumeration and DB read amplification; default 10 requests / 10 seconds);
    2. Per-`target_device_id` bounded sliding window (at most 1 request per `target_device_id` every **5 seconds**). Excess requests receive `wol_ack` (`ok = false, method = "none", code = "rate_limited"`).
  - Target device MUST have `wol_enabled == true` and a valid stored unicast `mac_addr`, otherwise the server replies `wol_ack` (`ok = false, method = "none", code = "wol_disabled"`).
- **3-way wake routing priority**:
  1. **Target already online**: replies immediately with `wol_ack` (`ok = true, method = "already_online"`).
  2. **Same-account LAN peer relay (`lan_peer`)**: searches other currently online peers belonging to the same `owner_user_id` (`peer_id != target_device_id && peer_id != caller_device_id`). When both `target.last_public_ip` and `peer.remote_addr.ip()` are distinct routable public IPs, RFC 1918 `/24` overlap is **strictly rejected** to prevent cross-site misrouting across common `192.168.1.0/24` networks. Eligible peers are prioritized as `(same_public_ip && same_private_slash24)` > `(same_public_ip)` > `(same_private_slash24 fallback when last_public_ip is empty or either side uses private/loopback addressing)`. Pushes `wol_relay` to the highest-priority deliverable peer and returns `wol_ack` (`ok = true, method = "lan_peer"`).
  3. **Server direct broadcast (`server`)**: if no eligible same-LAN peer is online and `ALLOW_SERVER_WOL=true` (default `false`), the server constructs a standard 102-byte magic packet (`6×0xFF + 16×MAC`) and broadcasts it over UDP (`SO_BROADCAST`) to each target private IPv4 `/24` directed broadcast `:9` plus `255.255.255.255:9`. Replies `wol_ack` (`ok = true, method = "server"`) on success or `wol_ack` (`ok = false, method = "none", code = "wol_send_failed"`) on failure.
  4. **No relay peer available**: replies `wol_ack` (`ok = false, method = "none", code = "wol_no_relay_peer"`).

#### `wol_relay` (Server -> Same-Account Online LAN Peer)

Sent by the server to an eligible online same-account LAN peer instructing it to broadcast a local Wake-on-LAN magic packet for `target_device_id`.

```json
{
  "type": "wol_relay",
  "request_id": "req-0123456789ab",
  "target_device_id": "987654321",
  "mac_addr": "aa:bb:cc:dd:ee:ff",
  "target_lan_addrs": ["192.168.1.20:50000"]
}
```

#### `wol_ack` (Server -> Requester Client)

```json
{
  "type": "wol_ack",
  "request_id": "optional-req-id",
  "target_device_id": "987654321",
  "ok": true,
  "method": "lan_peer",
  "message": "wake-on-lan magic packet relayed via same-LAN peer"
}
```

- `method`: one of `"already_online"`, `"lan_peer"`, `"server"`, or `"none"`.
- `code` (optional string, omitted on success): `snake_case` wire alias from `generated::error_codes::wire::*` (`wol_disabled`, `wol_no_relay_peer`, `wol_send_failed`, `rate_limited`, `unauthorized`, `forbidden`, `device_not_found`, `device_disabled`, `invalid_input`).

#### `kicked` (Server -> Client)

Sent before the server terminates the TCP signaling connection (e.g., admin disable via `DELETE /api/v1/devices/:id`, server shutdown, or replacement by a newer connection).

```json
{
  "type": "kicked",
  "reason": "disabled_by_admin"
}
```

#### `error` (Server -> Client)

```json
{
  "type": "error",
  "code": "invalid_payload",
  "message": "target_id is required"
}
```

`code` uses the `snake_case` wire aliases generated from `TokenBoom/rabbitcontrol-spec` (`backend/src/generated/error_codes.rs::wire::*`); see **§8 Unified Error Code Contract** for the canonical mapping and backward-compatibility guarantees.

---

## 3. UDP STUN-lite Probe Protocol (`:21116/udp` & `:21119/udp`)

A fixed-offset binary protocol used by peers to discover their NAT-mapped public UDP `IP:Port`, classify NAT mapping behavior, and publish dual-stack endpoints to `EphemeralStore`. All multi-byte integers are **big-endian**.

### 3.1 Request Packet (`RCSP`, v1: 22 bytes / v2: 38 bytes)

**Version 1 (22 bytes, legacy IP-matched):**

```text
+---------------+----------+-------------------------+------------------+
| Magic (4 B)   | Ver (1B) | Device ID (9 B ASCII)   | Nonce (8 B)      |
| "RCSP"        | 0x01     | e.g. "123456789"        | random 8 bytes   |
+---------------+----------+-------------------------+------------------+
```

**Version 2 (38 bytes, token-authenticated multi-egress / dual-stack):**

```text
+---------------+----------+-------------------------+------------------+------------------+
| Magic (4 B)   | Ver (1B) | Device ID (9 B ASCII)   | Nonce (8 B)      | Token (16 B raw) |
| "RCSP"        | 0x02     | e.g. "123456789"        | random 8 bytes   | udp_probe_token  |
+---------------+----------+-------------------------+------------------+------------------+
```

| Offset | Size | Field | Description |
|---|---|---|---|
| `0` | 4 B | `magic` | ASCII `"RCSP"` (`0x52 0x43 0x53 0x50`) |
| `4` | 1 B | `ver` | Protocol version: `0x01` (22B) or `0x02` (38B) |
| `5` | 9 B | `device_id` | 9-byte ASCII digits (e.g. `"123456789"`; `"000000000"` = anonymous probe without storing endpoint) |
| `14` | 8 B | `nonce` | Random 8-byte request nonce echoed verbatim in response |
| `22` | 16 B | `token` | (`ver == 0x02` only) Raw 16-byte `udp_probe_token` issued in `registered` |

Malformed packets or unsupported versions are silently dropped.

### 3.2 Response Packet (`RCSA`, 20 bytes IPv4 / 32 bytes IPv6)

```text
+---------------+----------+------------+------------------------+---------------+------------------+
| Magic (4 B)   | Ver (1B) | IPLen (1B) | IP Bytes (4 B or 16 B) | Port (u16 BE) | Nonce (8 B)      |
| "RCSA"        | 0x01     | 4 or 16    | IPv4 / IPv6 octets     | source port   | echoed 8 bytes   |
+---------------+----------+------------+------------------------+---------------+------------------+
```

| Offset | Size | Field | Description |
|---|---|---|---|
| `0` | 4 B | `magic` | ASCII `"RCSA"` (`0x52 0x43 0x53 0x41`) |
| `4` | 1 B | `ver` | Protocol version, `0x01` (unchanged for both v1 and v2 requests) |
| `5` | 1 B | `ip_len` | `4` (IPv4) or `16` (IPv6) |
| `6` | `ip_len` B | `ip_bytes` | Observed source IP octets |
| `6 + ip_len` | 2 B | `port` | Observed source UDP port (`u16` big-endian) |
| `8 + ip_len` | 8 B | `nonce` | Echoed 8-byte nonce from request |

Under per-source-IP UDP rate limiting, the server immediately replies `RCSA` with the canonicalized source address (IPv4-mapped IPv6 addresses are normalized to IPv4) and then asynchronously queues the `EphemeralStore` update on the primary `:21116/udp` listener. When `device_id != "000000000"` and passes `9`-digit validation, `device_id -> observed_ip:port` is stored per address family (`rc:udp4:{did}` / `rc:udp6:{did}` + `rc:udp:{did}`) with TTL **only if**:
- **`RCSP v1`**: `device_id` is currently online on authenticated TCP signaling from a matching canonical IP (`canonical_ip(peer.remote_addr.ip()) == canonical_src.ip()`).
- **`RCSP v2`**: `device_id` is currently online on authenticated TCP signaling and constant-time comparison of `token == peer.udp_probe_token` succeeds (supporting multi-egress NAT pools and dual-stack TCP IPv6 + UDP IPv4 probing without requiring matching TCP/UDP source IPs).

### 3.3 Secondary UDP Probe Port (`:21119/udp`)

By default (`--udp-probe-alt` / `RC_UDP_PROBE_ALT_ADDR` unset), `rc-server` binds a second UDP probe socket on the same IP as `--signal` at `signal_port + 3` (`:21119/udp` when `--signal` is `:21116`, `:0` when `--signal` is `:0`, disabled if port addition overflows; explicitly configurable or disabled via `"disabled"` / `"none"`). Conflict checking is transport-aware (TCP `--web-addr` on `:21119/tcp` does not conflict with UDP `:21119/udp`). The secondary port shares the same per-IP UDP rate limiter and replies with identical `RCSA` echo packets, **but never writes to or overwrites `EphemeralStore`**.

---

## 4. Zero-Copy TCP Relay Protocol (`:21117/tcp`)

### 4.1 Binary Handshake (`RCR1`)

Immediately after TCP connect, each peer sends the handshake frame within the handshake timeout (`5s`):

```text
+---------------+----------+-------------+-----------------------+
| Magic (4 B)   | Role (1B)| TokenLen(1B)| Token (TokenLen B)    |
| "RCR1"        | 1 or 2   | 1..=128     | UTF-8 / ASCII hex     |
+---------------+----------+-------------+-----------------------+
```

| Field | Size | Values |
|---|---|---|
| `magic` | 4 B | ASCII `"RCR1"` (`0x52 0x43 0x52 0x31`) |
| `role` | 1 B | `0x01` = Host (controlled), `0x02` = Client (controller) |
| `token_len` | 1 B | Length of `token` in bytes (`1..=128`) |
| `token` | `token_len` B | One-time UTF-8 `relay_token` issued by `punch_coord` or `relay_ready` |

### 4.2 Server Reply (1 Byte)

- `0x00` (`OK`): Token validated and complementary peer (`host` + `client`) paired. Immediately after reading `0x00`, the TCP connection transitions into a raw full-duplex byte stream.
- `0x01` (`ERR`): Handshake failed (invalid magic/role/token length, unknown/expired token, duplicate role, or pairing timeout). Server closes immediately after writing `0x01`.

### 4.3 Forwarding Data Path

- **Linux (`#[cfg(target_os = "linux")]`)**: Kernel-to-kernel zero-copy forwarding via `splice(2)` with a 256 KiB pipe, `SPLICE_F_MOVE | SPLICE_F_NONBLOCK`, cooperative Tokio yield every 4 MiB or 64 ops, graceful half-close (`SHUT_WR`), and automatic fallback to bounded userspace copy on resource exhaustion.
- **Non-Linux (macOS / Windows)**: Bounded userspace bidirectional copy with graceful half-close (`shutdown`).
- On session end, totals (`bytes_up`, `bytes_down`, `started_at`, `ended_at`) are persisted to PostgreSQL `relay_sessions_log`.

---

## 5. Axum 0.8 REST API (`:21118/tcp`, `/api/v1/*`)

All responses — including malformed JSON, body-limit (`413`), and auth (`401`) errors — return `Content-Type: application/json` (`{"error": "<code>", "message": "<detail>"}`), where `<code>` is a `snake_case` wire alias defined in `TokenBoom/rabbitcontrol-spec` (see **§8 Unified Error Code Contract**).

### 5.1 Admin Authentication & CORS

- **Admin Bearer Auth (`--admin-token` / `RC_ADMIN_TOKEN`)**:
  - When configured, all admin routes (`/api/v1/stats`, `/api/v1/devices`, `/api/v1/devices/:id`, `/api/v1/sessions`, `/api/v1/sessions/:id`) require `Authorization: Bearer <token>` (verified with constant-time byte comparison). Missing or invalid tokens receive `401 Unauthorized` with JSON `ErrorBody` and `WWW-Authenticate: Bearer realm="rc-server-admin"`.
  - Public routes (`GET /api/v1/health`, `POST /api/v1/devices/register`) remain accessible without an admin token.
  - When `--admin-token` is unset, the server logs a startup warning and leaves admin routes unauthenticated.
- **CORS (`--cors-origin` / `RC_CORS_ORIGIN`)**:
  - Defaults to same-origin only (no cross-origin allowlist).
  - Accepts comma-separated origin values (e.g. `https://admin.example.com`) or explicit `*` wildcard only when explicitly requested via `--cors-origin '*'`.
  - Allowed methods: `GET`, `POST`, `DELETE`, `OPTIONS`. Allowed request headers: `Authorization`, `Content-Type`.

### 5.2 Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/health` | Public | Liveness & dependency health (`status`, `postgres`, `ephemeral_backend`, `relay_engine`, `uptime_sec`, `version`) |
| `POST` | `/api/v1/devices/register` | Public | Idempotently register device by `device_key` and issue/return permanent 9-digit `device_id` (`400` on invalid input, `403` if disabled, `413` if body > 8 KiB) |
| `GET` | `/api/v1/stats` | Admin | Server metrics: `online_count`, `registered_count`, `active_relay_sessions`, `total_relay_sessions`, `total_relay_bytes`, `total_bytes_up`, `total_bytes_down`, `punch_coord_count`, `ephemeral_backend`, `relay_engine`, `uptime_sec` |
| `GET` | `/api/v1/devices` | Admin | Paginated device list (`?q=<search>&status=online\|offline\|in_session\|all&limit=1..=500&offset=0..`; default `limit=100`, `offset=0`). Searches `device_id`, `hostname`, `os`, `device_group`, and owner email (`owner_email`; excludes `device_key`). Invalid `status` always returns `400`. |
| `GET` | `/api/v1/sessions` | Admin | List currently active TCP relay sessions (`session_id`, `host_id`, `client_id`, `started_at`, `duration_sec`, `bytes_up`, `bytes_down`, `engine`) |
| `DELETE` | `/api/v1/sessions/:id` | Admin | Force-terminate an active relay session (`200 OK` or `404 Not Found`) |
| `DELETE` | `/api/v1/devices/:id` | Admin | Mark device `disabled = true`, kick online signaling peer (`reason = "disabled_by_admin"`), and terminate active relay sessions (`200 OK` or `404 Not Found`) |

### `POST /api/v1/devices/register`

- Request body limit: **8 KiB** (`8192` bytes).
- Validation limits (no NUL `\0` or control characters allowed): `device_key` 1–256 B, `hostname` ≤ 128 B, `os` ≤ 128 B, `app_version` ≤ 32 B, `arch` ≤ 32 B, `device_group` ≤ 64 B.

Request:

```json
{
  "device_key": "ed25519:7a9f2c...",
  "hostname": "macbook-pro",
  "os": "macos",
  "app_version": "0.1.10",
  "arch": "arm64",
  "device_group": "default"
}
```

Response (`200 OK`):

```json
{
  "device_id": "123456789",
  "formatted_id": "123 456 789",
  "device_key": "ed25519:7a9f2c...",
  "hostname": "macbook-pro",
  "os": "macos",
  "app_version": "0.1.10",
  "arch": "arm64",
  "device_group": "default",
  "created_at": "2026-11-22T10:00:00Z",
  "last_seen_at": "2026-11-22T10:05:00Z",
  "signal_tcp_addr": "172.16.1.2:21116",
  "udp_probe_addr": "172.16.1.2:21116",
  "udp_probe_alt_addr": "172.16.1.2:21119",
  "tcp_relay_addr": "172.16.1.2:21117",
  "relay_addr": "172.16.1.2:21117"
}
```

### `GET /api/v1/devices`

Query parameters:

- `q` (optional): case-insensitive literal substring search across `device_id`, `hostname`, `os`, `device_group` (SQL `LIKE` wildcards `\`, `%`, `_` are escaped; `device_key` is never searched).
- `status` (optional): `all` (default), `online`, `offline`, or `in_session`. Any other value returns `400 Bad Request` (`error = "invalid_status"`).
- `limit` (optional): page size, default `100`, clamped to `1..=500`.
- `offset` (optional): zero-based offset, default `0`.

Response (`200 OK`):

```json
{
  "devices": [
    {
      "device_id": "123456789",
      "formatted_id": "123 456 789",
      "hostname": "macbook-pro",
      "os": "macos",
      "app_version": "0.1.10",
      "arch": "arm64",
      "device_group": "default",
      "disabled": false,
      "online": true,
      "in_session": false,
      "status": "online",
      "public_udp_addr": "203.0.113.10:51234",
      "lan_addrs": ["192.168.1.10:50000"],
      "owner_email": "alice@example.com",
      "allow_remote_assist": false,
      "allow_remote_control": true,
      "wol_capable": true,
      "created_at": "2026-11-22T10:00:00Z",
      "last_seen_at": "2026-11-22T10:05:00Z"
    }
  ],
  "total": 1,
  "total_count": 1,
  "limit": 100,
  "offset": 0
}
```

Note: `total` equals `devices.len()` (page length), while `total_count` is the total number of matched devices across all pages. `wol_capable` indicates whether Wake-on-LAN is enabled with a valid unicast MAC; raw `mac_addr` is intentionally omitted from all device list responses (`/api/v1/devices` and `/api/v1/me/devices`).

---

## 6. Storage Architecture

### 6.1 PostgreSQL (`DeviceStore` / `migrations/0001_init.sql` – `0007_device_wol.sql`)

- `devices`: `device_id CHAR(9) PRIMARY KEY`, `device_key TEXT UNIQUE NOT NULL`, `hostname TEXT NOT NULL`, `os TEXT NOT NULL`, `app_version TEXT NOT NULL DEFAULT ''`, `arch TEXT NOT NULL DEFAULT ''`, `device_group TEXT NOT NULL DEFAULT ''`, `disabled BOOLEAN NOT NULL DEFAULT FALSE`, `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, plus `owner_user_id UUID REFERENCES users(id)`, `alias TEXT`, `device_pubkey TEXT`, `allow_remote_assist BOOLEAN`, `allow_remote_control BOOLEAN NOT NULL DEFAULT TRUE`, `mac_addr VARCHAR(17)`, `wol_enabled BOOLEAN NOT NULL DEFAULT FALSE`, `last_lan_addrs TEXT NOT NULL DEFAULT '[]'`, `last_public_ip TEXT NOT NULL DEFAULT ''` (`0005_device_app_version.sql` adds `app_version` and `arch`; `0006_device_allow_remote_control.sql` adds `allow_remote_control` and backfills `FALSE` for existing `android`/`ios` rows; `0007_device_wol.sql` adds the Wake-on-LAN and last-seen network columns). On device unbind, user deletion, or owner transfer, `allow_remote_assist` and `wol_enabled` reset to `FALSE`, `mac_addr` clears to `NULL`, `last_lan_addrs` resets to `'[]'`, `last_public_ip` resets to `''`, and `allow_remote_control` resets to its OS default (`FALSE` for Android/iOS, `TRUE` for desktop).
- `relay_sessions_log`: `id BIGSERIAL PRIMARY KEY`, `session_id TEXT NOT NULL`, `host_id CHAR(9) NOT NULL`, `client_id CHAR(9) NOT NULL`, `bytes_up BIGINT NOT NULL DEFAULT 0`, `bytes_down BIGINT NOT NULL DEFAULT 0`, `started_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `ended_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, indexed on `(started_at DESC)`, `(session_id)`, `(host_id, started_at DESC)`, and `(client_id, started_at DESC)`.
- `users`, `user_sessions` (refresh family tracking with single-use 15s grace + `retired_token_hashes` multi-generation replay detection), `system_settings` (`allow_registration`), `server_keys`, `pki_ca`, `device_certificates`, and `audit_logs` (`0003_users_auth_pki.sql`, `0004_session_replay_history.sql`).

### 6.2 Ephemeral Store (`EphemeralStore` & `SettingsCache`)

- **Default (`MemoryEphemeralStore`)**: Zero-dependency `DashMap` with per-entry `Instant` TTL expiry and periodic background cleanup. Used automatically when `--redis-url` / `REDIS_URL` is not set.
- **Optional (`RedisEphemeralStore`)**: Enabled when `--redis-url` / `REDIS_URL` is configured. Uses `redis::aio::ConnectionManager` (with bounded 2s connect/response timeouts and 1 retry) and millisecond `PX` TTLs (zero TTL executes `DEL`):
  - `rc:online:{device_id}` (`SET ... PX <ms>`) + `rc:online_zset` (Sorted Set scored by expiry unix ms; `online_ids()` prunes via `ZREMRANGEBYSCORE` and reads via `ZRANGEBYSCORE` in `O(|online|)`)
  - `rc:udp:{device_id}` / `rc:udp4:{device_id}` / `rc:udp6:{device_id}` (`SET ... PX <ms>`, dual-stack per-family endpoint cache queried via `MGET` in `get_public_udp_all`)
  - `rc:token:{token}` (`SET ... PX <ms>`, atomically consumed via `GETDEL`)
  - `rc:setting:allow_registration` (60s TTL cache backed by PostgreSQL `system_settings`, guarded by `SettingsCache` `write_epoch` against stale concurrent backfill)
  - `rc:revoked_cert:{serial_hex}` (revoked device certificate serial cache for `:21117` mTLS validation)

---

## 7. Account Auth, Admin Bootstrapping, Owner Self-Control & Mandatory Relay mTLS (`Phase 1`)

### 7.1 Initial Admin & `must_change_password` Gate
- On first startup with no admin user, `rc-server` creates the initial admin with a randomly generated password printed to server logs and sets `must_change_password = true`.
- Until `POST /api/v1/auth/change-password` succeeds, `require_user_auth_allow_pwd_change` only permits `/api/v1/me`, `/api/v1/auth/logout`, and `/api/v1/auth/change-password`, while `require_user_auth_full` and `require_admin_auth` fail closed with `403` (`password_change_required`).

### 7.2 REST Auth, Device Binding, PKI & Admin Routes (`:21118` / optional `--web-addr`)
- **Single-port (`RC_WEB_ADDR` unset, `RouterMode::Combined`)**: All routes below plus optional `RC_WEB_DIR` SPA static hosting are served on `:21118`.
- **Split-port (`--web-addr` / `RC_WEB_ADDR` set)**: `:21118` switches to `RouterMode::ClientApiOnly` (retaining only public client routes, restricted user routes, and full user routes; admin routes and SPA static files return `404`), while `--web-addr` serves plain-HTTP `RouterMode::WebAdminOnly` (`RC_WEB_DIR` SPA static files + `/api/v1/health`, `/api/v1/pki/ca`, `/api/v1/auth/{login,refresh,logout,change-password}`, `/api/v1/me`, and all Admin routes).
- **Public**: `GET /api/v1/health`, `GET /api/v1/pki/ca`, `POST /api/v1/devices/register`, `GET /api/v1/auth/config`, `POST /api/v1/auth/register` (gated by `allow_registration`), `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`.
- **Restricted User (allowed before password change)**: `GET /api/v1/me`, `POST /api/v1/auth/logout` (accepts Bearer token or `refresh_token` fallback with explicit `device_id` ownership pre-check via `verify_explicit_device_owner`), `POST /api/v1/auth/change-password` (revokes other sessions and kicks signaling/relay peers).
- **Full User**: `GET /api/v1/me/devices` (returns `MyDeviceView` including `allow_remote_assist` and `allow_remote_control`), `POST /api/v1/me/devices/bind` (atomic ownership transfer via `bind_device_to_user_with_prev`), `PATCH /api/v1/me/devices/{id}` (accepts optional `alias`, `allow_remote_assist`, and `allow_remote_control`; persists updates, syncs in-memory peer policy, and broadcasts `device_status_changed` to same-account online peers), `DELETE /api/v1/me/devices/{id}`, `POST /api/v1/certs/issue` (CSR verification -> 7-day device cert with URI SAN `urn:rabbitcontrol:user:{user_id}:device:{device_id}`).
- **Admin**: `GET / PATCH /api/v1/admin/settings` (`allow_registration`, `updated_at`), `GET / POST /api/v1/admin/users`, `PATCH / DELETE /api/v1/admin/users/{id}`, `GET /api/v1/stats`, `GET /api/v1/devices` (returns `DeviceView` including `allow_remote_assist` and `allow_remote_control`), `GET / DELETE /api/v1/sessions`, `DELETE /api/v1/devices/{id}`.

### 7.3 Signaling Extensions (`:21116`) & Two-Layer Remote Control Policy
- **TLS 1.3**: Enabled by default using server leaf cert signed by `pki_ca` (`--no-tls` opt-out for plaintext dev).
- **`Register`**: Accepts `access_token`, `device_pubkey`, `allow_remote_assist`, and `allow_remote_control`. Missing/invalid/revoked sessions return `Error` (`account_disabled`, `user_deleted`, `token_revoked`). Re-binding a device across users atomically transfers ownership (`bind_device_to_user_with_prev`), revokes the previous owner's certificates and sessions for that device, resets `allow_remote_assist = false` and `allow_remote_control` to the OS default, and preserves `effective_owner`.
- **Two-Layer Authorization (`authorize_peer_connection`)**:
  1. **Layer 1 (`allow_remote_control`)**: Evaluated **unconditionally before** same-account owner bypass on both `connect_request` and `relay_alloc` (including legacy `require_auth = false` / anonymous mode). Whenever `!target.allow_remote_control`, the server immediately rejects with `Error { code: "remote_control_disabled", message: "对方未开启允许远程控制" }` — even for the same account owner — without issuing `OwnerGrantTicket`, without sending `punch_coord` / `relay_ready`, and without allocating any `relay_token`.
  2. **Layer 2 (Owner Self-Control vs. `allow_remote_assist`)**: Once `target.allow_remote_control == true`:
     - If caller and target belong to the same `owner_user_id`, signaling bypasses `allow_remote_assist == false` and issues a signed `OwnerGrantTicket` (`RC-OWNER-GRANT-V1\0`) in `PunchCoord`/`RelayReady` (when `device_pubkey` is valid), paired with client Ed25519 `OwnerTicket` PoP inside `rc-session`.
     - Otherwise (non-owner), `!target.allow_remote_assist` is rejected with `Error { code: "assist_disabled", message: "对方未开启允许他人远程协助" }`.
- **Dynamic Kick Reasons**: `account_disabled`, `user_deleted`, `account_updated`, `password_changed`, `token_revoked`, `device_unbound`, `cert_revoked`, `disabled_by_admin`.

### 7.4 Mandatory Relay mTLS (`:21117`) & Direct P2P/LAN mTLS
- `:21117` enforces TLS 1.3 `WebPkiClientVerifier` client authentication against the Root CA, extracts SAN `urn:rabbitcontrol:user:{uid}:device:{did}` (`eq_ignore_ascii_case` for user ID), verifies `device_id == RelayTokenRecord.peer_id`, and checks `rc:revoked_cert:{serial_hex}` + PostgreSQL `device_certificates`.
- Direct P2P QUIC and Relay inner E2EE both support mutual TLS with `DEFAULT_ENCRYPT_CONNECTION = true`.

---

## 8. Unified Error Code Contract (`TokenBoom/rabbitcontrol-spec`)

### 8.1 Single Source of Truth & Synced Artifacts
- **`TokenBoom/rabbitcontrol-spec`** is the cross-platform single source of truth for all RabbitControl error codes, wire aliases, `zh-CN` user copy, severity, presentation, and recovery actions across server, core, desktop, mobile, and Admin Web.
- `rabbitcontrol-server` pins the synced spec version and SHA-256 digests in root `spec-lock.json` and consumes two **read-only generated artifacts** (zero Cargo dependency on `rabbitcontrol-core`):
  - `backend/src/generated/error_codes.rs` (`rust-server` target: canonical constants, `wire::*` `snake_case` aliases, `WIRE_ALIAS_MAP`, and `canonical_for_wire` / `primary_wire_alias`).
  - `web/src/generated/errorCatalog.ts` (`ts-web` target: `ERROR_CATALOG`, `WIRE_ALIASES`, `resolveWireAlias`, `lookupErrorEntry`, `buildUiError`).
- **Never hand-edit generated files.** All contract changes must be authored in `TokenBoom/rabbitcontrol-spec` first, regenerated there, and synced via `rabbitcontrol-spec/scripts/sync-to-repo.py`.
- CI enforces offline integrity via `python3 scripts/verify-spec-lock.py` (verifying `spec-lock.json` metadata, file SHA-256 digests, and rejecting untracked files in `generated/` directories without network access).

### 8.2 Wire Protocol Backward-Compatibility Principles
- **Wire envelope stability**:
  - REST API (`:21118` / `--web-addr`) preserves HTTP status codes and JSON body `{"error": "<wire_snake_case>", "message": "<detail>"}`.
  - TCP signaling (`:21116`) preserves `{"type": "error", "code": "<wire_snake_case>", "message": "<detail>"}` and `{"type": "kicked", "reason": "<wire_snake_case>"}`.
- **No spelling drift**: `backend/src/api.rs` and `backend/src/signal.rs` emit wire codes exclusively via `crate::generated::error_codes::wire::*` constants, guarded by unit tests asserting every emitted REST and signaling code exists in `WIRE_ALIAS_MAP` and resolves through `canonical_for_wire`.
- **Canonical normalization on clients & Admin Web**: Clients and Admin Web (`web/src/utils/errorDisplay.ts`) normalize incoming `snake_case` wire aliases (including client-side codes such as `network_error` and `auth_superseded`) to canonical dot-separated codes (e.g. `invalid_credentials` → `auth.invalid_credentials`, `network_error` → `network.unreachable`, `auth_superseded` → `auth.superseded`) to render structured localized Chinese titles, messages, and remediation suggestions instead of raw English server details.
