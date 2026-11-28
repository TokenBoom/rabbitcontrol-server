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
| UDP STUN-lite Probe (Alt-IP, optional) | Unset by default (`--udp-probe-alt-ip` / `RC_UDP_PROBE_ALT_IP`, default `None`) | UDP | Optional self-hosted second public IP `RCSP`/`RCSA` probe endpoint advertised via `registered.udp_probe_alt_ip_addr` and REST endpoint/status snapshots (100% private STUN; third-party public STUN is forbidden) |
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
  "cpu_model": "Apple M3 Max",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "total_memory_mb": 32768,
  "os_version": "macOS 15.1",
  "gpu_model": "Apple M3 Max",
  "device_group": "default",
  "lan_addrs": ["192.168.1.10:50000"],
  "access_token": "<optional-jwt>",
  "device_pubkey": "<optional-ed25519-hex>",
  "allow_remote_assist": false,
  "allow_remote_control": true,
  "mac_addr": "aa:bb:cc:dd:ee:ff",
  "wol_enabled": true,
  "nat_type": "cone",
  "nat_port_delta": 0,
  "nat_port_range": [10000, 20000],
  "rcp2_v2": true
}
```

- `device_key` (required): stable unique identifier (1–256 chars).
- `device_id` (optional): if provided, verified against the resolved permanent 9-digit ID.
- `hostname`, `os`, `app_version` (≤32 UTF-8 bytes), `arch` (≤32 UTF-8 bytes), `device_group` (alias `"group"`), `lan_addrs`: optional metadata (backward-compatible with older clients; empty strings preserve previously stored values).
- `cpu_model` (optional string, ≤128 UTF-8 bytes), `mac_address` (optional string, ≤64 UTF-8 bytes; valid unicast MACs normalized to lowercase `"aa:bb:cc:dd:ee:ff"`), `total_memory_mb` (optional `u64`, `0..=i64::MAX`), `os_version` (optional string, ≤128 UTF-8 bytes), `gpu_model` (optional string, ≤128 UTF-8 bytes): optional hardware metadata for device inventory display. Forward/backward-compatible: omitted fields, `null`, empty strings (`""`), or `total_memory_mb == 0` preserve previously stored DB values without overwriting them; NUL or control characters and oversized values are rejected (`invalid_payload` / `invalid_input`).
- `allow_remote_control` (optional bool): gates **all** incoming remote control connections (including same-account owner self-control). When explicitly provided (`Some(v)`), persisted immediately. When omitted (`None`, older clients), newly registered devices default via `default_allow_remote_control_for_os(os)` (`false` when `os` contains `android` or `ios` case-insensitively, `true` otherwise), while existing devices preserve their stored DB value (converging to `false` if their previously empty `os` is populated with an Android/iOS OS).
- `allow_remote_assist` (optional bool): gates non-owner third-party assistance (effective only when `allow_remote_control == true`).
- `mac_addr` (optional string): primary Ethernet/Wi-Fi unicast MAC address for Wake-on-LAN (`:` or `-` separated 6 hex bytes, normalized to lowercase `"aa:bb:cc:dd:ee:ff"`). All-zero (`00:00:00:00:00:00`), broadcast (`ff:ff:ff:ff:ff:ff`), and multicast (`(b0 & 0x01) != 0`) MACs are strictly rejected with `error` (`code = "invalid_input"`). When omitted or empty, previously stored `mac_addr` is preserved.
- `wol_enabled` (optional bool): whether this device allows Wake-on-LAN remote wake by its account owner (defaults to `false`; omitted preserves the stored DB value).
- `nat_type` (optional string): client-classified NAT behavior (`"unknown"`, `"public"`, `"cone"`, `"cone_verified"`, `"cone_unverified"`, `"symmetric_seq"`, `"symmetric_random"`, `"adm_seq"`, `"adm_random"`, `"apdm_seq"`, `"apdm_random"`, `"udp_blocked"`, normalized case-insensitively; unrecognized values are safely ignored as `None` for backward compatibility).
- `nat_port_delta` (optional `i16`): observed sequential NAT port allocation step, clamped to `-1024..=1024`.
- `nat_port_range` (optional `[u16; 2]`): observed NAT port allocation range hint `[min, max]` (`1 <= min <= max <= 65535`; invalid ranges or `0` ports are safely ignored as `None`).
- `rcp2_v2` (optional bool, default `false`): declares support for `RCP2 v2` 48-byte HMAC-SHA256 authenticated punch packets; omitted by legacy (`< v0.2.5`) clients and treated as `false`.
- `device_status_changed` broadcasts and `/api/v1/me/devices`, `/api/v1/devices` views also expose `app_version`, `arch`, `cpu_model`, `mac_address` (falling back to normalized `mac_addr` when `mac_address` is empty), `total_memory_mb`, `os_version`, `gpu_model`, `allow_remote_assist`, `allow_remote_control`, and `wol_capable` (`wol_enabled && valid(mac_addr)`). The internal WoL key `mac_addr` itself is **never** serialized in device list or status broadcasts.

#### `update_assist_state` (Client -> Server)

Updates the device's remote-assist, remote-control, Wake-on-LAN, and/or incremental hardware metadata configuration in real time, persisting to `DeviceStore`, updating active peer state, and broadcasting `device_status_changed` to same-account online peers.

```json
{
  "type": "update_assist_state",
  "allow_remote_assist": false,
  "allow_remote_control": true,
  "mac_addr": "aa:bb:cc:dd:ee:ff",
  "wol_enabled": true,
  "cpu_model": "Apple M3 Max",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "total_memory_mb": 32768,
  "os_version": "macOS 15.1",
  "gpu_model": "Apple M3 Max"
}
```

- `allow_remote_assist` (optional bool): whether non-owner third-party assistance is allowed; when omitted (`None`), preserves the existing stored value without modification.
- `allow_remote_control` (optional bool): when provided (`Some(v)`), persists and updates `allow_remote_control`; when omitted (`None`, older clients), preserves the existing stored value without modification.
- `mac_addr` (optional string): optional unicast MAC address (`aa:bb:cc:dd:ee:ff`); validated with the same strict rules as `register`.
- `wol_enabled` (optional bool): optional Wake-on-LAN opt-in flag; omitted preserves the existing stored value.
- `cpu_model`, `mac_address`, `total_memory_mb`, `os_version`, `gpu_model` (optional): incremental hardware metadata updates using the same validation/normalization rules as `register`; omitted, empty, or `0` values preserve previously stored DB values.
- At least one effective field among `allow_remote_assist`, `allow_remote_control`, `mac_addr`, `wol_enabled`, or non-empty/`>0` hardware metadata fields must be present (otherwise the server responds with `error` `code = "invalid_payload"`). If persistence fails or affects 0 rows, the server returns an `error` frame without mutating in-memory peer state or broadcasting `device_status_changed`.

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
  "cpu_model": "Apple M3 Max",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "total_memory_mb": 32768,
  "os_version": "macOS 15.1",
  "gpu_model": "Apple M3 Max",
  "allow_remote_assist": false,
  "allow_remote_control": true,
  "wol_capable": true
}
```

Pushed to other online peers belonging to the same `owner_user_id` on register (online), disconnect/kick (offline), `update_assist_state`, and `heartbeat` (when `wol_capable` changes). `cpu_model`, `mac_address`, `os_version`, `gpu_model` are omitted when empty and `total_memory_mb` is omitted when `0` (`skip_serializing_if`), preserving wire compatibility with legacy clients. `wol_capable` is `true` iff `wol_enabled == true` and a valid unicast `mac_addr` is stored; the internal `mac_addr` field is never serialized (`mac_address` falls back to normalized `mac_addr` when empty). On REST `PATCH /api/v1/me/devices/{id}`, `device_status_changed` is pushed both to other same-account online peers **and** to the target device itself (if online) so the device can synchronize its local policy cache without stale overwrite on reconnect.

#### `ActiveControllerSummary` (Shared Signaling & REST Sub-object)

Represents an active controller session currently attached to a controlled host device:

```json
{
  "session_id": "f3a1c9...",
  "controller_device_id": "111222333",
  "controller_device_name": "Alice's MacBook",
  "controller_os": "macos",
  "is_owner": true,
  "mode": "remote_control",
  "connected_at_ms": 1763800000000
}
```

- `session_id` (required non-empty string, printable non-whitespace ASCII `is_ascii_graphic()`, ≤ 64 B): unique controller session identifier.
- `controller_device_id` (optional string, default `""`, ≤ 64 B): 9-digit device ID of the controller (empty when unknown).
- `controller_device_name` (optional string, default `""`, ≤ 128 B): human-readable controller display name / hostname.
- `controller_os` (optional string, default `""`, ≤ 128 B): controller operating system identifier.
- `is_owner` (optional bool, default `false`): whether the controller authenticated via same-account `OwnerTicket` PoP.
- `mode` (optional string, default `""`, ≤ 32 B): active session mode (e.g. `"remote_control"`, `"watch_only"`, `"tools"`).
- `connected_at_ms` (optional `u64`, default `0`): Unix timestamp in milliseconds when the session was established.

#### `control_state_report` (Client -> Server)

Sent by a controlled host device whenever its list of active controller sessions changes (bounded to at most 32 entries).

```json
{
  "type": "control_state_report",
  "active_controllers": [
    {
      "session_id": "f3a1c9...",
      "controller_device_id": "111222333",
      "controller_device_name": "Alice's MacBook",
      "controller_os": "macos",
      "is_owner": true,
      "mode": "remote_control",
      "connected_at_ms": 1763800000000
    }
  ]
}
```

- Validates entry count (≤ 32) and field lengths / printable constraints (rejecting invalid payloads with `error` `code = "invalid_payload"` without mutating state).
- Updates the peer's in-memory `active_controllers` snapshot (reflected immediately in `/api/v1/me/devices` and `/api/v1/devices` `active_controllers` & `in_session`), refreshes online TTL, and broadcasts `device_control_state_changed` to same-account online peers.
- Automatically cleared when the host disconnects, is kicked, or is replaced by a new signaling connection; if `active_controllers` was non-empty on disconnect/kick/replacement, the server automatically broadcasts `device_control_state_changed` with `active_controllers: []` to same-account online peers.

#### `device_control_state_changed` (Server -> Same-Account Online Peers)

```json
{
  "type": "device_control_state_changed",
  "device_id": "123456789",
  "active_controllers": [
    {
      "session_id": "f3a1c9...",
      "controller_device_id": "111222333",
      "controller_device_name": "Alice's MacBook",
      "controller_os": "macos",
      "is_owner": true,
      "mode": "remote_control",
      "connected_at_ms": 1763800000000
    }
  ]
}
```

Pushed to other online peers belonging to the same `owner_user_id` whenever a peer reports `control_state_report` or disconnects/is kicked/replaced while `active_controllers` is non-empty (in which case `active_controllers` is `[]`).

#### `force_disconnect_request` (Client -> Server)

Requests a same-account controlled host (`target_id`) to disconnect an active controller session (or all active sessions when `controller_device_id` and `session_id` are omitted).

```json
{
  "type": "force_disconnect_request",
  "target_id": "987654321",
  "controller_device_id": "111222333",
  "session_id": "f3a1c9..."
}
```

- **Payload normalization & validation**:
  - `target_id` is normalized; empty `target_id` is rejected with `error` (`code = "invalid_payload"`).
  - `controller_device_id` (optional, ≤ 64 B, no NUL/control chars; empty/whitespace normalized to `None`) and `session_id` (optional, printable non-whitespace ASCII ≤ 64 B; empty normalized to `None`) failing validation are rejected with `error` (`code = "invalid_payload"`). When both normalize to `None`, the target host disconnects all active sessions.
  - Per-caller sliding window rate-limiting is enforced (`code = "rate_limited"`).
- **Strict same-account authorization & delivery**:
  - Disabled callers return `peer_disabled`; unauthenticated/unbound callers (`owner_user_id = None` or missing device record) are rejected with `error` (`code = "unauthorized"`).
  - Target devices belonging to a different (or `None`) `owner_user_id` are strictly rejected with `error` (`code = "forbidden"`). Cross-account kicking is forbidden.
  - Unknown targets return `peer_not_found`; disabled targets return `peer_disabled`; offline targets return `peer_offline`; if the target signaling queue is full or serialized frame exceeds max length, the server returns `peer_busy` or `frame_too_large`.
- When authorized and `target_id` is online, forwards `force_disconnect` to the target host.

#### `force_disconnect` (Server -> Target Host)

```json
{
  "type": "force_disconnect",
  "requester_device_id": "444555666",
  "controller_device_id": "111222333",
  "session_id": "f3a1c9..."
}
```

- `controller_device_id` and `session_id` are optional (`skip_serializing_if = "Option::is_none"`). Once the target host terminates the session(s), it publishes an updated `control_state_report`.

#### `registered` (`RegisterAck`, Server -> Client)

```json
{
  "type": "registered",
  "device_id": "123456789",
  "formatted_id": "123 456 789",
  "server_time": "2026-11-22T10:00:00Z",
  "udp_probe_addr": "172.16.1.2:21116",
  "udp_probe_alt_addr": "172.16.1.2:21119",
  "udp_probe_alt_ip_addr": "172.16.1.3:21116",
  "udp_probe_token": "0123456789abcdef0123456789abcdef",
  "relay_addr": "172.16.1.2:21117"
}
```

- `udp_probe_alt_addr` (optional string, omitted when disabled): secondary UDP STUN-lite echo-only endpoint (`:21119/udp` by default) used to distinguish Cone vs Symmetric NAT.
- `udp_probe_alt_ip_addr` (optional string, omitted when unset): optional self-hosted secondary public IP UDP STUN-lite probe address configured via `--udp-probe-alt-ip` / `RC_UDP_PROBE_ALT_IP` (default `None`; third-party public STUN is forbidden).
- `udp_probe_token` (optional string): 32-char lowercase hex encoding of a random 16-byte per-connection probe token used in `RCSP v2` packets for constant-time cross-IP/dual-stack endpoint authentication.

#### `heartbeat` (Client -> Server)

Refreshes online TTL in `EphemeralStore`, updates `last_seen_at`, `last_lan_addrs`, and `last_public_ip` in `DeviceStore`, and optionally synchronizes `mac_addr` / `wol_enabled`, NAT telemetry (`nat_type`, `nat_port_delta`, `nat_port_range`), and observed signaling RTT (`rtt_ms`).

```json
{
  "type": "heartbeat",
  "lan_addrs": ["192.168.1.10:50000"],
  "mac_addr": "aa:bb:cc:dd:ee:ff",
  "wol_enabled": true,
  "nat_type": "cone",
  "nat_port_delta": 0,
  "nat_port_range": [10000, 20000],
  "rtt_ms": 24
}
```

- `mac_addr` (optional string) and `wol_enabled` (optional bool): backward-compatible optional fields; omitted preserves stored values. Invalid non-empty `mac_addr` returns `error` (`code = "invalid_input"`).
- `nat_type` / `nat_port_delta` / `nat_port_range` (optional): updates the peer's in-memory NAT profile using the same whitelist/clamping/range-validation rules as `register`.
- `rtt_ms` (optional `u32`): client-observed heartbeat/signaling RTT in milliseconds; updates the server's per-peer EWMA smoothed RTT estimate (clamped to `0..=10_000` ms; when no sample has been observed, the peer's RTT estimate falls back to `0`).

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
  "nat_port_delta": 0,
  "nat_port_range": [10000, 20000],
  "takeover": false
}
```

- `nat_type` / `nat_port_delta` / `nat_port_range` (optional): updates the caller's in-memory NAT profile before issuing `punch_coord`.
- `takeover` (optional bool, `#[serde(default)]`, default `false`): when `true` and caller belongs to the same authenticated `owner_user_id` as `target_id`, allows taking over an in-session host.
- **In-session & takeover gate**: after verifying `allow_remote_control` and `allow_remote_assist` / same-account ownership, if `!target.active_controllers.is_empty()`:
  - If the caller is already listed in `target.active_controllers` (same normalized `controller_device_id` reconnecting or switching route), the request is permitted.
  - Otherwise, if `takeover == false`, OR if the caller is **not** a same-account owner (`!is_owner_connection`, even when `takeover == true`), the server immediately rejects with `error` (`code = "target_in_session"`) without allocating a relay token or notifying the host.
  - Only a same-account owner with `takeover == true` is permitted to forward `takeover = true` in `punch_coord` to the host. (Non-owner requests always have `takeover` sanitized to `false`.)
- If `target_id` is offline, the server responds only to the requester with `peer_offline`.
- If `target_id` is online and authorized, the server reads both sides' observed public UDP endpoints (`get_public_udp` and dual-stack `get_public_udp_all`) from `EphemeralStore`, allocates a one-time fallback `relay_token` in `EphemeralStore`, generates a per-session 128-bit `OsRng` `punch_secret` **only when both peers declared `rcp2_v2 == true`** (otherwise `None`), computes synchronized `start_after_ms` from both peers' smoothed RTT estimates (falling back to `0` when unsampled), and pushes `punch_coord` to **both** the client (`role = "client"`) and target host (`role = "host"`).

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
  "self_nat_port_range": [10000, 20000],
  "peer_nat_port_range": [30000, 40000],
  "peer_lan_addrs": ["192.168.1.20:50000"],
  "nonce": "a1b2c3d4",
  "punch_secret": "0123456789abcdef0123456789abcdef",
  "start_after_ms": 40,
  "relay_fallback_after_ms": 400,
  "relay_token": "9f8e7d6c...",
  "relay_addr": "172.16.1.2:21117",
  "is_owner_connection": true,
  "takeover": false,
  "peer_hostname": "macbook-pro",
  "peer_os": "macos"
}
```

- `peer_public_udp_addr`: legacy primary observed public UDP address of the peer (kept for backward compatibility).
- `peer_public_udp_addrs` (optional array, omitted when empty): all non-expired dual-stack public UDP addresses of the peer (IPv6 + IPv4, deduplicated).
- `self_public_udp_addr` (optional string): the recipient's own observed public UDP address (for hairpin / same-public-IP detection).
- `peer_nat_type` / `peer_nat_port_delta` (optional): the peer's normalized NAT classification and port step hint.
- `self_nat_port_range` / `peer_nat_port_range` (optional `[u16; 2]`): validated NAT port range hints (`[min, max]`, `1 <= min <= max <= 65535`) for the recipient and peer respectively.
- `punch_secret` (optional string, omitted when `None`): 32-char lowercase hex encoding of a per-session 128-bit `OsRng` secret shared identically by both `client` and `host` for `RCP2 v2` HMAC-SHA256 punch authentication. Issued **only** when both `client` and `host` declared `rcp2_v2 == true` during `register`; otherwise omitted (`None`) so mixed or legacy clients fall back to 29-byte `RCP2 v1` interoperability.
- `start_after_ms` (optional `u16`): fast-side punch launch delay in milliseconds, computed as `clamp((rtt_slow - rtt_fast) / 2, 0, 500)` for the lower-RTT peer and `0` for the slower peer (unsampled peers fall back to `0` ms).
- `relay_fallback_after_ms` (optional `u16`): synchronized delay threshold in milliseconds (default `400`) after which both peers concurrently initiate Relay-first dialing.
- `takeover` (bool, `#[serde(default)]`): `true` only when a same-account owner requested takeover (`connect_request.takeover == true`); always `false` for non-owner sessions.
- `peer_hostname` / `peer_os` (optional strings, omitted when empty/`None`): remote peer's registered hostname and OS identifier (allowing the host to render controller metadata immediately on takeover/approval prompts).

#### `relay_alloc` (Client -> Server)

Explicitly requests a fresh one-time TCP Relay token when P2P hole-punching fails or is bypassed.

```json
{
  "type": "relay_alloc",
  "target_id": "987654321",
  "session_id": "f3a1c9...",
  "takeover": false
}
```

- Enforces the exact same authorization and `target_in_session` / same-account `takeover` rules as `connect_request`.
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
  "expires_in_sec": 60,
  "is_owner_connection": true,
  "takeover": false,
  "peer_hostname": "macbook-pro",
  "peer_os": "macos"
}
```

- `takeover`, `peer_hostname`, and `peer_os` carry the same semantics as in `punch_coord`.

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
| `GET` | `/api/v1/health` | Public | Liveness & dependency health (`status`, `postgres`, `ephemeral_backend`, `relay_engine`, `uptime_sec`, `version`, optional `udp_probe_alt_ip_addr`) |
| `POST` | `/api/v1/devices/register` | Public | Idempotently register device by `device_key` and issue/return permanent 9-digit `device_id` (`400` on invalid input, `403` if disabled, `413` if body > 8 KiB) |
| `GET` | `/api/v1/stats` | Admin | Server metrics: `online_count`, `registered_count`, `active_relay_sessions`, `total_relay_sessions`, `total_relay_bytes`, `total_bytes_up`, `total_bytes_down`, `punch_coord_count`, `ephemeral_backend`, `relay_engine`, `uptime_sec`, optional `udp_probe_alt_ip_addr` |
| `GET` | `/api/v1/devices` | Admin | Paginated device list (`?q=<search>&status=online\|offline\|in_session\|all&limit=1..=500&offset=0..`; default `limit=100`, `offset=0`). Searches `device_id`, `hostname`, `os`, `device_group`, `alias`, and owner email (`owner_email`; excludes `device_key`). Invalid `status` always returns `400`. |
| `GET` | `/api/v1/sessions` | Admin | List currently active TCP relay sessions (`session_id`, `host_id`, `client_id`, `started_at`, `duration_sec`, `bytes_up`, `bytes_down`, `engine`) |
| `DELETE` | `/api/v1/sessions/:id` | Admin | Force-terminate an active relay session (`200 OK` or `404 Not Found`) |
| `DELETE` | `/api/v1/devices/:id` | Admin | Mark device `disabled = true`, kick online signaling peer (`reason = "disabled_by_admin"`), and terminate active relay sessions (`200 OK` or `404 Not Found`) |

### `POST /api/v1/devices/register`

- Request body limit: **8 KiB** (`8192` bytes).
- Validation limits (no NUL `\0` or control characters allowed): `device_key` 1–256 B, `hostname` ≤ 128 B, `os` ≤ 128 B, `app_version` ≤ 32 B, `arch` ≤ 32 B, `cpu_model` ≤ 128 B, `mac_address` ≤ 64 B (valid unicast MACs normalized to lowercase `aa:bb:cc:dd:ee:ff`), `total_memory_mb` `0..=i64::MAX`, `os_version` ≤ 128 B, `gpu_model` ≤ 128 B, `device_group` ≤ 64 B.
- Backward/forward compatibility: all 5 hardware metadata fields are optional (`#[serde(default)]`, also tolerating JSON `null` as empty/`0`); omitted, empty, or `0` values preserve any previously stored values on re-registration.

Request:

```json
{
  "device_key": "ed25519:7a9f2c...",
  "hostname": "macbook-pro",
  "os": "macos",
  "app_version": "0.1.10",
  "arch": "arm64",
  "cpu_model": "Apple M3 Max",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "total_memory_mb": 32768,
  "os_version": "macOS 15.1",
  "gpu_model": "Apple M3 Max",
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
  "cpu_model": "Apple M3 Max",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "total_memory_mb": 32768,
  "os_version": "macOS 15.1",
  "gpu_model": "Apple M3 Max",
  "device_group": "default",
  "created_at": "2026-11-22T10:00:00Z",
  "last_seen_at": "2026-11-22T10:05:00Z",
  "signal_tcp_addr": "172.16.1.2:21116",
  "udp_probe_addr": "172.16.1.2:21116",
  "udp_probe_alt_addr": "172.16.1.2:21119",
  "udp_probe_alt_ip_addr": "172.16.1.3:21116",
  "tcp_relay_addr": "172.16.1.2:21117",
  "relay_addr": "172.16.1.2:21117"
}
```

### `GET /api/v1/devices`

Query parameters:

- `q` (optional): case-insensitive literal substring search across `device_id`, `hostname`, `os`, `device_group`, `alias`, and owner email (`owner_email`) (SQL `LIKE` wildcards `\`, `%`, `_` are escaped; `device_key` is never searched).
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
      "cpu_model": "Apple M3 Max",
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "total_memory_mb": 32768,
      "os_version": "macOS 15.1",
      "gpu_model": "Apple M3 Max",
      "device_group": "default",
      "disabled": false,
      "online": true,
      "in_session": false,
      "active_controllers": [],
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

Note: `total` equals `devices.len()` (page length), while `total_count` is the total number of matched devices across all pages. `wol_capable` indicates whether Wake-on-LAN is enabled with a valid unicast `mac_addr`; the internal WoL `mac_addr` key is never serialized, while `mac_address` returns the stored hardware MAC address (falling back to normalized `mac_addr` when `mac_address` is empty). `active_controllers` lists the host's currently reported `ActiveControllerSummary` entries (`#[serde(default)]`, empty array `[]` when idle/offline), and `in_session` reflects `!active_controllers.is_empty() || relay_in_session` (matching both `status = "in_session"` and `?status=in_session`).

---

## 6. Storage Architecture

### 6.1 PostgreSQL (`DeviceStore` / `migrations/0001_init.sql` – `0008_device_hardware_info.sql`)

- `devices`: `device_id CHAR(9) PRIMARY KEY`, `device_key TEXT UNIQUE NOT NULL`, `hostname TEXT NOT NULL`, `os TEXT NOT NULL`, `app_version TEXT NOT NULL DEFAULT ''`, `arch TEXT NOT NULL DEFAULT ''`, `cpu_model TEXT NOT NULL DEFAULT ''`, `mac_address TEXT NOT NULL DEFAULT ''`, `total_memory_mb BIGINT NOT NULL DEFAULT 0`, `os_version TEXT NOT NULL DEFAULT ''`, `gpu_model TEXT NOT NULL DEFAULT ''`, `device_group TEXT NOT NULL DEFAULT ''`, `disabled BOOLEAN NOT NULL DEFAULT FALSE`, `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, plus `owner_user_id UUID REFERENCES users(id)`, `alias TEXT`, `device_pubkey TEXT`, `allow_remote_assist BOOLEAN`, `allow_remote_control BOOLEAN NOT NULL DEFAULT TRUE`, `mac_addr VARCHAR(17)`, `wol_enabled BOOLEAN NOT NULL DEFAULT FALSE`, `last_lan_addrs TEXT NOT NULL DEFAULT '[]'`, `last_public_ip TEXT NOT NULL DEFAULT ''` (`0005_device_app_version.sql` adds `app_version` and `arch`; `0006_device_allow_remote_control.sql` adds `allow_remote_control` and backfills `FALSE` for existing `android`/`ios` rows; `0007_device_wol.sql` adds the Wake-on-LAN and last-seen network columns; `0008_device_hardware_info.sql` adds `cpu_model`, `mac_address`, `total_memory_mb`, `os_version`, and `gpu_model`). On device unbind, user deletion, or owner transfer, `allow_remote_assist` and `wol_enabled` reset to `FALSE`, `mac_addr` clears to `NULL`, `last_lan_addrs` resets to `'[]'`, `last_public_ip` resets to `''`, and `allow_remote_control` resets to its OS default (`FALSE` for Android/iOS, `TRUE` for desktop), while intrinsic hardware metadata (`cpu_model`, `mac_address`, `total_memory_mb`, `os_version`, `gpu_model`) is preserved.
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
- **Public**: `GET /api/v1/health`, `GET /api/v1/pki/ca`, `POST /api/v1/devices/register`, `GET /api/v1/auth/config`, `POST /api/v1/auth/register` (gated by `allow_registration`; optionally accepts `cpu_model`, `mac_address`, `total_memory_mb`, `os_version`, `gpu_model` when binding a device), `POST /api/v1/auth/login` (optionally accepts the same hardware metadata fields when binding a device), `POST /api/v1/auth/refresh`.
- **Restricted User (allowed before password change)**: `GET /api/v1/me`, `POST /api/v1/auth/logout` (accepts Bearer token or `refresh_token` fallback with explicit `device_id` ownership pre-check via `verify_explicit_device_owner`), `POST /api/v1/auth/change-password` (revokes other sessions and kicks signaling/relay peers).
- **Full User**: `GET /api/v1/me/devices` (returns `MyDeviceView` including `allow_remote_assist`, `allow_remote_control`, `wol_capable`, `active_controllers`, `in_session` reflecting `!active_controllers.is_empty() || relay_in_session`, and hardware metadata `cpu_model`, `mac_address` — falling back to normalized `mac_addr` when `mac_address` is empty — `total_memory_mb`, `os_version`, `gpu_model`), `POST /api/v1/me/devices/bind` (atomic ownership transfer via `bind_device_to_user_with_prev`; optionally accepts `cpu_model`, `mac_address`, `total_memory_mb`, `os_version`, `gpu_model`), `PATCH /api/v1/me/devices/{id}` (accepts optional `alias`, `allow_remote_assist`, and `allow_remote_control`; persists updates, syncs in-memory peer policy, and broadcasts `device_status_changed` to same-account online peers including the target device itself), `DELETE /api/v1/me/devices/{id}`, `POST /api/v1/certs/issue` (CSR verification -> 7-day device cert with URI SAN `urn:rabbitcontrol:user:{user_id}:device:{device_id}`).
- **Admin**: `GET / PATCH /api/v1/admin/settings` (`allow_registration`, `updated_at`), `GET / POST /api/v1/admin/users`, `PATCH / DELETE /api/v1/admin/users/{id}`, `GET /api/v1/stats`, `GET /api/v1/devices` (returns `DeviceView` including `allow_remote_assist`, `allow_remote_control`, `wol_capable`, `active_controllers`, `in_session` reflecting `!active_controllers.is_empty() || relay_in_session`, and `cpu_model`, `mac_address`, `total_memory_mb`, `os_version`, `gpu_model`), `GET / DELETE /api/v1/sessions`, `DELETE /api/v1/devices/{id}`.

### 7.3 Signaling Extensions (`:21116`) & Two-Layer Remote Control Policy
- **TLS 1.3**: Enabled by default using server leaf cert signed by `pki_ca` (`--no-tls` opt-out for plaintext dev).
- **`Register`**: Accepts `access_token`, `device_pubkey`, `allow_remote_assist`, and `allow_remote_control`. Missing/invalid/revoked sessions return `Error` (`account_disabled`, `user_deleted`, `token_revoked`). Re-binding a device across users atomically transfers ownership (`bind_device_to_user_with_prev`), revokes the previous owner's certificates and sessions for that device, resets `allow_remote_assist = false` and `allow_remote_control` to the OS default, and preserves `effective_owner`.
- **Two-Layer Authorization (`authorize_peer_connection`) & In-Session Takeover / Force-Disconnect**:
  1. **Layer 1 (`allow_remote_control`)**: Evaluated **unconditionally before** same-account owner bypass on both `connect_request` and `relay_alloc` (including legacy `require_auth = false` / anonymous mode). Whenever `!target.allow_remote_control`, the server immediately rejects with `Error { code: "remote_control_disabled", message: "对方未开启允许远程控制" }` — even for the same account owner — without issuing `OwnerGrantTicket`, without sending `punch_coord` / `relay_ready`, and without allocating any `relay_token`.
  2. **Layer 2 (Owner Self-Control vs. `allow_remote_assist`)**: Once `target.allow_remote_control == true`:
     - If caller and target belong to the same `owner_user_id`, signaling bypasses `allow_remote_assist == false` and issues a signed `OwnerGrantTicket` (`RC-OWNER-GRANT-V1\0`) in `PunchCoord`/`RelayReady` (when `device_pubkey` is valid), paired with client Ed25519 `OwnerTicket` PoP inside `rc-session`.
     - Otherwise (non-owner), `!target.allow_remote_assist` is rejected with `Error { code: "assist_disabled", message: "对方未开启允许他人远程协助" }`.
  3. **Layer 3 (`active_controllers` & `takeover` / `force_disconnect_request`)**:
     - When `!target.active_controllers.is_empty()` and the caller's normalized `device_id` is **not** already in `target.active_controllers`:
       - If `takeover == false`, OR if the caller is a non-owner guest (`!is_owner_connection`, even with `takeover == true`), `connect_request` / `relay_alloc` is immediately rejected with `Error { code: "target_in_session", ... }`.
       - Only a same-account owner (`is_owner_connection == true`) with `takeover == true` may proceed and deliver `takeover: true` to the target host.
     - `force_disconnect_request` strictly requires `caller.owner_user_id == Some(uid)` and `target.owner_user_id == Some(uid)` (same account); cross-account requests are rejected with `forbidden`.
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
- **Canonical normalization on clients & Admin Web**: Clients and Admin Web (`web/src/utils/errorDisplay.ts`) normalize incoming `snake_case` wire aliases (including client-side codes such as `network_error` and `auth_superseded`, and in-session/takeover codes `target_in_session` → `signal.target_in_session` and `session_preempted` / `preempted` → `session.preempted`; currently `118` canonical codes / `130` wire aliases in `TokenBoom/rabbitcontrol-spec`) to canonical dot-separated codes (e.g. `invalid_credentials` → `auth.invalid_credentials`, `target_in_session` → `signal.target_in_session`, `session_preempted` → `session.preempted`, `network_error` → `network.unreachable`, `auth_superseded` → `auth.superseded`) to render structured localized Chinese titles, messages, and remediation suggestions instead of raw English server details.
