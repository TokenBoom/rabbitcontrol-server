use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use socket2::{SockRef, TcpKeepalive};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch, Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::auth::{AuthAuthority, AuthError, OwnerGrantTicket, OWNER_GRANT_DEFAULT_TTL};
use crate::ephemeral::{
    EphemeralError, EphemeralStore, RelayTokenRecord, DEFAULT_MAX_RELAY_TOKENS,
};
use crate::generated::error_codes::wire as err_code;
use crate::store::{
    deserialize_null_default, format_device_id, is_valid_device_id, normalize_device_id,
    normalize_display_mac_address, normalize_mac_addr, parse_mac_addr_bytes, validate_text_field,
    validate_total_memory_mb, AuthStore, DeviceHardwareUpdate, DeviceStore, RegisterInput,
    StoreError, MAX_CPU_MODEL_LEN, MAX_DEVICE_PUBKEY_LEN, MAX_GPU_MODEL_LEN, MAX_OS_VERSION_LEN,
    STATUS_ACTIVE,
};

pub const UDP_PROBE_MAGIC: &[u8; 4] = b"RCSP";
pub const UDP_ANSWER_MAGIC: &[u8; 4] = b"RCSA";
pub const UDP_PROTO_VERSION: u8 = 1;
pub const UDP_PROTO_VERSION_V2: u8 = 2;
pub const UDP_PROBE_LEN: usize = 22;
pub const UDP_PROBE_TOKEN_LEN: usize = 16;
pub const UDP_PROBE_V2_LEN: usize = 38;
pub const PUNCH_SECRET_LEN: usize = 16;
pub const PUNCH_START_AFTER_MAX_MS: u16 = 500;
pub const DEFAULT_RELAY_FALLBACK_AFTER_MS: u16 = 400;
pub const PEER_RTT_MAX_MS: u32 = 10_000;
pub const ANONYMOUS_DEVICE_ID: &str = "000000000";
pub const NAT_PORT_DELTA_MIN: i16 = -1024;
pub const NAT_PORT_DELTA_MAX: i16 = 1024;

pub const MAX_SIGNAL_FRAME_LEN: usize = 65_536;
pub const MAX_SESSION_ID_LEN: usize = 64;
pub const MAX_NONCE_LEN: usize = 64;
pub const MAX_LAN_ADDRS: usize = 16;
pub const MAX_LAN_ADDR_LEN: usize = 64;
pub const MAX_HOSTNAME_LEN: usize = crate::store::MAX_HOSTNAME_LEN;
pub const MAX_OS_LEN: usize = crate::store::MAX_OS_LEN;
pub const MAX_APP_VERSION_LEN: usize = crate::store::MAX_APP_VERSION_LEN;
pub const MAX_ARCH_LEN: usize = crate::store::MAX_ARCH_LEN;
pub const MAX_DEVICE_GROUP_LEN: usize = crate::store::MAX_DEVICE_GROUP_LEN;
pub const MAX_ACTIVE_CONTROLLERS: usize = 32;
pub const MAX_CONTROLLER_DEVICE_ID_LEN: usize = 64;
pub const MAX_CONTROLLER_MODE_LEN: usize = 32;

pub const DEFAULT_MAX_SIGNAL_CONNECTIONS: usize = 8_192;
pub const DEFAULT_CONNECT_RATE_LIMIT_MAX: usize = 20;
pub const DEFAULT_CONNECT_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(10);
pub const DEFAULT_UDP_RATE_LIMIT_MAX: usize = 30;
pub const DEFAULT_UDP_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(10);
pub const DEFAULT_WOL_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(5);
pub const DEFAULT_WOL_CALLER_RATE_LIMIT_MAX: usize = 10;
pub const DEFAULT_WOL_CALLER_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(10);
pub const WOL_MAGIC_PACKET_LEN: usize = 102;
pub const WOL_UDP_PORT: u16 = 9;
pub const WOL_METHOD_ALREADY_ONLINE: &str = "already_online";
pub const WOL_METHOD_LAN_PEER: &str = "lan_peer";
pub const WOL_METHOD_SERVER: &str = "server";
pub const WOL_METHOD_NONE: &str = "none";

const DEVICE_LOCK_STRIPES: usize = 64;
const INITIAL_FRAME_BUF_CAP: usize = 4_096;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
const UDP_EPHEMERAL_UPDATE_TIMEOUT: Duration = Duration::from_millis(200);
const UDP_EPHEMERAL_QUEUE_CAPACITY: usize = 1_024;
const MAX_RATE_LIMIT_TRACKED_KEYS: usize = 16_384;
const SIGNAL_TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(30);
#[cfg(any(target_os = "linux", target_os = "macos"))]
const SIGNAL_TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
#[cfg(any(target_os = "linux", target_os = "macos"))]
const SIGNAL_TCP_KEEPALIVE_RETRIES: u32 = 3;

fn tune_signal_socket(stream: &TcpStream, peer_addr: SocketAddr) {
    let sock = SockRef::from(stream);
    if let Err(err) = sock.set_tcp_nodelay(true) {
        debug!(%peer_addr, error = %err, "failed to set TCP_NODELAY on signaling socket");
    }
    if let Err(err) = sock.set_keepalive(true) {
        debug!(%peer_addr, error = %err, "failed to set SO_KEEPALIVE on signaling socket");
    }
    let keepalive = TcpKeepalive::new().with_time(SIGNAL_TCP_KEEPALIVE_TIME);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let keepalive = keepalive
        .with_interval(SIGNAL_TCP_KEEPALIVE_INTERVAL)
        .with_retries(SIGNAL_TCP_KEEPALIVE_RETRIES);
    if let Err(err) = sock.set_tcp_keepalive(&keepalive) {
        debug!(%peer_addr, error = %err, "failed to configure TCP keepalive on signaling socket");
    }
}

/// Canonicalize IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to native `IpAddr::V4`.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// Canonicalize a `SocketAddr`'s IP (converting IPv4-mapped IPv6 to IPv4).
pub fn canonical_socket_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonical_ip(addr.ip()), addr.port())
}

/// Constant-time byte-slice equality check for UDP probe authentication tokens.
pub fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let lhs = a.get(i).copied().unwrap_or(0);
        let rhs = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(lhs ^ rhs);
    }
    std::hint::black_box(diff) == 0
}

/// Normalize client-reported NAT type to the canonical lowercase whitelist.
/// Unknown or malformed values are safely ignored (`None`) to maintain backward compatibility.
pub fn normalize_nat_type(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "unknown" => Some("unknown".to_string()),
        "public" => Some("public".to_string()),
        "cone" => Some("cone".to_string()),
        "cone_verified" => Some("cone_verified".to_string()),
        "cone_unverified" => Some("cone_unverified".to_string()),
        "symmetric_seq" => Some("symmetric_seq".to_string()),
        "symmetric_random" => Some("symmetric_random".to_string()),
        "adm_seq" => Some("adm_seq".to_string()),
        "adm_random" => Some("adm_random".to_string()),
        "apdm_seq" => Some("apdm_seq".to_string()),
        "apdm_random" => Some("apdm_random".to_string()),
        "udp_blocked" => Some("udp_blocked".to_string()),
        _ => None,
    }
}

/// Clamp client-reported NAT port delta to `[-1024, 1024]`.
pub fn normalize_nat_port_delta(raw: Option<i16>) -> Option<i16> {
    raw.map(|d| d.clamp(NAT_PORT_DELTA_MIN, NAT_PORT_DELTA_MAX))
}

/// Validate client-reported NAT port range `[min, max]` (`1 <= min <= max <= 65535`).
/// Invalid or zero-port ranges are safely ignored as `None`.
pub fn normalize_nat_port_range(raw: Option<[u16; 2]>) -> Option<[u16; 2]> {
    let [min_port, max_port] = raw?;
    if min_port == 0 || max_port == 0 || min_port > max_port {
        return None;
    }
    Some([min_port, max_port])
}

/// Update EWMA smoothed RTT estimate in milliseconds (`(3 * prev + sample + 2) / 4`),
/// clamping each sample to `0..=PEER_RTT_MAX_MS`.
pub fn update_smoothed_rtt_ms(prev: Option<u32>, sample_ms: u32) -> u32 {
    let clamped = sample_ms.min(PEER_RTT_MAX_MS);
    match prev {
        Some(old) => (old.saturating_mul(3).saturating_add(clamped) + 2) / 4,
        None => clamped,
    }
}

/// Compute synchronized punch delay `start_after_ms` for a peer:
/// faster peer waits `clamp((peer_rtt - self_rtt) / 2, 0, 500)`, slower peer starts immediately (`0`).
pub fn compute_punch_start_after_ms(self_rtt_ms: u32, peer_rtt_ms: u32) -> u16 {
    if self_rtt_ms >= peer_rtt_ms {
        0
    } else {
        let half_diff = (peer_rtt_ms - self_rtt_ms) / 2;
        u16::try_from(half_diff)
            .unwrap_or(PUNCH_START_AFTER_MAX_MS)
            .min(PUNCH_START_AFTER_MAX_MS)
    }
}

/// Select the legacy single-field `public_udp_addr` pair (`(a_addr, b_addr)`) for `PunchCoord`.
///
/// When both peers have an IPv4 endpoint in `*_all`, both legacy fields (`peer_public_udp_addr`
/// and `self_public_udp_addr`) are pinned to IPv4 so older clients receive IPv4 and
/// `same_public_ip` can perform same-family IPv4-vs-IPv4 comparison even if IPv6 probed last.
/// Otherwise, each side prefers IPv4 from `*_all`, falling back to `*_fallback` or `*_all.first()`.
pub fn select_legacy_public_udp_pair(
    a_all: &[SocketAddr],
    a_fallback: Option<SocketAddr>,
    b_all: &[SocketAddr],
    b_fallback: Option<SocketAddr>,
) -> (Option<String>, Option<String>) {
    let a_v4 = a_all.iter().copied().find(SocketAddr::is_ipv4);
    let b_v4 = b_all.iter().copied().find(SocketAddr::is_ipv4);
    if let (Some(a), Some(b)) = (a_v4, b_v4) {
        return (Some(a.to_string()), Some(b.to_string()));
    }
    let pick = |all: &[SocketAddr], fallback: Option<SocketAddr>| -> Option<String> {
        all.iter()
            .copied()
            .find(SocketAddr::is_ipv4)
            .or(fallback)
            .or_else(|| all.first().copied())
            .map(|addr| addr.to_string())
    };
    (pick(a_all, a_fallback), pick(b_all, b_fallback))
}

#[derive(Debug, Error)]
pub enum SignalError {
    #[error("invalid UDP packet: {0}")]
    InvalidUdpPacket(&'static str),
    #[error("invalid TCP frame: {0}")]
    InvalidFrame(String),
    #[error("frame length {0} exceeds maximum {MAX_SIGNAL_FRAME_LEN}")]
    FrameTooLarge(usize),
    #[error("JSON codec error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// UDP STUN-lite Codec (`RCSP` / `RCSA`)
// ─────────────────────────────────────────────────────────────────────────────

/// Wire layout (22 bytes fixed):
/// `[b"RCSP" (4B)][ver=1 (1B)][device_id: 9B ASCII][nonce: 8B]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpProbeRequest {
    pub device_id: String,
    pub nonce: [u8; 8],
}

impl UdpProbeRequest {
    pub fn encode(&self) -> Result<[u8; UDP_PROBE_LEN], SignalError> {
        let id_bytes = self.device_id.as_bytes();
        if id_bytes.len() != 9 || !id_bytes.iter().all(u8::is_ascii_digit) {
            return Err(SignalError::InvalidUdpPacket(
                "device_id must be exactly 9 ASCII digits",
            ));
        }
        let mut out = [0u8; UDP_PROBE_LEN];
        out[0..4].copy_from_slice(UDP_PROBE_MAGIC);
        out[4] = UDP_PROTO_VERSION;
        out[5..14].copy_from_slice(id_bytes);
        out[14..22].copy_from_slice(&self.nonce);
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> Result<Self, SignalError> {
        if buf.len() != UDP_PROBE_LEN {
            return Err(SignalError::InvalidUdpPacket(
                "RCSP packet must be exactly 22 bytes",
            ));
        }
        if &buf[0..4] != UDP_PROBE_MAGIC {
            return Err(SignalError::InvalidUdpPacket("bad RCSP magic"));
        }
        if buf[4] != UDP_PROTO_VERSION {
            return Err(SignalError::InvalidUdpPacket("unsupported RCSP version"));
        }
        let id_bytes = &buf[5..14];
        if !id_bytes.iter().all(u8::is_ascii_digit) {
            return Err(SignalError::InvalidUdpPacket(
                "device_id must be 9 ASCII digits",
            ));
        }
        let device_id = std::str::from_utf8(id_bytes)
            .map_err(|_| SignalError::InvalidUdpPacket("invalid UTF-8 device_id"))?
            .to_string();
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&buf[14..22]);
        Ok(Self { device_id, nonce })
    }
}

/// Wire layout (38 bytes fixed):
/// `[b"RCSP" (4B)][ver=2 (1B)][device_id: 9B ASCII][nonce: 8B][token: 16B raw]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpProbeRequestV2 {
    pub device_id: String,
    pub nonce: [u8; 8],
    pub token: [u8; UDP_PROBE_TOKEN_LEN],
}

impl UdpProbeRequestV2 {
    pub fn encode(&self) -> Result<[u8; UDP_PROBE_V2_LEN], SignalError> {
        let id_bytes = self.device_id.as_bytes();
        if id_bytes.len() != 9 || !id_bytes.iter().all(u8::is_ascii_digit) {
            return Err(SignalError::InvalidUdpPacket(
                "device_id must be exactly 9 ASCII digits",
            ));
        }
        let mut out = [0u8; UDP_PROBE_V2_LEN];
        out[0..4].copy_from_slice(UDP_PROBE_MAGIC);
        out[4] = UDP_PROTO_VERSION_V2;
        out[5..14].copy_from_slice(id_bytes);
        out[14..22].copy_from_slice(&self.nonce);
        out[22..38].copy_from_slice(&self.token);
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> Result<Self, SignalError> {
        if buf.len() != UDP_PROBE_V2_LEN {
            return Err(SignalError::InvalidUdpPacket(
                "RCSP v2 packet must be exactly 38 bytes",
            ));
        }
        if &buf[0..4] != UDP_PROBE_MAGIC {
            return Err(SignalError::InvalidUdpPacket("bad RCSP magic"));
        }
        if buf[4] != UDP_PROTO_VERSION_V2 {
            return Err(SignalError::InvalidUdpPacket("unsupported RCSP version"));
        }
        let id_bytes = &buf[5..14];
        if !id_bytes.iter().all(u8::is_ascii_digit) {
            return Err(SignalError::InvalidUdpPacket(
                "device_id must be 9 ASCII digits",
            ));
        }
        let device_id = std::str::from_utf8(id_bytes)
            .map_err(|_| SignalError::InvalidUdpPacket("invalid UTF-8 device_id"))?
            .to_string();
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&buf[14..22]);
        let mut token = [0u8; UDP_PROBE_TOKEN_LEN];
        token.copy_from_slice(&buf[22..38]);
        Ok(Self {
            device_id,
            nonce,
            token,
        })
    }
}

/// Versioned RCSP request decoded by the UDP STUN-lite listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedUdpProbe {
    V1(UdpProbeRequest),
    V2(UdpProbeRequestV2),
}

impl DecodedUdpProbe {
    pub fn decode(buf: &[u8]) -> Result<Self, SignalError> {
        if buf.len() < 5 {
            return Err(SignalError::InvalidUdpPacket("RCSP packet too short"));
        }
        if &buf[0..4] != UDP_PROBE_MAGIC {
            return Err(SignalError::InvalidUdpPacket("bad RCSP magic"));
        }
        match buf[4] {
            UDP_PROTO_VERSION => Ok(Self::V1(UdpProbeRequest::decode(buf)?)),
            UDP_PROTO_VERSION_V2 => Ok(Self::V2(UdpProbeRequestV2::decode(buf)?)),
            _ => Err(SignalError::InvalidUdpPacket("unsupported RCSP version")),
        }
    }

    pub fn device_id(&self) -> &str {
        match self {
            Self::V1(req) => &req.device_id,
            Self::V2(req) => &req.device_id,
        }
    }

    pub fn nonce(&self) -> [u8; 8] {
        match self {
            Self::V1(req) => req.nonce,
            Self::V2(req) => req.nonce,
        }
    }
}

/// Wire layout (20 bytes IPv4 / 32 bytes IPv6):
/// `[b"RCSA" (4B)][ver=1 (1B)][ip_len: 1B (4 or 16)][ip_bytes][port: u16 BE][nonce: 8B]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpProbeResponse {
    pub observed_addr: SocketAddr,
    pub nonce: [u8; 8],
}

impl UdpProbeResponse {
    pub fn encode(&self) -> Vec<u8> {
        let canonical = canonical_socket_addr(self.observed_addr);
        let mut out = match canonical.ip() {
            IpAddr::V4(v4) => {
                let mut buf = Vec::with_capacity(20);
                buf.extend_from_slice(UDP_ANSWER_MAGIC);
                buf.push(UDP_PROTO_VERSION);
                buf.push(4);
                buf.extend_from_slice(&v4.octets());
                buf
            }
            IpAddr::V6(v6) => {
                let mut buf = Vec::with_capacity(32);
                buf.extend_from_slice(UDP_ANSWER_MAGIC);
                buf.push(UDP_PROTO_VERSION);
                buf.push(16);
                buf.extend_from_slice(&v6.octets());
                buf
            }
        };
        out.extend_from_slice(&canonical.port().to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, SignalError> {
        if buf.len() < 6 {
            return Err(SignalError::InvalidUdpPacket("RCSA packet too short"));
        }
        if &buf[0..4] != UDP_ANSWER_MAGIC {
            return Err(SignalError::InvalidUdpPacket("bad RCSA magic"));
        }
        if buf[4] != UDP_PROTO_VERSION {
            return Err(SignalError::InvalidUdpPacket("unsupported RCSA version"));
        }
        let ip_len = buf[5] as usize;
        let expected_len = 6 + ip_len + 2 + 8;
        if (ip_len != 4 && ip_len != 16) || buf.len() != expected_len {
            return Err(SignalError::InvalidUdpPacket(
                "invalid RCSA ip_len or packet length",
            ));
        }
        let ip = if ip_len == 4 {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&buf[6..10]);
            IpAddr::V4(Ipv4Addr::from(octets))
        } else {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[6..22]);
            IpAddr::V6(Ipv6Addr::from(octets))
        };
        let port_offset = 6 + ip_len;
        let port = u16::from_be_bytes([buf[port_offset], buf[port_offset + 1]]);
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&buf[port_offset + 2..port_offset + 10]);
        Ok(Self {
            observed_addr: SocketAddr::new(ip, port),
            nonce,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Native TCP Framed Signaling Codec (`[u32 BE length (1..=65536)][UTF-8 JSON]`)
// ─────────────────────────────────────────────────────────────────────────────

fn default_true() -> bool {
    true
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveControllerSummary {
    pub session_id: String,
    #[serde(default)]
    pub controller_device_id: String,
    #[serde(default)]
    pub controller_device_name: String,
    #[serde(default)]
    pub controller_os: String,
    #[serde(default)]
    pub is_owner: bool,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub connected_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalMsg {
    Register {
        #[serde(default)]
        device_id: Option<String>,
        device_key: String,
        #[serde(default)]
        hostname: String,
        #[serde(default)]
        os: String,
        #[serde(default)]
        app_version: String,
        #[serde(default)]
        arch: String,
        #[serde(default, deserialize_with = "deserialize_null_default")]
        cpu_model: String,
        #[serde(default, deserialize_with = "deserialize_null_default")]
        mac_address: String,
        #[serde(default, deserialize_with = "deserialize_null_default")]
        total_memory_mb: u64,
        #[serde(default, deserialize_with = "deserialize_null_default")]
        os_version: String,
        #[serde(default, deserialize_with = "deserialize_null_default")]
        gpu_model: String,
        #[serde(default, alias = "group")]
        device_group: String,
        #[serde(default)]
        lan_addrs: Vec<String>,
        #[serde(default)]
        access_token: Option<String>,
        #[serde(default)]
        device_pubkey: Option<String>,
        #[serde(default)]
        allow_remote_assist: Option<bool>,
        #[serde(default)]
        allow_remote_control: Option<bool>,
        #[serde(default)]
        mac_addr: Option<String>,
        #[serde(default)]
        wol_enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nat_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nat_port_delta: Option<i16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nat_port_range: Option<[u16; 2]>,
        #[serde(default)]
        rcp2_v2: bool,
    },
    Registered {
        device_id: String,
        formatted_id: String,
        server_time: DateTime<Utc>,
        udp_probe_addr: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_probe_alt_addr: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_probe_alt_ip_addr: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_probe_token: Option<String>,
        relay_addr: String,
    },
    Heartbeat {
        #[serde(default)]
        lan_addrs: Vec<String>,
        #[serde(default)]
        mac_addr: Option<String>,
        #[serde(default)]
        wol_enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nat_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nat_port_delta: Option<i16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nat_port_range: Option<[u16; 2]>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rtt_ms: Option<u32>,
    },
    HeartbeatAck {
        server_time: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        public_udp_addr: Option<String>,
        online_peers: usize,
    },
    UpdateAssistState {
        #[serde(default)]
        allow_remote_assist: Option<bool>,
        #[serde(default)]
        allow_remote_control: Option<bool>,
        #[serde(default)]
        mac_addr: Option<String>,
        #[serde(default)]
        wol_enabled: Option<bool>,
        #[serde(default)]
        cpu_model: Option<String>,
        #[serde(default)]
        mac_address: Option<String>,
        #[serde(default)]
        total_memory_mb: Option<u64>,
        #[serde(default)]
        os_version: Option<String>,
        #[serde(default)]
        gpu_model: Option<String>,
    },
    DeviceStatusChanged {
        device_id: String,
        online: bool,
        hostname: String,
        alias: String,
        os: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        app_version: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        arch: String,
        #[serde(
            default,
            skip_serializing_if = "String::is_empty",
            deserialize_with = "deserialize_null_default"
        )]
        cpu_model: String,
        #[serde(
            default,
            skip_serializing_if = "String::is_empty",
            deserialize_with = "deserialize_null_default"
        )]
        mac_address: String,
        #[serde(
            default,
            skip_serializing_if = "is_zero_u64",
            deserialize_with = "deserialize_null_default"
        )]
        total_memory_mb: u64,
        #[serde(
            default,
            skip_serializing_if = "String::is_empty",
            deserialize_with = "deserialize_null_default"
        )]
        os_version: String,
        #[serde(
            default,
            skip_serializing_if = "String::is_empty",
            deserialize_with = "deserialize_null_default"
        )]
        gpu_model: String,
        allow_remote_assist: bool,
        #[serde(default = "default_true")]
        allow_remote_control: bool,
        #[serde(default)]
        wol_capable: bool,
    },
    ControlStateReport {
        #[serde(default)]
        active_controllers: Vec<ActiveControllerSummary>,
    },
    DeviceControlStateChanged {
        device_id: String,
        #[serde(default)]
        active_controllers: Vec<ActiveControllerSummary>,
    },
    ForceDisconnectRequest {
        target_id: String,
        #[serde(default)]
        controller_device_id: Option<String>,
        #[serde(default)]
        session_id: Option<String>,
    },
    ForceDisconnect {
        requester_device_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        controller_device_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
    },
    ConnectRequest {
        target_id: String,
        #[serde(default)]
        session_id: Option<String>,
        #[serde(default)]
        lan_addrs: Vec<String>,
        #[serde(default)]
        nonce: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nat_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nat_port_delta: Option<i16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nat_port_range: Option<[u16; 2]>,
        #[serde(default)]
        takeover: bool,
    },
    PunchCoord {
        session_id: String,
        role: String,
        peer_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        peer_public_udp_addr: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        peer_public_udp_addrs: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        self_public_udp_addr: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_nat_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_nat_port_delta: Option<i16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        self_nat_port_range: Option<[u16; 2]>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_nat_port_range: Option<[u16; 2]>,
        peer_lan_addrs: Vec<String>,
        nonce: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        punch_secret: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        start_after_ms: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_fallback_after_ms: Option<u16>,
        relay_token: String,
        relay_addr: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner_grant: Option<OwnerGrantTicket>,
        #[serde(default)]
        is_owner_connection: bool,
        #[serde(default)]
        takeover: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_hostname: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_os: Option<String>,
    },
    RelayAlloc {
        target_id: String,
        #[serde(default)]
        session_id: Option<String>,
        #[serde(default)]
        takeover: bool,
    },
    RelayReady {
        session_id: String,
        role: String,
        peer_id: String,
        relay_token: String,
        relay_addr: String,
        expires_in_sec: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner_grant: Option<OwnerGrantTicket>,
        #[serde(default)]
        is_owner_connection: bool,
        #[serde(default)]
        takeover: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_hostname: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_os: Option<String>,
    },
    PeerOffline {
        target_id: String,
        session_id: String,
    },
    WolRequest {
        #[serde(default)]
        request_id: Option<String>,
        target_device_id: String,
    },
    WolRelay {
        request_id: String,
        target_device_id: String,
        mac_addr: String,
        #[serde(default)]
        target_lan_addrs: Vec<String>,
    },
    WolAck {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        target_device_id: String,
        ok: bool,
        method: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<String>,
        message: String,
    },
    Kicked {
        reason: String,
    },
    Error {
        code: String,
        message: String,
    },
}

pub fn encode_signal_frame(msg: &SignalMsg) -> Result<Vec<u8>, SignalError> {
    let payload = serde_json::to_vec(msg)?;
    if payload.is_empty() {
        return Err(SignalError::InvalidFrame("empty JSON payload".into()));
    }
    if payload.len() > MAX_SIGNAL_FRAME_LEN {
        return Err(SignalError::FrameTooLarge(payload.len()));
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_signal_frame(bytes: &[u8]) -> Result<SignalMsg, SignalError> {
    if bytes.len() < 4 {
        return Err(SignalError::InvalidFrame(
            "frame shorter than 4-byte header".into(),
        ));
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if len == 0 {
        return Err(SignalError::InvalidFrame(
            "frame length must be >= 1".into(),
        ));
    }
    if len > MAX_SIGNAL_FRAME_LEN {
        return Err(SignalError::FrameTooLarge(len));
    }
    if bytes.len() != 4 + len {
        return Err(SignalError::InvalidFrame(format!(
            "frame length mismatch: header={len}, actual={}",
            bytes.len() - 4
        )));
    }
    Ok(serde_json::from_slice(&bytes[4..])?)
}

pub async fn read_signal_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<SignalMsg>, SignalError> {
    let mut header = [0u8; 4];
    let mut filled = 0usize;
    while filled < 4 {
        let n = reader.read(&mut header[filled..]).await?;
        if n == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(SignalError::InvalidFrame(
                "unexpected EOF while reading frame header".into(),
            ));
        }
        filled += n;
    }

    let len = u32::from_be_bytes(header) as usize;
    if len == 0 {
        return Err(SignalError::InvalidFrame(
            "frame length must be >= 1".into(),
        ));
    }
    if len > MAX_SIGNAL_FRAME_LEN {
        return Err(SignalError::FrameTooLarge(len));
    }

    let mut payload = Vec::with_capacity(len.min(INITIAL_FRAME_BUF_CAP));
    let mut limited = (&mut *reader).take(len as u64);
    limited.read_to_end(&mut payload).await?;
    if payload.len() != len {
        return Err(SignalError::InvalidFrame(format!(
            "unexpected EOF while reading frame payload: expected {len} bytes, got {}",
            payload.len()
        )));
    }
    let msg = serde_json::from_slice(&payload)?;
    Ok(Some(msg))
}

pub async fn write_signal_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &SignalMsg,
) -> Result<(), SignalError> {
    let frame = encode_signal_frame(msg)?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// SignalHub (Native TCP Signaling + UDP STUN-lite Probe)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SignalConfig {
    pub online_ttl: Duration,
    pub udp_ttl: Duration,
    pub relay_token_ttl: Duration,
    pub handshake_timeout: Duration,
    pub read_idle_timeout: Duration,
    pub write_timeout: Duration,
    pub channel_capacity: usize,
    pub max_connections: usize,
    pub max_relay_tokens: usize,
    pub connect_rate_limit_max: usize,
    pub connect_rate_limit_window: Duration,
    pub udp_rate_limit_max: usize,
    pub udp_rate_limit_window: Duration,
    pub wol_rate_limit_window: Duration,
    pub wol_caller_rate_limit_max: usize,
    pub wol_caller_rate_limit_window: Duration,
    pub allow_server_wol: bool,
    pub public_udp_probe_addr: String,
    pub public_udp_probe_alt_addr: Option<String>,
    pub public_udp_probe_alt_ip_addr: Option<String>,
    pub public_relay_addr: String,
    pub relay_fallback_after_ms: u16,
    pub require_auth: bool,
}

impl Default for SignalConfig {
    fn default() -> Self {
        Self {
            online_ttl: Duration::from_secs(150),
            udp_ttl: Duration::from_secs(120),
            relay_token_ttl: Duration::from_secs(60),
            handshake_timeout: Duration::from_secs(10),
            read_idle_timeout: Duration::from_secs(120),
            write_timeout: Duration::from_secs(5),
            channel_capacity: 64,
            max_connections: DEFAULT_MAX_SIGNAL_CONNECTIONS,
            max_relay_tokens: DEFAULT_MAX_RELAY_TOKENS,
            connect_rate_limit_max: DEFAULT_CONNECT_RATE_LIMIT_MAX,
            connect_rate_limit_window: DEFAULT_CONNECT_RATE_LIMIT_WINDOW,
            udp_rate_limit_max: DEFAULT_UDP_RATE_LIMIT_MAX,
            udp_rate_limit_window: DEFAULT_UDP_RATE_LIMIT_WINDOW,
            wol_rate_limit_window: DEFAULT_WOL_RATE_LIMIT_WINDOW,
            wol_caller_rate_limit_max: DEFAULT_WOL_CALLER_RATE_LIMIT_MAX,
            wol_caller_rate_limit_window: DEFAULT_WOL_CALLER_RATE_LIMIT_WINDOW,
            allow_server_wol: false,
            public_udp_probe_addr: "127.0.0.1:21116".to_string(),
            public_udp_probe_alt_addr: None,
            public_udp_probe_alt_ip_addr: None,
            public_relay_addr: "127.0.0.1:21117".to_string(),
            relay_fallback_after_ms: DEFAULT_RELAY_FALLBACK_AFTER_MS,
            require_auth: true,
        }
    }
}

/// Build a standard 102-byte Wake-on-LAN magic packet (`6×0xFF + 16×MAC`).
/// Returns `None` if `mac_addr` is not a valid unicast MAC address.
pub fn build_wol_magic_packet(mac_addr: &str) -> Option<[u8; WOL_MAGIC_PACKET_LEN]> {
    let mac_bytes = parse_mac_addr_bytes(mac_addr)?;
    let mut pkt = [0u8; WOL_MAGIC_PACKET_LEN];
    pkt[0..6].fill(0xFF);
    for i in 0..16 {
        let start = 6 + i * 6;
        pkt[start..start + 6].copy_from_slice(&mac_bytes);
    }
    Some(pkt)
}

fn extract_private_ipv4(addr: &str) -> Option<Ipv4Addr> {
    let trimmed = addr.trim();
    let ip = trimmed
        .parse::<SocketAddr>()
        .map(|sa| canonical_ip(sa.ip()))
        .or_else(|_| trimmed.parse::<IpAddr>().map(canonical_ip))
        .ok()?;
    match ip {
        IpAddr::V4(v4) if v4.is_private() => Some(v4),
        _ => None,
    }
}

fn share_private_ipv4_slash24(a: &[String], b: &[String]) -> bool {
    let a_nets: Vec<[u8; 3]> = a
        .iter()
        .filter_map(|s| extract_private_ipv4(s))
        .map(|v4| {
            let o = v4.octets();
            [o[0], o[1], o[2]]
        })
        .collect();
    if a_nets.is_empty() {
        return false;
    }
    b.iter().filter_map(|s| extract_private_ipv4(s)).any(|v4| {
        let o = v4.octets();
        a_nets.contains(&[o[0], o[1], o[2]])
    })
}

fn is_routable_public_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let is_cgnat = o[0] == 100 && (o[1] & 0b1100_0000) == 64;
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || is_cgnat)
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local())
        }
    }
}

/// Score a same-account online candidate peer for Wake-on-LAN LAN relay.
///
/// Priority:
/// - `3`: same public IP AND shared RFC 1918 IPv4 `/24` private subnet
/// - `2`: same public IP (same NAT site)
/// - `1`: shared RFC 1918 IPv4 `/24` private subnet fallback (ONLY when `target_public_ip` is
///   empty or at least one side is private/loopback/non-public; strictly `0` when both sides
///   have distinct routable public IPs to avoid cross-site misrouting on `192.168.1.0/24`)
/// - `0`: ineligible
fn score_wol_relay_candidate(
    target_public_ip_raw: &str,
    target_lan_addrs: &[String],
    peer_remote_ip: IpAddr,
    peer_lan_addrs: &[String],
) -> u8 {
    let target_ip = target_public_ip_raw
        .trim()
        .parse::<IpAddr>()
        .ok()
        .map(canonical_ip);
    let peer_ip = canonical_ip(peer_remote_ip);
    let same_public_ip = target_ip.is_some_and(|tip| tip == peer_ip);
    let both_distinct_public_ips = target_ip.is_some_and(|tip| {
        tip != peer_ip && is_routable_public_ip(tip) && is_routable_public_ip(peer_ip)
    });

    if both_distinct_public_ips {
        return 0;
    }

    let same_lan_subnet = share_private_ipv4_slash24(peer_lan_addrs, target_lan_addrs);
    match (same_public_ip, same_lan_subnet) {
        (true, true) => 3,
        (true, false) => 2,
        (false, true) => 1,
        (false, false) => 0,
    }
}

/// Compute directed `/24` subnet broadcast destinations (port 9) for all private IPv4 LAN
/// addresses, followed by the limited broadcast address `255.255.255.255:9`.
pub fn wol_broadcast_targets(target_lan_addrs: &[String]) -> Vec<SocketAddr> {
    let mut targets = Vec::new();
    for raw in target_lan_addrs {
        if let Some(v4) = extract_private_ipv4(raw) {
            let o = v4.octets();
            let bcast = SocketAddr::from((Ipv4Addr::new(o[0], o[1], o[2], 255), WOL_UDP_PORT));
            if !targets.contains(&bcast) {
                targets.push(bcast);
            }
        }
    }
    let global = SocketAddr::from((Ipv4Addr::BROADCAST, WOL_UDP_PORT));
    if !targets.contains(&global) {
        targets.push(global);
    }
    targets
}

async fn send_server_wol_magic_packet(
    mac_addr: &str,
    target_lan_addrs: &[String],
) -> io::Result<()> {
    let packet = build_wol_magic_packet(mac_addr)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid unicast mac_addr"))?;
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
    socket.set_broadcast(true)?;
    let destinations = wol_broadcast_targets(target_lan_addrs);
    let mut sent_ok = 0usize;
    let mut last_err: Option<io::Error> = None;
    for dest in destinations {
        match socket.send_to(&packet, dest).await {
            Ok(_) => sent_ok += 1,
            Err(err) => {
                debug!(%dest, error = %err, "server WoL broadcast send_to failed");
                last_err = Some(err);
            }
        }
    }
    if sent_ok > 0 {
        Ok(())
    } else {
        Err(last_err
            .unwrap_or_else(|| io::Error::other("no Wake-on-LAN broadcast destination succeeded")))
    }
}

fn validate_optional_signal_mac_addr(
    mac_addr: Option<&str>,
) -> Result<Option<String>, &'static str> {
    let Some(raw) = mac_addr else {
        return Ok(None);
    };
    if raw.contains('\0') || raw.chars().any(char::is_control) {
        return Err("mac_addr must not contain NUL or control characters");
    }
    if raw.trim().is_empty() {
        return Ok(None);
    }
    normalize_mac_addr(raw)
        .map(Some)
        .ok_or("invalid unicast mac_addr")
}

fn validate_ascii_token(val: &str, max_len: usize, field: &'static str) -> Result<(), String> {
    if val.len() > max_len {
        return Err(format!("{field} exceeds maximum length of {max_len} bytes"));
    }
    if !val.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "{field} must contain only printable ASCII non-whitespace characters"
        ));
    }
    Ok(())
}

fn resolve_optional_ascii_token(
    opt: Option<String>,
    max_len: usize,
    default_bytes: usize,
    field: &'static str,
) -> Result<String, String> {
    match opt {
        None => Ok(random_hex(default_bytes)),
        Some(s) if s.is_empty() => Ok(random_hex(default_bytes)),
        Some(s) => {
            validate_ascii_token(&s, max_len, field)?;
            Ok(s)
        }
    }
}

fn validate_lan_addrs(addrs: &[String]) -> Result<(), String> {
    if addrs.len() > MAX_LAN_ADDRS {
        return Err(format!(
            "lan_addrs exceeds maximum of {MAX_LAN_ADDRS} entries"
        ));
    }
    for addr in addrs {
        if addr.is_empty() || addr.len() > MAX_LAN_ADDR_LEN {
            return Err(format!(
                "each lan_addrs entry must be 1..={MAX_LAN_ADDR_LEN} bytes"
            ));
        }
        if !addr.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(
                "lan_addrs entries must contain only printable ASCII non-whitespace characters"
                    .into(),
            );
        }
    }
    Ok(())
}

fn validate_metadata_field(val: &str, max_len: usize, field: &'static str) -> Result<(), String> {
    if val.len() > max_len {
        return Err(format!("{field} exceeds maximum length of {max_len} bytes"));
    }
    if val.contains('\0') || val.chars().any(char::is_control) {
        return Err(format!(
            "{field} must not contain NUL or control characters"
        ));
    }
    Ok(())
}

struct RegisterMetadataFields<'a> {
    hostname: &'a str,
    os: &'a str,
    app_version: &'a str,
    arch: &'a str,
    cpu_model: &'a str,
    mac_address: &'a str,
    total_memory_mb: u64,
    os_version: &'a str,
    gpu_model: &'a str,
    device_group: &'a str,
    lan_addrs: &'a [String],
}

fn validate_register_fields(fields: RegisterMetadataFields<'_>) -> Result<String, String> {
    validate_metadata_field(fields.hostname, MAX_HOSTNAME_LEN, "hostname")?;
    validate_metadata_field(fields.os, MAX_OS_LEN, "os")?;
    validate_metadata_field(fields.app_version, MAX_APP_VERSION_LEN, "app_version")?;
    validate_metadata_field(fields.arch, MAX_ARCH_LEN, "arch")?;
    validate_metadata_field(fields.cpu_model, MAX_CPU_MODEL_LEN, "cpu_model")?;
    let norm_mac_address =
        normalize_display_mac_address(fields.mac_address).map_err(|e| e.to_string())?;
    validate_total_memory_mb(fields.total_memory_mb).map_err(|e| e.to_string())?;
    validate_metadata_field(fields.os_version, MAX_OS_VERSION_LEN, "os_version")?;
    validate_metadata_field(fields.gpu_model, MAX_GPU_MODEL_LEN, "gpu_model")?;
    validate_metadata_field(fields.device_group, MAX_DEVICE_GROUP_LEN, "device_group")?;
    validate_lan_addrs(fields.lan_addrs)?;
    Ok(norm_mac_address)
}

fn validate_optional_signal_text(
    raw: Option<&str>,
    max_len: usize,
    field: &'static str,
) -> Result<Option<String>, String> {
    let Some(val) = raw else {
        return Ok(None);
    };
    let cleaned = validate_text_field(val, max_len, field).map_err(|e| e.to_string())?;
    if cleaned.is_empty() {
        Ok(None)
    } else {
        Ok(Some(cleaned))
    }
}

fn validate_optional_signal_mac_address(raw: Option<&str>) -> Result<Option<String>, String> {
    let Some(val) = raw else {
        return Ok(None);
    };
    let cleaned = normalize_display_mac_address(val).map_err(|e| e.to_string())?;
    if cleaned.is_empty() {
        Ok(None)
    } else {
        Ok(Some(cleaned))
    }
}

fn validate_optional_signal_total_memory_mb(raw: Option<u64>) -> Result<Option<u64>, String> {
    let Some(val) = raw else {
        return Ok(None);
    };
    let checked = validate_total_memory_mb(val).map_err(|e| e.to_string())?;
    if checked == 0 {
        Ok(None)
    } else {
        Ok(Some(checked))
    }
}

fn non_empty_opt(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn validate_active_controllers(items: &[ActiveControllerSummary]) -> Result<(), String> {
    if items.len() > MAX_ACTIVE_CONTROLLERS {
        return Err(format!(
            "active_controllers exceeds maximum of {MAX_ACTIVE_CONTROLLERS} entries"
        ));
    }
    for item in items {
        if item.session_id.is_empty() {
            return Err("active_controllers session_id must not be empty".into());
        }
        validate_ascii_token(&item.session_id, MAX_SESSION_ID_LEN, "session_id")?;
        validate_metadata_field(
            &item.controller_device_id,
            MAX_CONTROLLER_DEVICE_ID_LEN,
            "controller_device_id",
        )?;
        validate_metadata_field(
            &item.controller_device_name,
            MAX_HOSTNAME_LEN,
            "controller_device_name",
        )?;
        validate_metadata_field(&item.controller_os, MAX_OS_LEN, "controller_os")?;
        validate_metadata_field(&item.mode, MAX_CONTROLLER_MODE_LEN, "mode")?;
    }
    Ok(())
}

fn device_lock_index(device_id: &str) -> usize {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in device_id.as_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    (hash as usize) % DEVICE_LOCK_STRIPES
}

fn check_sliding_window_rate_limit<K>(
    table: &DashMap<K, VecDeque<Instant>>,
    key: K,
    max_requests: usize,
    window: Duration,
) -> bool
where
    K: Eq + std::hash::Hash + Clone,
{
    if max_requests == 0 {
        return false;
    }
    let now = Instant::now();
    if table.len() >= MAX_RATE_LIMIT_TRACKED_KEYS && !table.contains_key(&key) {
        table.retain(|_, q| {
            while q
                .front()
                .is_some_and(|t| now.saturating_duration_since(*t) >= window)
            {
                q.pop_front();
            }
            !q.is_empty()
        });
        if table.len() >= MAX_RATE_LIMIT_TRACKED_KEYS {
            let evict_keys: Vec<K> = table
                .iter()
                .take(256)
                .map(|entry| entry.key().clone())
                .collect();
            for k in evict_keys {
                table.remove(&k);
            }
        }
    }

    let mut entry = table.entry(key).or_default();
    let queue = entry.value_mut();
    while queue
        .front()
        .is_some_and(|t| now.saturating_duration_since(*t) >= window)
    {
        queue.pop_front();
    }
    if queue.len() >= max_requests {
        return false;
    }
    queue.push_back(now);
    true
}

#[derive(Clone)]
struct SignalShutdown {
    cancelled: Arc<AtomicBool>,
    tx: Arc<watch::Sender<bool>>,
}

impl SignalShutdown {
    fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            tx: Arc::new(tx),
        }
    }

    fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            let _ = self.tx.send(true);
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        let mut rx = self.tx.subscribe();
        if *rx.borrow_and_update() || self.is_cancelled() {
            return;
        }
        while rx.changed().await.is_ok() {
            if *rx.borrow_and_update() || self.is_cancelled() {
                return;
            }
        }
    }
}

async fn wait_external_shutdown(rx: &mut Option<watch::Receiver<bool>>) {
    let Some(rx) = rx.as_mut() else {
        std::future::pending::<()>().await;
        return;
    };
    if *rx.borrow_and_update() {
        return;
    }
    while rx.changed().await.is_ok() {
        if *rx.borrow_and_update() {
            return;
        }
    }
}

struct SignalTaskGuard {
    hub: Arc<SignalHub>,
}

impl SignalTaskGuard {
    fn enter(hub: Arc<SignalHub>) -> Self {
        hub.in_flight_tasks.fetch_add(1, Ordering::AcqRel);
        Self { hub }
    }
}

impl Drop for SignalTaskGuard {
    fn drop(&mut self) {
        if self.hub.in_flight_tasks.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.hub.tasks_drained.notify_waiters();
        }
    }
}

#[derive(Debug, Clone)]
struct PeerCancel {
    tx: Arc<watch::Sender<Option<String>>>,
}

impl PeerCancel {
    fn new() -> Self {
        let (tx, _rx) = watch::channel(None);
        Self { tx: Arc::new(tx) }
    }

    fn kick(&self, reason: impl Into<String>) {
        let reason = reason.into();
        self.tx.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some(reason);
                true
            }
        });
    }

    fn is_kicked(&self) -> bool {
        self.tx.borrow().is_some()
    }

    fn kick_reason(&self) -> Option<String> {
        self.tx.borrow().clone()
    }

    fn subscribe(&self) -> watch::Receiver<Option<String>> {
        self.tx.subscribe()
    }
}

async fn wait_kicked(rx: &mut watch::Receiver<Option<String>>) -> String {
    if let Some(reason) = rx.borrow_and_update().clone() {
        return reason;
    }
    while rx.changed().await.is_ok() {
        if let Some(reason) = rx.borrow_and_update().clone() {
            return reason;
        }
    }
    "disconnected".to_string()
}

async fn write_frame_with_timeout<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &SignalMsg,
    timeout: Duration,
) {
    let _ = tokio::time::timeout(timeout, write_signal_frame(writer, msg)).await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnqueueError {
    FrameTooLarge,
    Full,
    Closed,
}

struct DeviceStatusBroadcast<'a> {
    owner_user_id: Option<Uuid>,
    device_id: &'a str,
    online: bool,
    hostname: &'a str,
    alias: &'a str,
    os: &'a str,
    app_version: &'a str,
    arch: &'a str,
    cpu_model: &'a str,
    mac_address: &'a str,
    total_memory_mb: u64,
    os_version: &'a str,
    gpu_model: &'a str,
    allow_remote_assist: bool,
    allow_remote_control: bool,
    wol_capable: bool,
}

struct OwnedDeviceStatus {
    owner_user_id: Option<Uuid>,
    hostname: String,
    alias: String,
    os: String,
    app_version: String,
    arch: String,
    cpu_model: String,
    mac_address: String,
    total_memory_mb: u64,
    os_version: String,
    gpu_model: String,
    allow_remote_assist: bool,
    allow_remote_control: bool,
    wol_capable: bool,
}

impl ActivePeer {
    fn to_owned_status(&self) -> OwnedDeviceStatus {
        OwnedDeviceStatus {
            owner_user_id: self.owner_user_id,
            hostname: self.hostname.clone(),
            alias: self.alias.clone(),
            os: self.os.clone(),
            app_version: self.app_version.clone(),
            arch: self.arch.clone(),
            cpu_model: self.cpu_model.clone(),
            mac_address: self.mac_address.clone(),
            total_memory_mb: self.total_memory_mb,
            os_version: self.os_version.clone(),
            gpu_model: self.gpu_model.clone(),
            allow_remote_assist: self.allow_remote_assist,
            allow_remote_control: self.allow_remote_control,
            wol_capable: self.wol_capable,
        }
    }
}

#[derive(Debug, Clone)]
struct ActivePeer {
    conn_id: u64,
    tx: mpsc::Sender<SignalMsg>,
    cancel: PeerCancel,
    lan_addrs: Vec<String>,
    remote_addr: SocketAddr,
    connected_at: DateTime<Utc>,
    owner_user_id: Option<Uuid>,
    device_pubkey: String,
    allow_remote_assist: bool,
    allow_remote_control: bool,
    wol_capable: bool,
    hostname: String,
    alias: String,
    os: String,
    app_version: String,
    arch: String,
    cpu_model: String,
    mac_address: String,
    total_memory_mb: u64,
    os_version: String,
    gpu_model: String,
    udp_probe_token: Option<[u8; UDP_PROBE_TOKEN_LEN]>,
    nat_type: Option<String>,
    nat_port_delta: Option<i16>,
    nat_port_range: Option<[u16; 2]>,
    smoothed_rtt_ms: Option<u32>,
    rcp2_v2: bool,
    active_controllers: Vec<ActiveControllerSummary>,
}

#[derive(Debug, Clone)]
struct PeerNatUpdate {
    nat_type: Option<String>,
    nat_port_delta: Option<i16>,
    nat_port_range: Option<[u16; 2]>,
}

fn apply_peer_nat_update(
    peer: &mut ActivePeer,
    nat_type: Option<&str>,
    nat_port_delta: Option<i16>,
    nat_port_range: Option<[u16; 2]>,
) {
    let norm_nat_type = normalize_nat_type(nat_type);
    let norm_nat_delta = normalize_nat_port_delta(nat_port_delta);
    let norm_nat_range = normalize_nat_port_range(nat_port_range);
    if let Some(nt) = norm_nat_type {
        peer.nat_type = Some(nt);
        peer.nat_port_delta = norm_nat_delta;
        peer.nat_port_range = norm_nat_range;
    } else {
        if let Some(delta) = norm_nat_delta {
            peer.nat_port_delta = Some(delta);
        }
        if let Some(range) = norm_nat_range {
            peer.nat_port_range = Some(range);
        }
    }
}

pub struct SignalHub {
    device_store: Arc<dyn DeviceStore>,
    auth_store: Option<Arc<dyn AuthStore>>,
    auth_authority: Option<Arc<AuthAuthority>>,
    ephemeral: Arc<dyn EphemeralStore>,
    peers: DashMap<String, ActivePeer>,
    device_locks: [Mutex<()>; DEVICE_LOCK_STRIPES],
    connect_rate_limits: DashMap<String, VecDeque<Instant>>,
    udp_rate_limits: DashMap<IpAddr, VecDeque<Instant>>,
    wol_rate_limits: DashMap<String, VecDeque<Instant>>,
    wol_caller_rate_limits: DashMap<String, VecDeque<Instant>>,
    issued_relay_tokens: DashMap<String, Instant>,
    conn_semaphore: Arc<Semaphore>,
    shutdown: SignalShutdown,
    in_flight_tasks: AtomicUsize,
    tasks_drained: Notify,
    config: SignalConfig,
    next_conn_id: AtomicU64,
    punch_coord_count: AtomicU64,
}

impl SignalHub {
    /// Legacy constructor without user authentication (`require_auth` forced to `false`).
    pub fn new(
        device_store: Arc<dyn DeviceStore>,
        ephemeral: Arc<dyn EphemeralStore>,
        mut config: SignalConfig,
    ) -> Self {
        config.require_auth = false;
        let max_connections = config.max_connections.max(1);
        Self {
            device_store,
            auth_store: None,
            auth_authority: None,
            ephemeral,
            peers: DashMap::new(),
            device_locks: std::array::from_fn(|_| Mutex::new(())),
            connect_rate_limits: DashMap::new(),
            udp_rate_limits: DashMap::new(),
            wol_rate_limits: DashMap::new(),
            wol_caller_rate_limits: DashMap::new(),
            issued_relay_tokens: DashMap::new(),
            conn_semaphore: Arc::new(Semaphore::new(max_connections)),
            shutdown: SignalShutdown::new(),
            in_flight_tasks: AtomicUsize::new(0),
            tasks_drained: Notify::new(),
            config,
            next_conn_id: AtomicU64::new(1),
            punch_coord_count: AtomicU64::new(0),
        }
    }

    /// Production constructor wired with `AuthStore`, `AuthAuthority`, and `EphemeralStore`.
    pub fn with_auth(
        auth_store: Arc<dyn AuthStore>,
        ephemeral: Arc<dyn EphemeralStore>,
        auth_authority: Arc<AuthAuthority>,
        config: SignalConfig,
    ) -> Self {
        let device_store: Arc<dyn DeviceStore> = auth_store.clone();
        let max_connections = config.max_connections.max(1);
        Self {
            device_store,
            auth_store: Some(auth_store),
            auth_authority: Some(auth_authority),
            ephemeral,
            peers: DashMap::new(),
            device_locks: std::array::from_fn(|_| Mutex::new(())),
            connect_rate_limits: DashMap::new(),
            udp_rate_limits: DashMap::new(),
            wol_rate_limits: DashMap::new(),
            wol_caller_rate_limits: DashMap::new(),
            issued_relay_tokens: DashMap::new(),
            conn_semaphore: Arc::new(Semaphore::new(max_connections)),
            shutdown: SignalShutdown::new(),
            in_flight_tasks: AtomicUsize::new(0),
            tasks_drained: Notify::new(),
            config,
            next_conn_id: AtomicU64::new(1),
            punch_coord_count: AtomicU64::new(0),
        }
    }

    pub fn config(&self) -> &SignalConfig {
        &self.config
    }

    pub fn online_count(&self) -> usize {
        self.peers.len()
    }

    pub fn in_flight_task_count(&self) -> usize {
        self.in_flight_tasks.load(Ordering::Acquire)
    }

    pub fn punch_coord_count(&self) -> u64 {
        self.punch_coord_count.load(Ordering::Relaxed)
    }

    pub fn is_peer_connected(&self, device_id: &str) -> bool {
        let norm = normalize_device_id(device_id);
        self.peers.contains_key(&norm)
    }

    pub fn peer_lan_addrs(&self, device_id: &str) -> Option<Vec<String>> {
        let norm = normalize_device_id(device_id);
        self.peers.get(&norm).map(|p| p.lan_addrs.clone())
    }

    pub fn peer_remote_addr(&self, device_id: &str) -> Option<SocketAddr> {
        let norm = normalize_device_id(device_id);
        self.peers.get(&norm).map(|p| p.remote_addr)
    }

    pub fn peer_connected_at(&self, device_id: &str) -> Option<DateTime<Utc>> {
        let norm = normalize_device_id(device_id);
        self.peers.get(&norm).map(|p| p.connected_at)
    }

    pub fn peer_active_controllers(&self, device_id: &str) -> Vec<ActiveControllerSummary> {
        let norm = normalize_device_id(device_id);
        self.peers
            .get(&norm)
            .map(|p| p.active_controllers.clone())
            .unwrap_or_default()
    }

    /// Return the peer's smoothed signaling RTT estimate in milliseconds, falling back to `0`
    /// when no RTT sample has been observed yet (or the peer is offline).
    pub fn peer_smoothed_rtt_ms(&self, device_id: &str) -> u32 {
        let norm = normalize_device_id(device_id);
        self.peers
            .get(&norm)
            .and_then(|p| p.smoothed_rtt_ms)
            .unwrap_or(0)
    }

    /// Record an observed RTT sample (in ms) for an online peer using EWMA smoothing.
    pub fn record_peer_rtt_ms(&self, device_id: &str, sample_ms: u32) -> Option<u32> {
        let norm = normalize_device_id(device_id);
        self.peers.get_mut(&norm).map(|mut p| {
            let next = update_smoothed_rtt_ms(p.smoothed_rtt_ms, sample_ms);
            p.smoothed_rtt_ms = Some(next);
            next
        })
    }

    async fn lock_device(&self, device_id: &str) -> tokio::sync::MutexGuard<'_, ()> {
        self.device_locks[device_lock_index(device_id)].lock().await
    }

    fn is_active_conn(&self, device_id: &str, conn_id: u64, cancel: &PeerCancel) -> bool {
        !cancel.is_kicked()
            && self
                .peers
                .get(device_id)
                .is_some_and(|peer| peer.conn_id == conn_id)
    }

    /// Cancel accepting new connections/probes, kick all connected peers, and drain all
    /// tracked signaling and UDP update tasks cleanly.
    pub async fn shutdown_all(&self) {
        self.shutdown.cancel();
        let peer_ids: Vec<String> = self.peers.iter().map(|e| e.key().clone()).collect();
        for id in peer_ids {
            self.kick_device(&id, err_code::SERVER_SHUTDOWN).await;
        }
        loop {
            let notified = self.tasks_drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if self.in_flight_tasks.load(Ordering::Acquire) == 0 {
                break;
            }
            let remaining: Vec<String> = self.peers.iter().map(|e| e.key().clone()).collect();
            for id in remaining {
                self.kick_device(&id, err_code::SERVER_SHUTDOWN).await;
            }
            notified.await;
        }
    }

    fn broadcast_user_device_status(&self, status: DeviceStatusBroadcast<'_>) {
        let Some(uid) = status.owner_user_id else {
            return;
        };
        let targets: Vec<(String, mpsc::Sender<SignalMsg>)> = self
            .peers
            .iter()
            .filter(|entry| {
                entry.key() != status.device_id && entry.value().owner_user_id == Some(uid)
            })
            .map(|entry| (entry.key().clone(), entry.value().tx.clone()))
            .collect();
        if targets.is_empty() {
            return;
        }
        let msg = SignalMsg::DeviceStatusChanged {
            device_id: status.device_id.to_string(),
            online: status.online,
            hostname: status.hostname.to_string(),
            alias: status.alias.to_string(),
            os: status.os.to_string(),
            app_version: status.app_version.to_string(),
            arch: status.arch.to_string(),
            cpu_model: status.cpu_model.to_string(),
            mac_address: status.mac_address.to_string(),
            total_memory_mb: status.total_memory_mb,
            os_version: status.os_version.to_string(),
            gpu_model: status.gpu_model.to_string(),
            allow_remote_assist: status.allow_remote_assist,
            allow_remote_control: status.allow_remote_control,
            wol_capable: status.wol_capable,
        };
        for (peer_id, peer_tx) in targets {
            Self::send_nonblocking(&peer_tx, &peer_id, msg.clone());
        }
    }

    fn broadcast_device_control_state(
        &self,
        owner_user_id: Option<Uuid>,
        device_id: &str,
        active_controllers: Vec<ActiveControllerSummary>,
    ) {
        let Some(uid) = owner_user_id else {
            return;
        };
        let targets: Vec<(String, mpsc::Sender<SignalMsg>)> = self
            .peers
            .iter()
            .filter(|entry| entry.key() != device_id && entry.value().owner_user_id == Some(uid))
            .map(|entry| (entry.key().clone(), entry.value().tx.clone()))
            .collect();
        if targets.is_empty() {
            return;
        }
        let msg = SignalMsg::DeviceControlStateChanged {
            device_id: device_id.to_string(),
            active_controllers,
        };
        for (peer_id, peer_tx) in targets {
            Self::send_nonblocking(&peer_tx, &peer_id, msg.clone());
        }
    }

    /// Synchronize updated device metadata/policy (`alias`, `allow_remote_assist`,
    /// `allow_remote_control`, `wol_capable`) from REST `PATCH /api/v1/me/devices/{id}` into in-memory
    /// active peer state, notify the target online device itself (preventing stale cache
    /// overwrite on reconnect), and broadcast `DeviceStatusChanged` to same-account online peers.
    pub async fn sync_device_policy_and_broadcast(&self, updated: &crate::store::DeviceRecord) {
        let norm = normalize_device_id(&updated.device_id);
        let wol_capable = updated.wol_capable();
        let effective_mac = updated.effective_mac_address();
        let self_tx = {
            let _guard = self.lock_device(&norm).await;
            if let Some(mut peer) = self.peers.get_mut(&norm) {
                peer.alias = updated.alias.clone();
                peer.allow_remote_assist = updated.allow_remote_assist;
                peer.allow_remote_control = updated.allow_remote_control;
                peer.wol_capable = wol_capable;
                peer.cpu_model = updated.cpu_model.clone();
                peer.mac_address = effective_mac.clone();
                peer.total_memory_mb = updated.total_memory_mb;
                peer.os_version = updated.os_version.clone();
                peer.gpu_model = updated.gpu_model.clone();
                Some(peer.tx.clone())
            } else {
                None
            }
        };
        let online = self_tx.is_some();
        if let Some(peer_tx) = self_tx {
            let msg = SignalMsg::DeviceStatusChanged {
                device_id: norm.clone(),
                online: true,
                hostname: updated.hostname.clone(),
                alias: updated.alias.clone(),
                os: updated.os.clone(),
                app_version: updated.app_version.clone(),
                arch: updated.arch.clone(),
                cpu_model: updated.cpu_model.clone(),
                mac_address: effective_mac.clone(),
                total_memory_mb: updated.total_memory_mb,
                os_version: updated.os_version.clone(),
                gpu_model: updated.gpu_model.clone(),
                allow_remote_assist: updated.allow_remote_assist,
                allow_remote_control: updated.allow_remote_control,
                wol_capable,
            };
            Self::send_nonblocking(&peer_tx, &norm, msg);
        }
        self.broadcast_user_device_status(DeviceStatusBroadcast {
            owner_user_id: updated.owner_user_id,
            device_id: &norm,
            online,
            hostname: &updated.hostname,
            alias: &updated.alias,
            os: &updated.os,
            app_version: &updated.app_version,
            arch: &updated.arch,
            cpu_model: &updated.cpu_model,
            mac_address: &effective_mac,
            total_memory_mb: updated.total_memory_mb,
            os_version: &updated.os_version,
            gpu_model: &updated.gpu_model,
            allow_remote_assist: updated.allow_remote_assist,
            allow_remote_control: updated.allow_remote_control,
            wol_capable,
        });
    }

    /// Kick an online device by signalling its per-connection cancellation handle,
    /// removing it from active peers, and clearing its online status from `EphemeralStore`.
    pub async fn kick_device(&self, device_id: &str, reason: &str) -> bool {
        let norm = normalize_device_id(device_id);
        let removed = {
            let _guard = self.lock_device(&norm).await;
            let removed = self.peers.remove(&norm);
            if let Some((_, ref peer)) = removed {
                peer.cancel.kick(reason);
            }
            if let Err(err) = self.ephemeral.remove_online(&norm).await {
                warn!(device_id = %norm, error = %err, "failed to remove kicked device from ephemeral store");
            }
            if let Some((_, ref peer)) = removed {
                if !peer.active_controllers.is_empty() {
                    self.broadcast_device_control_state(peer.owner_user_id, &norm, Vec::new());
                }
            }
            removed
        };
        if let Some((_, peer)) = removed {
            self.broadcast_user_device_status(DeviceStatusBroadcast {
                owner_user_id: peer.owner_user_id,
                device_id: &norm,
                online: false,
                hostname: &peer.hostname,
                alias: &peer.alias,
                os: &peer.os,
                app_version: &peer.app_version,
                arch: &peer.arch,
                cpu_model: &peer.cpu_model,
                mac_address: &peer.mac_address,
                total_memory_mb: peer.total_memory_mb,
                os_version: &peer.os_version,
                gpu_model: &peer.gpu_model,
                allow_remote_assist: peer.allow_remote_assist,
                allow_remote_control: peer.allow_remote_control,
                wol_capable: peer.wol_capable,
            });
            true
        } else {
            false
        }
    }

    /// Kick all currently online signaling connections belonging to `user_id`.
    pub async fn kick_user_devices(&self, user_id: Uuid, reason: &str) -> Vec<String> {
        let mut targets: Vec<String> = self
            .peers
            .iter()
            .filter(|entry| entry.value().owner_user_id == Some(user_id))
            .map(|entry| entry.key().clone())
            .collect();
        if let Some(ref auth_store) = self.auth_store {
            if let Ok(devs) = auth_store.list_user_devices(user_id).await {
                for dev in devs {
                    if !targets.contains(&dev.device_id) {
                        targets.push(dev.device_id);
                    }
                }
            }
        }
        let mut kicked = Vec::new();
        for did in targets {
            if self.kick_device(&did, reason).await {
                kicked.push(did);
            }
        }
        kicked
    }

    /// Serve UDP STUN-lite probes (`RCSP` -> `RCSA`) on a bound `UdpSocket` until `shutdown_all()`.
    pub async fn serve_udp_probe_on_socket(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
    ) -> std::io::Result<()> {
        self.serve_udp_probe_on_socket_inner(socket, None, true)
            .await
    }

    /// Serve UDP STUN-lite probes on a bound `UdpSocket`, exiting cleanly on either
    /// external `shutdown` signal or `shutdown_all()`.
    pub async fn serve_udp_probe_on_socket_with_shutdown(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
        shutdown: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        self.serve_udp_probe_on_socket_inner(socket, Some(shutdown), true)
            .await
    }

    /// Serve secondary UDP STUN-lite echo-only probes (`RCSP` -> `RCSA`) without updating `EphemeralStore`.
    pub async fn serve_udp_probe_alt_on_socket(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
    ) -> std::io::Result<()> {
        self.serve_udp_probe_on_socket_inner(socket, None, false)
            .await
    }

    /// Serve secondary UDP STUN-lite echo-only probes on a bound `UdpSocket`, exiting cleanly on
    /// either external `shutdown` signal or `shutdown_all()`.
    pub async fn serve_udp_probe_alt_on_socket_with_shutdown(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
        shutdown: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        self.serve_udp_probe_on_socket_inner(socket, Some(shutdown), false)
            .await
    }

    async fn serve_udp_probe_on_socket_inner(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
        mut shutdown: Option<watch::Receiver<bool>>,
        persist_endpoints: bool,
    ) -> std::io::Result<()> {
        let server_shutdown = self.shutdown.cancelled();
        tokio::pin!(server_shutdown);
        let external_shutdown = wait_external_shutdown(&mut shutdown);
        tokio::pin!(external_shutdown);

        // Bounded background queue for `set_public_udp` updates so Redis/backend latency
        // never head-of-line blocks UDP `RCSA` responses. Disabled on the secondary alt port.
        let (udp_update_tx, worker_handle) = if persist_endpoints {
            let (tx, mut rx) = mpsc::channel::<(String, SocketAddr)>(UDP_EPHEMERAL_QUEUE_CAPACITY);
            let worker_hub = Arc::clone(&self);
            let worker_guard = SignalTaskGuard::enter(Arc::clone(&self));
            let handle = tokio::spawn(async move {
                let _guard = worker_guard;
                let worker_shutdown = worker_hub.shutdown.cancelled();
                tokio::pin!(worker_shutdown);
                loop {
                    let next = tokio::select! {
                        biased;
                        _ = &mut worker_shutdown => break,
                        item = rx.recv() => match item {
                            Some(pair) => pair,
                            None => break,
                        },
                    };
                    let (device_id, canonical_src) = next;
                    match tokio::time::timeout(
                        UDP_EPHEMERAL_UPDATE_TIMEOUT,
                        worker_hub.ephemeral.set_public_udp(
                            &device_id,
                            canonical_src,
                            worker_hub.config.udp_ttl,
                        ),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            warn!(
                                %device_id,
                                %canonical_src,
                                error = %err,
                                "failed to store public UDP endpoint"
                            );
                        }
                        Err(_) => {
                            warn!(
                                %device_id,
                                %canonical_src,
                                "timed out storing public UDP endpoint"
                            );
                        }
                    }
                }
            });
            (Some(tx), Some(handle))
        } else {
            (None, None)
        };

        let mut buf = [0u8; 256];
        loop {
            if self.shutdown.is_cancelled() {
                break;
            }
            let received = tokio::select! {
                biased;
                _ = &mut server_shutdown => break,
                _ = &mut external_shutdown => break,
                res = socket.recv_from(&mut buf) => res,
            };

            let (n, src_addr) = match received {
                Ok(pair) => pair,
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    debug!(error = %err, "transient UDP recv_from error; continuing");
                    continue;
                }
                Err(err) => {
                    warn!(error = %err, "UDP recv_from error; backing off 50ms");
                    tokio::select! {
                        biased;
                        _ = &mut server_shutdown => break,
                        _ = &mut external_shutdown => break,
                        _ = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
                    }
                    continue;
                }
            };

            let canonical_src = canonical_socket_addr(src_addr);

            // Per-source-IP UDP rate limit mitigates reflection/amplification & floods.
            if !check_sliding_window_rate_limit(
                &self.udp_rate_limits,
                canonical_src.ip(),
                self.config.udp_rate_limit_max,
                self.config.udp_rate_limit_window,
            ) {
                debug!(%canonical_src, "dropping rate-limited UDP RCSP probe");
                continue;
            }

            let req = match DecodedUdpProbe::decode(&buf[..n]) {
                Ok(req) => req,
                Err(err) => {
                    debug!(%canonical_src, bytes = n, error = %err, "dropping malformed UDP RCSP packet");
                    continue;
                }
            };

            let req_device_id = req.device_id();
            if req_device_id != ANONYMOUS_DEVICE_ID && !is_valid_device_id(req_device_id) {
                debug!(
                    %canonical_src,
                    device_id = %req_device_id,
                    "dropping UDP RCSP packet with invalid device_id"
                );
                continue;
            }

            // Reply `RCSA` BEFORE updating ephemeral storage so backend latency never
            // delays STUN-lite echo. Send back to original `src_addr` for dual-stack sockets.
            let resp = UdpProbeResponse {
                observed_addr: canonical_src,
                nonce: req.nonce(),
            }
            .encode();

            if let Err(err) = socket.send_to(&resp, src_addr).await {
                debug!(%src_addr, error = %err, "failed to send UDP RCSA reply");
            }

            // Secondary alt port is echo-only and must never overwrite primary EphemeralStore state.
            let Some(ref tx) = udp_update_tx else {
                continue;
            };

            // Persist public UDP endpoint only for authenticated online devices:
            // - RCSP v1: matching canonical TCP remote IP
            // - RCSP v2: constant-time verification of the 16B udp_probe_token (supports multi-egress / dual-stack)
            if req_device_id != ANONYMOUS_DEVICE_ID {
                let authorized = match &req {
                    DecodedUdpProbe::V1(v1) => self.peers.get(&v1.device_id).is_some_and(|peer| {
                        canonical_ip(peer.remote_addr.ip()) == canonical_src.ip()
                    }),
                    DecodedUdpProbe::V2(v2) => self.peers.get(&v2.device_id).is_some_and(|peer| {
                        peer.udp_probe_token
                            .is_some_and(|expected| constant_time_eq_bytes(&expected, &v2.token))
                    }),
                };
                if authorized {
                    if let Err(err) = tx.try_send((req_device_id.to_string(), canonical_src)) {
                        debug!(%canonical_src, error = %err, "dropping public UDP update because background queue is full/closed");
                    }
                } else {
                    debug!(
                        device_id = %req_device_id,
                        %canonical_src,
                        "ignoring UDP endpoint update for offline device, mismatched IP, or invalid probe token"
                    );
                }
            }
        }

        drop(udp_update_tx);
        if let Some(handle) = worker_handle {
            let _ = tokio::time::timeout(
                UDP_EPHEMERAL_UPDATE_TIMEOUT + Duration::from_millis(100),
                handle,
            )
            .await;
        }
        Ok(())
    }

    /// Bind a UDP socket on `addr` and serve UDP STUN-lite probes.
    pub async fn serve_udp_probe(self: Arc<Self>, addr: SocketAddr) -> std::io::Result<()> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!(%addr, "UDP STUN-lite probe listener started");
        self.serve_udp_probe_on_socket(socket).await
    }

    /// Serve native TCP framed signaling connections on a bound `TcpListener` until `shutdown_all()`.
    pub async fn serve_tcp_signaling_on_listener(
        self: Arc<Self>,
        listener: TcpListener,
    ) -> std::io::Result<()> {
        self.serve_signaling_on_listener_inner(listener, None, None)
            .await
    }

    /// Serve native TCP framed signaling connections on a bound `TcpListener`, exiting cleanly
    /// on either external `shutdown` signal or `shutdown_all()`.
    pub async fn serve_tcp_signaling_on_listener_with_shutdown(
        self: Arc<Self>,
        listener: TcpListener,
        shutdown: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        self.serve_signaling_on_listener_inner(listener, None, Some(shutdown))
            .await
    }

    /// Serve TLS 1.3 framed signaling connections on a bound `TcpListener` until `shutdown_all()`.
    pub async fn serve_tls_signaling_on_listener(
        self: Arc<Self>,
        listener: TcpListener,
        tls_config: Arc<rustls::ServerConfig>,
    ) -> std::io::Result<()> {
        self.serve_signaling_on_listener_inner(listener, Some(TlsAcceptor::from(tls_config)), None)
            .await
    }

    /// Serve TLS 1.3 framed signaling connections on a bound `TcpListener`, exiting cleanly
    /// on either external `shutdown` signal or `shutdown_all()`.
    pub async fn serve_tls_signaling_on_listener_with_shutdown(
        self: Arc<Self>,
        listener: TcpListener,
        tls_config: Arc<rustls::ServerConfig>,
        shutdown: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        self.serve_signaling_on_listener_inner(
            listener,
            Some(TlsAcceptor::from(tls_config)),
            Some(shutdown),
        )
        .await
    }

    async fn serve_signaling_on_listener_inner(
        self: Arc<Self>,
        listener: TcpListener,
        tls_acceptor: Option<TlsAcceptor>,
        mut shutdown: Option<watch::Receiver<bool>>,
    ) -> std::io::Result<()> {
        let server_shutdown = self.shutdown.cancelled();
        tokio::pin!(server_shutdown);
        let external_shutdown = wait_external_shutdown(&mut shutdown);
        tokio::pin!(external_shutdown);

        loop {
            if self.shutdown.is_cancelled() {
                return Ok(());
            }

            // Acquire a connection permit before accept() to bound concurrent TCP connections.
            let permit = tokio::select! {
                biased;
                _ = &mut server_shutdown => return Ok(()),
                _ = &mut external_shutdown => return Ok(()),
                res = self.conn_semaphore.clone().acquire_owned() => match res {
                    Ok(permit) => permit,
                    Err(_) => return Ok(()),
                },
            };

            let accepted = tokio::select! {
                biased;
                _ = &mut server_shutdown => return Ok(()),
                _ = &mut external_shutdown => return Ok(()),
                res = listener.accept() => res,
            };

            let (stream, peer_addr) = match accepted {
                Ok(pair) => pair,
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    drop(permit);
                    continue;
                }
                Err(err) => {
                    drop(permit);
                    warn!(error = %err, "TCP signaling accept error; backing off 50ms");
                    tokio::select! {
                        biased;
                        _ = &mut server_shutdown => return Ok(()),
                        _ = &mut external_shutdown => return Ok(()),
                        _ = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
                    }
                    continue;
                }
            };

            let hub = Arc::clone(&self);
            let task_guard = SignalTaskGuard::enter(Arc::clone(&self));
            let tls_acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                let _task_guard = task_guard;
                tune_signal_socket(&stream, peer_addr);
                if let Some(acceptor) = tls_acceptor {
                    let tls_res = tokio::select! {
                        biased;
                        _ = hub.shutdown.cancelled() => return,
                        res = tokio::time::timeout(hub.config.handshake_timeout, acceptor.accept(stream)) => res,
                    };
                    match tls_res {
                        Ok(Ok(tls_stream)) => {
                            hub.handle_stream_connection_inner(tls_stream, peer_addr, Some(permit))
                                .await;
                        }
                        Ok(Err(err)) => {
                            debug!(%peer_addr, error = %err, "signaling TLS handshake failed");
                        }
                        Err(_) => {
                            debug!(%peer_addr, "signaling TLS handshake timed out");
                        }
                    }
                } else {
                    hub.handle_stream_connection_inner(stream, peer_addr, Some(permit))
                        .await;
                }
            });
        }
    }

    /// Bind a TCP listener on `addr` and serve native TCP framed signaling (NO WebSocket).
    pub async fn serve_tcp_signaling(self: Arc<Self>, addr: SocketAddr) -> std::io::Result<()> {
        let listener = crate::bind_tcp_listener(addr, crate::DEFAULT_TCP_LISTEN_BACKLOG)?;
        info!(%addr, "native TCP framed signaling listener started");
        self.serve_tcp_signaling_on_listener(listener).await
    }

    pub async fn handle_tcp_connection(
        self: Arc<Self>,
        stream: TcpStream,
        remote_addr: SocketAddr,
    ) {
        let _task_guard = SignalTaskGuard::enter(Arc::clone(&self));
        tune_signal_socket(&stream, remote_addr);
        self.handle_stream_connection_inner(stream, remote_addr, None)
            .await;
    }

    async fn authenticate_signal_token(
        &self,
        access_token: Option<&str>,
    ) -> Result<Option<Uuid>, (&'static str, String)> {
        let token = access_token.map(str::trim).filter(|s| !s.is_empty());
        let Some(token) = token else {
            if self.config.require_auth {
                return Err((err_code::UNAUTHORIZED, "access_token is required".into()));
            }
            return Ok(None);
        };

        let (Some(auth_authority), Some(auth_store)) =
            (self.auth_authority.as_ref(), self.auth_store.as_ref())
        else {
            if self.config.require_auth {
                return Err((
                    err_code::SERVER_MISCONFIGURED,
                    "signaling auth authority is not configured".into(),
                ));
            }
            return Ok(None);
        };

        let claims = match auth_authority.verify_access_token(token) {
            Ok(c) => c,
            Err(AuthError::TokenExpired) => {
                return Err((err_code::TOKEN_EXPIRED, "access token expired".into()));
            }
            Err(_) => {
                return Err((err_code::UNAUTHORIZED, "invalid access token".into()));
            }
        };

        if claims.pwd_change_only {
            return Err((
                err_code::PASSWORD_CHANGE_REQUIRED,
                "password change is required before connecting signaling".into(),
            ));
        }

        let user = match auth_store.get_user_by_id(claims.sub).await {
            Ok(Some(u)) => u,
            Ok(None) => return Err((err_code::UNAUTHORIZED, "user not found".into())),
            Err(err) => return Err((err_code::REGISTER_FAILED, err.to_string())),
        };

        if user.status != STATUS_ACTIVE {
            return Err((
                err_code::ACCOUNT_DISABLED,
                "user account is disabled".into(),
            ));
        }
        if user.token_version != claims.ver {
            return Err((
                err_code::TOKEN_REVOKED,
                "access token has been revoked".into(),
            ));
        }
        if user.must_change_password {
            return Err((
                err_code::PASSWORD_CHANGE_REQUIRED,
                "password change is required before connecting signaling".into(),
            ));
        }
        match auth_store.get_user_session(claims.sid).await {
            Ok(Some(sess)) => {
                if sess.revoked_at.is_some() {
                    return Err((err_code::TOKEN_REVOKED, "session has been revoked".into()));
                }
            }
            Ok(None) => {
                return Err((
                    err_code::TOKEN_REVOKED,
                    "session not found or expired".into(),
                ));
            }
            Err(err) => {
                return Err((err_code::SERVICE_UNAVAILABLE, err.to_string()));
            }
        }

        Ok(Some(user.id))
    }

    async fn handle_stream_connection_inner<S>(
        self: Arc<Self>,
        stream: S,
        remote_addr: SocketAddr,
        _permit: Option<OwnedSemaphorePermit>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let remote_addr = canonical_socket_addr(remote_addr);

        if self.shutdown.is_cancelled() {
            return;
        }

        let (mut reader, mut writer) = tokio::io::split(stream);

        // Step 1: First frame MUST be `register` within handshake_timeout.
        let first_frame = tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => return,
            res = tokio::time::timeout(
                self.config.handshake_timeout,
                read_signal_frame(&mut reader),
            ) => match res {
                Ok(Ok(Some(msg))) => msg,
                Ok(Ok(None)) => return,
                Ok(Err(err)) => {
                    write_frame_with_timeout(
                        &mut writer,
                        &SignalMsg::Error {
                            code: err_code::INVALID_FRAME.into(),
                            message: err.to_string(),
                        },
                        self.config.write_timeout,
                    )
                    .await;
                    return;
                }
                Err(_) => {
                    write_frame_with_timeout(
                        &mut writer,
                        &SignalMsg::Error {
                            code: err_code::HANDSHAKE_TIMEOUT.into(),
                            message: "register frame timed out".into(),
                        },
                        self.config.write_timeout,
                    )
                    .await;
                    return;
                }
            },
        };

        let (
            claimed_id,
            register_input,
            initial_lan_addrs,
            access_token,
            device_pubkey,
            allow_remote_assist_opt,
            allow_remote_control_opt,
            mac_addr_opt,
            wol_enabled_opt,
            nat_type_opt,
            nat_port_delta_opt,
            nat_port_range_opt,
            rcp2_v2,
        ) = match first_frame {
            SignalMsg::Register {
                device_id,
                device_key,
                hostname,
                os,
                app_version,
                arch,
                cpu_model,
                mac_address,
                total_memory_mb,
                os_version,
                gpu_model,
                device_group,
                lan_addrs,
                access_token,
                device_pubkey,
                allow_remote_assist,
                allow_remote_control,
                mac_addr,
                wol_enabled,
                nat_type,
                nat_port_delta,
                nat_port_range,
                rcp2_v2,
            } => {
                let norm_mac_address = match validate_register_fields(RegisterMetadataFields {
                    hostname: &hostname,
                    os: &os,
                    app_version: &app_version,
                    arch: &arch,
                    cpu_model: &cpu_model,
                    mac_address: &mac_address,
                    total_memory_mb,
                    os_version: &os_version,
                    gpu_model: &gpu_model,
                    device_group: &device_group,
                    lan_addrs: &lan_addrs,
                }) {
                    Ok(mac) => mac,
                    Err(reason) => {
                        write_frame_with_timeout(
                            &mut writer,
                            &SignalMsg::Error {
                                code: err_code::INVALID_PAYLOAD.into(),
                                message: reason,
                            },
                            self.config.write_timeout,
                        )
                        .await;
                        return;
                    }
                };
                if let Some(ref pk) = device_pubkey {
                    if let Err(reason) =
                        validate_metadata_field(pk, MAX_DEVICE_PUBKEY_LEN, "device_pubkey")
                    {
                        write_frame_with_timeout(
                            &mut writer,
                            &SignalMsg::Error {
                                code: err_code::INVALID_PAYLOAD.into(),
                                message: reason,
                            },
                            self.config.write_timeout,
                        )
                        .await;
                        return;
                    }
                }
                let normalized_mac = match validate_optional_signal_mac_addr(mac_addr.as_deref()) {
                    Ok(mac) => mac,
                    Err(reason) => {
                        write_frame_with_timeout(
                            &mut writer,
                            &SignalMsg::Error {
                                code: err_code::INVALID_INPUT.into(),
                                message: reason.into(),
                            },
                            self.config.write_timeout,
                        )
                        .await;
                        return;
                    }
                };
                (
                    device_id,
                    RegisterInput {
                        device_key,
                        hostname,
                        os,
                        app_version,
                        arch,
                        cpu_model,
                        mac_address: norm_mac_address,
                        total_memory_mb,
                        os_version,
                        gpu_model,
                        device_group,
                        ..Default::default()
                    },
                    lan_addrs,
                    access_token,
                    device_pubkey,
                    allow_remote_assist,
                    allow_remote_control,
                    normalized_mac,
                    wol_enabled,
                    normalize_nat_type(nat_type.as_deref()),
                    normalize_nat_port_delta(nat_port_delta),
                    normalize_nat_port_range(nat_port_range),
                    rcp2_v2,
                )
            }
            _ => {
                write_frame_with_timeout(
                    &mut writer,
                    &SignalMsg::Error {
                        code: err_code::EXPECTED_REGISTER.into(),
                        message: "first signaling frame must be register".into(),
                    },
                    self.config.write_timeout,
                )
                .await;
                return;
            }
        };

        let authed_user_id = match self
            .authenticate_signal_token(access_token.as_deref())
            .await
        {
            Ok(uid) => uid,
            Err((code, message)) => {
                write_frame_with_timeout(
                    &mut writer,
                    &SignalMsg::Error {
                        code: code.into(),
                        message,
                    },
                    self.config.write_timeout,
                )
                .await;
                return;
            }
        };

        // Step 2: If the client claims an existing `device_id`, verify ownership against
        // `device_key` BEFORE calling `register_or_get` so mismatched or unknown keys cannot
        // insert orphan device rows or mutate another device's metadata.
        let claimed = claimed_id
            .as_deref()
            .map(normalize_device_id)
            .filter(|id| !id.is_empty());

        if let Some(ref claimed) = claimed {
            match self.device_store.get_by_id(claimed).await {
                Ok(Some(existing)) if existing.device_key == register_input.device_key.trim() => {
                    if existing.disabled {
                        write_frame_with_timeout(
                            &mut writer,
                            &SignalMsg::Error {
                                code: err_code::DEVICE_DISABLED.into(),
                                message: format!("device {} is disabled", existing.device_id),
                            },
                            self.config.write_timeout,
                        )
                        .await;
                        return;
                    }
                }
                Ok(_) => {
                    write_frame_with_timeout(
                        &mut writer,
                        &SignalMsg::Error {
                            code: err_code::DEVICE_ID_MISMATCH.into(),
                            message: "provided device_id does not match device_key".into(),
                        },
                        self.config.write_timeout,
                    )
                    .await;
                    return;
                }
                Err(err) => {
                    write_frame_with_timeout(
                        &mut writer,
                        &SignalMsg::Error {
                            code: err_code::REGISTER_FAILED.into(),
                            message: err.to_string(),
                        },
                        self.config.write_timeout,
                    )
                    .await;
                    return;
                }
            }
        }

        let record = match self.device_store.register_or_get(register_input).await {
            Ok(rec) => rec,
            Err(StoreError::DeviceDisabled(id)) => {
                write_frame_with_timeout(
                    &mut writer,
                    &SignalMsg::Error {
                        code: err_code::DEVICE_DISABLED.into(),
                        message: format!("device {id} is disabled"),
                    },
                    self.config.write_timeout,
                )
                .await;
                return;
            }
            Err(err) => {
                write_frame_with_timeout(
                    &mut writer,
                    &SignalMsg::Error {
                        code: err_code::REGISTER_FAILED.into(),
                        message: err.to_string(),
                    },
                    self.config.write_timeout,
                )
                .await;
                return;
            }
        };

        if let Some(ref claimed) = claimed {
            if claimed != &record.device_id {
                write_frame_with_timeout(
                    &mut writer,
                    &SignalMsg::Error {
                        code: err_code::DEVICE_ID_MISMATCH.into(),
                        message: "provided device_id does not match device_key".into(),
                    },
                    self.config.write_timeout,
                )
                .await;
                return;
            }
        }

        let device_id = record.device_id.clone();

        if let Some(uid) = authed_user_id {
            let clean_pubkey = device_pubkey
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let prev_owner = match self
                .device_store
                .bind_device_to_user_with_prev(&device_id, uid, None, clean_pubkey)
                .await
            {
                Ok(Some((_, prev_owner))) => prev_owner,
                Ok(None) => {
                    write_frame_with_timeout(
                        &mut writer,
                        &SignalMsg::Error {
                            code: err_code::REGISTER_FAILED.into(),
                            message: format!("device {device_id} disappeared during bind"),
                        },
                        self.config.write_timeout,
                    )
                    .await;
                    return;
                }
                Err(err) => {
                    write_frame_with_timeout(
                        &mut writer,
                        &SignalMsg::Error {
                            code: err_code::REGISTER_FAILED.into(),
                            message: err.to_string(),
                        },
                        self.config.write_timeout,
                    )
                    .await;
                    return;
                }
            };
            if let Some(prev_uid) = prev_owner {
                if prev_uid != uid {
                    if let Some(ref auth_store) = self.auth_store {
                        if let Ok(certs) = auth_store
                            .list_device_certs(Some(prev_uid), Some(&device_id))
                            .await
                        {
                            for cert in certs {
                                if cert.revoked_at.is_none() {
                                    if let Ok(Some(revoked)) = auth_store
                                        .revoke_cert_by_serial(
                                            &cert.serial_hex,
                                            Some("device_rebound"),
                                        )
                                        .await
                                    {
                                        let rem = (revoked.expires_at - Utc::now())
                                            .to_std()
                                            .unwrap_or_else(|_| Duration::from_secs(1));
                                        let _ = self
                                            .ephemeral
                                            .revoke_cert_serial(&revoked.serial_hex, rem)
                                            .await;
                                    }
                                }
                            }
                        }
                        let _ = auth_store
                            .revoke_device_sessions(prev_uid, &device_id)
                            .await;
                    }
                }
            }
        }

        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = mpsc::channel::<SignalMsg>(self.config.channel_capacity);
        let cancel = PeerCancel::new();

        // Step 3 (M4): Serialize disabled re-check + policy persistence + peers.insert +
        // ephemeral.set_online under the per-device stripe lock so concurrent admin disable/kick,
        // REST PATCH, or reconnect transitions can never interleave inconsistently.
        let (
            peer_owner,
            peer_hostname,
            peer_alias,
            peer_os,
            peer_ver,
            peer_arch,
            peer_cpu_model,
            peer_mac_address,
            peer_total_memory_mb,
            peer_os_version,
            peer_gpu_model,
            peer_assist,
            peer_remote_control,
            peer_wol_capable,
        ) = {
            let _guard = self.lock_device(&device_id).await;
            if self.shutdown.is_cancelled() {
                return;
            }
            if authed_user_id.is_some() {
                if let Err((code, message)) = self
                    .authenticate_signal_token(access_token.as_deref())
                    .await
                {
                    drop(_guard);
                    write_frame_with_timeout(
                        &mut writer,
                        &SignalMsg::Error {
                            code: code.into(),
                            message,
                        },
                        self.config.write_timeout,
                    )
                    .await;
                    return;
                }
            }
            let mut latest = match self.device_store.get_by_id(&device_id).await {
                Ok(Some(latest)) if !latest.disabled => latest,
                Ok(_) => {
                    drop(_guard);
                    write_frame_with_timeout(
                        &mut writer,
                        &SignalMsg::Error {
                            code: err_code::DEVICE_DISABLED.into(),
                            message: format!("device {device_id} is disabled"),
                        },
                        self.config.write_timeout,
                    )
                    .await;
                    return;
                }
                Err(err) => {
                    drop(_guard);
                    write_frame_with_timeout(
                        &mut writer,
                        &SignalMsg::Error {
                            code: err_code::REGISTER_FAILED.into(),
                            message: err.to_string(),
                        },
                        self.config.write_timeout,
                    )
                    .await;
                    return;
                }
            };
            if authed_user_id.is_some() && latest.owner_user_id != authed_user_id {
                drop(_guard);
                write_frame_with_timeout(
                    &mut writer,
                    &SignalMsg::Error {
                        code: err_code::DEVICE_UNBOUND.into(),
                        message: format!("device {device_id} ownership changed"),
                    },
                    self.config.write_timeout,
                )
                .await;
                return;
            }

            // Persist optional Register policy flags strictly inside the per-device lock.
            // Anonymous connections (`authed_user_id.is_none()`) may ONLY update policy on
            // unbound devices (`latest.owner_user_id.is_none()`).
            let can_update_policy = authed_user_id.is_some() || latest.owner_user_id.is_none();
            let mut policy_write_attempted = false;
            if can_update_policy {
                if let Some(allow) = allow_remote_assist_opt {
                    policy_write_attempted = true;
                    match self
                        .device_store
                        .set_device_allow_remote_assist(&device_id, authed_user_id, allow)
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            warn!(
                                %device_id,
                                "register allow_remote_assist update affected 0 rows"
                            );
                        }
                        Err(err) => {
                            warn!(
                                %device_id,
                                error = %err,
                                "failed to persist register allow_remote_assist"
                            );
                        }
                    }
                }
                if let Some(allow_rc) = allow_remote_control_opt {
                    policy_write_attempted = true;
                    match self
                        .device_store
                        .set_device_allow_remote_control(&device_id, authed_user_id, allow_rc)
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            warn!(
                                %device_id,
                                "register allow_remote_control update affected 0 rows"
                            );
                        }
                        Err(err) => {
                            warn!(
                                %device_id,
                                error = %err,
                                "failed to persist register allow_remote_control"
                            );
                        }
                    }
                }
                let public_ip_str = canonical_ip(remote_addr.ip()).to_string();
                let reg_lan_slice =
                    (!initial_lan_addrs.is_empty()).then_some(initial_lan_addrs.as_slice());
                if mac_addr_opt.is_some()
                    || wol_enabled_opt.is_some()
                    || reg_lan_slice.is_some()
                    || !public_ip_str.is_empty()
                {
                    if mac_addr_opt.is_some() || wol_enabled_opt.is_some() {
                        policy_write_attempted = true;
                    }
                    match self
                        .device_store
                        .update_device_wol_state(
                            &device_id,
                            authed_user_id,
                            mac_addr_opt.as_deref(),
                            wol_enabled_opt,
                            reg_lan_slice,
                            Some(&public_ip_str),
                        )
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            warn!(
                                %device_id,
                                "register WoL/network metadata update affected 0 rows"
                            );
                        }
                        Err(err) => {
                            warn!(
                                %device_id,
                                error = %err,
                                "failed to persist register WoL/network metadata"
                            );
                        }
                    }
                }
            } else if allow_remote_assist_opt.is_some()
                || allow_remote_control_opt.is_some()
                || mac_addr_opt.is_some()
                || wol_enabled_opt.is_some()
            {
                warn!(
                    %device_id,
                    "ignoring policy/WoL flags from unauthenticated register on bound device"
                );
            }

            if policy_write_attempted {
                latest = match self.device_store.get_by_id(&device_id).await {
                    Ok(Some(rec)) if !rec.disabled => rec,
                    Ok(_) => {
                        drop(_guard);
                        write_frame_with_timeout(
                            &mut writer,
                            &SignalMsg::Error {
                                code: err_code::DEVICE_DISABLED.into(),
                                message: format!("device {device_id} is disabled"),
                            },
                            self.config.write_timeout,
                        )
                        .await;
                        return;
                    }
                    Err(err) => {
                        drop(_guard);
                        write_frame_with_timeout(
                            &mut writer,
                            &SignalMsg::Error {
                                code: err_code::REGISTER_FAILED.into(),
                                message: err.to_string(),
                            },
                            self.config.write_timeout,
                        )
                        .await;
                        return;
                    }
                };
            }

            let effective_owner = authed_user_id;
            let effective_pubkey = if !latest.device_pubkey.is_empty() {
                latest.device_pubkey.clone()
            } else {
                device_pubkey.unwrap_or_default()
            };
            let effective_assist = latest.allow_remote_assist;
            let effective_remote_control = latest.allow_remote_control;
            let effective_wol_capable = latest.wol_capable();
            let effective_mac_address = latest.effective_mac_address();
            let mut udp_probe_token = [0u8; UDP_PROBE_TOKEN_LEN];
            OsRng.fill_bytes(&mut udp_probe_token);
            let udp_probe_token_hex = hex::encode(udp_probe_token);

            let replaced_owner_to_clear_ctrl = if let Some(old_peer) = self.peers.insert(
                device_id.clone(),
                ActivePeer {
                    conn_id,
                    tx: tx.clone(),
                    cancel: cancel.clone(),
                    lan_addrs: initial_lan_addrs,
                    remote_addr,
                    connected_at: Utc::now(),
                    owner_user_id: effective_owner,
                    device_pubkey: effective_pubkey,
                    allow_remote_assist: effective_assist,
                    allow_remote_control: effective_remote_control,
                    wol_capable: effective_wol_capable,
                    hostname: latest.hostname.clone(),
                    alias: latest.alias.clone(),
                    os: latest.os.clone(),
                    app_version: latest.app_version.clone(),
                    arch: latest.arch.clone(),
                    cpu_model: latest.cpu_model.clone(),
                    mac_address: effective_mac_address.clone(),
                    total_memory_mb: latest.total_memory_mb,
                    os_version: latest.os_version.clone(),
                    gpu_model: latest.gpu_model.clone(),
                    udp_probe_token: Some(udp_probe_token),
                    nat_type: nat_type_opt,
                    nat_port_delta: nat_port_delta_opt,
                    nat_port_range: nat_port_range_opt,
                    smoothed_rtt_ms: None,
                    rcp2_v2,
                    active_controllers: Vec::new(),
                },
            ) {
                old_peer.cancel.kick(err_code::REPLACED_BY_NEW_CONNECTION);
                if !old_peer.active_controllers.is_empty() {
                    old_peer.owner_user_id
                } else {
                    None
                }
            } else {
                None
            };

            if let Err(err) = self
                .ephemeral
                .set_online(&device_id, self.config.online_ttl)
                .await
            {
                warn!(%device_id, error = %err, "failed to set device online in ephemeral store");
            }

            // Enqueue `registered` response while still serialized before spawning writer.
            let _ = tx.try_send(SignalMsg::Registered {
                device_id: device_id.clone(),
                formatted_id: format_device_id(&device_id),
                server_time: Utc::now(),
                udp_probe_addr: self.config.public_udp_probe_addr.clone(),
                udp_probe_alt_addr: self.config.public_udp_probe_alt_addr.clone(),
                udp_probe_alt_ip_addr: self.config.public_udp_probe_alt_ip_addr.clone(),
                udp_probe_token: Some(udp_probe_token_hex),
                relay_addr: self.config.public_relay_addr.clone(),
            });

            if let Some(prev_owner) = replaced_owner_to_clear_ctrl {
                self.broadcast_device_control_state(Some(prev_owner), &device_id, Vec::new());
            }

            (
                effective_owner,
                latest.hostname,
                latest.alias,
                latest.os,
                latest.app_version,
                latest.arch,
                latest.cpu_model,
                effective_mac_address,
                latest.total_memory_mb,
                latest.os_version,
                latest.gpu_model,
                effective_assist,
                effective_remote_control,
                effective_wol_capable,
            )
        };

        let connected_instant = Instant::now();
        info!(
            %device_id,
            %remote_addr,
            conn_id,
            owner_user_id = ?peer_owner,
            "signaling peer registered"
        );

        self.broadcast_user_device_status(DeviceStatusBroadcast {
            owner_user_id: peer_owner,
            device_id: &device_id,
            online: true,
            hostname: &peer_hostname,
            alias: &peer_alias,
            os: &peer_os,
            app_version: &peer_ver,
            arch: &peer_arch,
            cpu_model: &peer_cpu_model,
            mac_address: &peer_mac_address,
            total_memory_mb: peer_total_memory_mb,
            os_version: &peer_os_version,
            gpu_model: &peer_gpu_model,
            allow_remote_assist: peer_assist,
            allow_remote_control: peer_remote_control,
            wol_capable: peer_wol_capable,
        });

        // Writer task drains bounded channel with per-frame write timeout and immediate kick wakeup.
        let (writer_done_tx, mut writer_done_rx) = oneshot::channel::<()>();
        let mut writer_cancel_rx = cancel.subscribe();
        let write_timeout = self.config.write_timeout;
        let writer_device_id = device_id.clone();
        let mut writer_handle = tokio::spawn(async move {
            let mut kicked_reason: Option<String> = None;

            loop {
                let next_msg = tokio::select! {
                    biased;
                    reason = wait_kicked(&mut writer_cancel_rx) => {
                        kicked_reason = Some(reason);
                        break;
                    }
                    msg = rx.recv() => match msg {
                        Some(msg) => msg,
                        None => break,
                    },
                };

                let is_kicked = matches!(next_msg, SignalMsg::Kicked { .. });

                // H5: Encode before writing and skip unencodable/oversized frames instead of
                // tearing down the victim peer's connection.
                let encoded = match encode_signal_frame(&next_msg) {
                    Ok(frame) => frame,
                    Err(err @ (SignalError::FrameTooLarge(_) | SignalError::Json(_))) => {
                        warn!(
                            device_id = %writer_device_id,
                            error = %err,
                            "skipping oversized or unencodable outbound signaling frame"
                        );
                        continue;
                    }
                    Err(err) => {
                        warn!(
                            device_id = %writer_device_id,
                            error = %err,
                            "skipping invalid outbound signaling frame"
                        );
                        continue;
                    }
                };

                let write_outcome = tokio::select! {
                    biased;
                    _ = wait_kicked(&mut writer_cancel_rx) => {
                        // Cancelled while blocked mid-write on a stalled socket; abort immediately.
                        break;
                    }
                    res = tokio::time::timeout(write_timeout, async {
                        writer.write_all(&encoded).await?;
                        writer.flush().await
                    }) => res,
                };

                match write_outcome {
                    Ok(Ok(())) => {
                        if is_kicked {
                            break;
                        }
                    }
                    Ok(Err(_)) | Err(_) => {
                        break;
                    }
                }
            }

            if let Some(reason) = kicked_reason {
                write_frame_with_timeout(&mut writer, &SignalMsg::Kicked { reason }, write_timeout)
                    .await;
            }

            let _ = writer.shutdown().await;
            let _ = writer_done_tx.send(());
        });

        // Reader loop processes incoming framed messages until disconnect, kick, shutdown, or idle timeout.
        let mut reader_cancel_rx = cancel.subscribe();
        let mut abort_writer_immediately = false;
        let disconnect_reason: String;
        loop {
            if cancel.is_kicked() {
                disconnect_reason = cancel
                    .kick_reason()
                    .map(|r| format!("kicked:{r}"))
                    .unwrap_or_else(|| "kicked".to_string());
                break;
            }
            if self.shutdown.is_cancelled() {
                disconnect_reason = "server_shutdown".to_string();
                break;
            }
            let next = tokio::select! {
                biased;
                reason = wait_kicked(&mut reader_cancel_rx) => {
                    disconnect_reason = format!("kicked:{reason}");
                    break;
                }
                _ = self.shutdown.cancelled() => {
                    disconnect_reason = "server_shutdown".to_string();
                    cancel.kick(err_code::SERVER_SHUTDOWN);
                    break;
                }
                _ = &mut writer_done_rx => {
                    disconnect_reason = "writer_closed".to_string();
                    break;
                }
                res = tokio::time::timeout(
                    self.config.read_idle_timeout,
                    read_signal_frame(&mut reader),
                ) => res,
            };

            match next {
                Ok(Ok(Some(msg))) => {
                    if !self.is_active_conn(&device_id, conn_id, &cancel) {
                        disconnect_reason = cancel
                            .kick_reason()
                            .map(|r| format!("kicked:{r}"))
                            .unwrap_or_else(|| "replaced".to_string());
                        break;
                    }
                    self.handle_peer_message(&device_id, conn_id, &cancel, &tx, msg)
                        .await;
                }
                Ok(Ok(None)) => {
                    disconnect_reason = "eof".to_string();
                    break;
                }
                Ok(Err(err)) => {
                    disconnect_reason = format!("read_error:{err}");
                    debug!(%device_id, %remote_addr, error = %err, "signaling read error");
                    let _ = tx.try_send(SignalMsg::Error {
                        code: err_code::INVALID_FRAME.into(),
                        message: err.to_string(),
                    });
                    break;
                }
                Err(_) => {
                    disconnect_reason = "read_idle_timeout".to_string();
                    debug!(%device_id, %remote_addr, "signaling peer idle timeout");
                    abort_writer_immediately = true;
                    break;
                }
            }
        }

        // Cleanup (M4): serialized under per-device stripe lock so we only clear ephemeral
        // online status when this connection is still the active one.
        let removed_peer = {
            let _guard = self.lock_device(&device_id).await;
            let removed = self
                .peers
                .remove_if(&device_id, |_, peer| peer.conn_id == conn_id)
                .map(|(_, p)| p);
            if let Some(ref peer) = removed {
                if !self.peers.contains_key(&device_id) {
                    if let Err(err) = self.ephemeral.remove_online(&device_id).await {
                        warn!(%device_id, error = %err, "failed to remove offline device from ephemeral store");
                    }
                }
                if !peer.active_controllers.is_empty() {
                    self.broadcast_device_control_state(peer.owner_user_id, &device_id, Vec::new());
                }
            }
            removed
        };

        info!(
            %device_id,
            %remote_addr,
            conn_id,
            reason = %disconnect_reason,
            connected_secs = connected_instant.elapsed().as_secs(),
            "signaling peer disconnected"
        );

        if let Some(peer) = removed_peer {
            self.broadcast_user_device_status(DeviceStatusBroadcast {
                owner_user_id: peer.owner_user_id,
                device_id: &device_id,
                online: false,
                hostname: &peer.hostname,
                alias: &peer.alias,
                os: &peer.os,
                app_version: &peer.app_version,
                arch: &peer.arch,
                cpu_model: &peer.cpu_model,
                mac_address: &peer.mac_address,
                total_memory_mb: peer.total_memory_mb,
                os_version: &peer.os_version,
                gpu_model: &peer.gpu_model,
                allow_remote_assist: peer.allow_remote_assist,
                allow_remote_control: peer.allow_remote_control,
                wol_capable: peer.wol_capable,
            });
        }

        drop(tx);
        if abort_writer_immediately
            || tokio::time::timeout(
                self.config.write_timeout + Duration::from_millis(250),
                &mut writer_handle,
            )
            .await
            .is_err()
        {
            writer_handle.abort();
            let _ = writer_handle.await;
        }
    }

    async fn refresh_online_under_lock(
        &self,
        device_id: &str,
        conn_id: u64,
        cancel: &PeerCancel,
        new_lan_addrs: Option<Vec<String>>,
    ) -> bool {
        self.refresh_online_and_nat_under_lock(device_id, conn_id, cancel, new_lan_addrs, None)
            .await
    }

    async fn refresh_online_and_nat_under_lock(
        &self,
        device_id: &str,
        conn_id: u64,
        cancel: &PeerCancel,
        new_lan_addrs: Option<Vec<String>>,
        nat_update: Option<PeerNatUpdate>,
    ) -> bool {
        let _guard = self.lock_device(device_id).await;
        if !self.is_active_conn(device_id, conn_id, cancel) {
            return false;
        }
        if new_lan_addrs.is_some() || nat_update.is_some() {
            if let Some(mut peer) = self.peers.get_mut(device_id) {
                if peer.conn_id == conn_id {
                    if let Some(addrs) = new_lan_addrs {
                        peer.lan_addrs = addrs;
                    }
                    if let Some(nat) = nat_update {
                        apply_peer_nat_update(
                            &mut peer,
                            nat.nat_type.as_deref(),
                            nat.nat_port_delta,
                            nat.nat_port_range,
                        );
                    }
                }
            }
        }
        if let Err(err) = self
            .ephemeral
            .set_online(device_id, self.config.online_ttl)
            .await
        {
            warn!(%device_id, error = %err, "failed to refresh ephemeral online TTL");
        }
        true
    }

    async fn allocate_relay_token(
        &self,
        token: &str,
        record: RelayTokenRecord,
    ) -> Result<(), &'static str> {
        let max_tokens = self.config.max_relay_tokens;
        if max_tokens == 0 {
            return Err(err_code::RELAY_CAPACITY_EXCEEDED);
        }
        let use_local_tracker = match self.ephemeral.active_relay_token_count().await {
            Ok(Some(active)) => {
                if active >= max_tokens {
                    return Err(err_code::RELAY_CAPACITY_EXCEEDED);
                }
                false
            }
            Ok(None) | Err(_) => {
                // Fallback local cap tracking when backend does not cheaply report count (e.g. Redis).
                let now = Instant::now();
                if self.issued_relay_tokens.len() >= max_tokens {
                    self.issued_relay_tokens.retain(|_, exp| *exp > now);
                    if self.issued_relay_tokens.len() >= max_tokens {
                        return Err(err_code::RELAY_CAPACITY_EXCEEDED);
                    }
                }
                true
            }
        };

        match self
            .ephemeral
            .put_relay_token(token, record, self.config.relay_token_ttl)
            .await
        {
            Ok(()) => {
                if use_local_tracker {
                    if let Some(exp) = Instant::now().checked_add(self.config.relay_token_ttl) {
                        self.issued_relay_tokens.insert(token.to_string(), exp);
                    }
                }
                Ok(())
            }
            Err(EphemeralError::RelayTokenCapacityExceeded(_)) => {
                Err(err_code::RELAY_CAPACITY_EXCEEDED)
            }
            Err(err) => {
                warn!(error = %err, "failed to store relay token in ephemeral store");
                Err(err_code::RELAY_TOKEN_ERROR)
            }
        }
    }

    async fn cleanup_relay_token(&self, token: &str) {
        self.issued_relay_tokens.remove(token);
        if let Err(err) = self.ephemeral.take_relay_token(token).await {
            warn!(error = %err, "failed to clean up undelivered relay token");
        }
    }

    async fn authorize_peer_connection(
        &self,
        caller_device_id: &str,
        target_device_id: &str,
        session_id: &str,
    ) -> Result<(Option<OwnerGrantTicket>, bool), (&'static str, String)> {
        let caller_peer = self
            .peers
            .get(caller_device_id)
            .map(|p| (p.owner_user_id, p.device_pubkey.clone()));
        let caller_in_peers = caller_peer.is_some();
        let (peer_owner_uid, peer_pubkey) = caller_peer.unwrap_or((None, String::new()));

        let (caller_uid, caller_pubkey) = match self.device_store.get_by_id(caller_device_id).await
        {
            Ok(Some(rec)) => {
                if rec.disabled {
                    return Err((err_code::PEER_DISABLED, "当前设备已被禁用".to_string()));
                }
                if caller_in_peers && peer_owner_uid != rec.owner_user_id {
                    return Err((
                        err_code::UNAUTHORIZED,
                        "设备归属已变更，请重新登录认证".to_string(),
                    ));
                }
                let pk = if !rec.device_pubkey.trim().is_empty() {
                    rec.device_pubkey
                } else {
                    peer_pubkey
                };
                (rec.owner_user_id, pk)
            }
            Ok(None)
                if caller_in_peers && !self.config.require_auth && peer_owner_uid.is_none() =>
            {
                (None, peer_pubkey)
            }
            Ok(None) => return Err((err_code::UNAUTHORIZED, "当前设备未注册或已失效".to_string())),
            Err(err) => {
                warn!(caller = %caller_device_id, error = %err, "failed to load caller device for authorization");
                return Err((err_code::INTERNAL_ERROR, "校验当前设备状态失败".to_string()));
            }
        };
        let target_peer_rc = self
            .peers
            .get(target_device_id)
            .map(|p| p.allow_remote_control);
        let (target_uid, target_allow_assist, target_allow_remote_control) = match self
            .device_store
            .get_by_id(target_device_id)
            .await
        {
            Ok(Some(rec)) => {
                if rec.disabled {
                    return Err((err_code::PEER_DISABLED, "目标设备已被禁用".to_string()));
                }
                (
                    rec.owner_user_id,
                    rec.allow_remote_assist,
                    rec.allow_remote_control,
                )
            }
            Ok(None)
                if target_peer_rc.is_some()
                    && !self.config.require_auth
                    && caller_uid.is_none() =>
            {
                (None, false, target_peer_rc.unwrap_or(true))
            }
            Ok(None) => return Err((err_code::PEER_NOT_FOUND, "目标设备不存在".to_string())),
            Err(err) => {
                warn!(target = %target_device_id, error = %err, "failed to load target device for authorization");
                return Err((err_code::INTERNAL_ERROR, "校验目标设备状态失败".to_string()));
            }
        };

        if !target_allow_remote_control {
            return Err((
                err_code::REMOTE_CONTROL_DISABLED,
                "对方未开启允许远程控制".to_string(),
            ));
        }

        if let (Some(c_uid), Some(t_uid)) = (caller_uid, target_uid) {
            if c_uid == t_uid {
                let mut owner_grant = None;
                if let Some(ref auth_authority) = self.auth_authority {
                    let trimmed = caller_pubkey.trim();
                    let pk_hex = trimmed.strip_prefix("ed25519:").unwrap_or(trimmed);
                    if pk_hex.len() == 64 && pk_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                        match auth_authority.issue_owner_grant(
                            c_uid,
                            caller_device_id,
                            pk_hex,
                            target_device_id,
                            session_id,
                            OWNER_GRANT_DEFAULT_TTL,
                        ) {
                            Ok(ticket) => owner_grant = Some(ticket),
                            Err(err) => {
                                warn!(
                                    caller = %caller_device_id,
                                    target = %target_device_id,
                                    error = %err,
                                    "failed to issue owner_grant ticket"
                                );
                            }
                        }
                    }
                }
                return Ok((owner_grant, true));
            }
        }

        if (self.config.require_auth || caller_uid.is_some() || target_uid.is_some())
            && !target_allow_assist
        {
            return Err((
                err_code::ASSIST_DISABLED,
                "对方未开启允许他人远程协助".to_string(),
            ));
        }

        Ok((None, false))
    }

    fn check_target_in_session_and_takeover(
        &self,
        caller_device_id: &str,
        target_device_id: &str,
        is_owner_connection: bool,
        requested_takeover: bool,
    ) -> Result<bool, (&'static str, String)> {
        let effective_takeover = is_owner_connection && requested_takeover;
        let Some(target_peer) = self.peers.get(target_device_id) else {
            return Ok(effective_takeover);
        };
        if target_peer.active_controllers.is_empty() {
            return Ok(effective_takeover);
        }
        let is_same_controller = target_peer.active_controllers.iter().any(|c| {
            !c.controller_device_id.is_empty()
                && normalize_device_id(&c.controller_device_id) == caller_device_id
        });
        if is_same_controller {
            return Ok(effective_takeover);
        }
        if !requested_takeover {
            return Err((
                err_code::TARGET_IN_SESSION,
                "目标设备正在被其他控制端远控中".to_string(),
            ));
        }
        if !is_owner_connection {
            return Err((
                err_code::TARGET_IN_SESSION,
                "目标设备正在被其他控制端远控中，非同账号访客不允许接管".to_string(),
            ));
        }
        Ok(true)
    }

    async fn handle_peer_message(
        &self,
        device_id: &str,
        conn_id: u64,
        cancel: &PeerCancel,
        self_tx: &mpsc::Sender<SignalMsg>,
        msg: SignalMsg,
    ) {
        if !self.is_active_conn(device_id, conn_id, cancel) {
            return;
        }

        match msg {
            SignalMsg::Heartbeat {
                lan_addrs,
                mac_addr,
                wol_enabled,
                nat_type,
                nat_port_delta,
                nat_port_range,
                rtt_ms,
            } => {
                if let Err(reason) = validate_lan_addrs(&lan_addrs) {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::Error {
                            code: err_code::INVALID_PAYLOAD.into(),
                            message: reason,
                        },
                    );
                    return;
                }
                let normalized_mac = match validate_optional_signal_mac_addr(mac_addr.as_deref()) {
                    Ok(mac) => mac,
                    Err(reason) => {
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: err_code::INVALID_INPUT.into(),
                                message: reason.into(),
                            },
                        );
                        return;
                    }
                };
                let has_wol_update = normalized_mac.is_some() || wol_enabled.is_some();

                // Serialize online TTL refresh, peer LAN/WoL cache updates, and conditional DB
                // persistence under the per-device stripe lock to eliminate TOCTOU races with
                // concurrent bind/unbind/UpdateAssistState/PATCH.
                let changed_peer = {
                    let _guard = self.lock_device(device_id).await;
                    if !self.is_active_conn(device_id, conn_id, cancel) {
                        return;
                    }

                    let (owner_uid, public_ip_str, lan_addrs_changed) = match self
                        .peers
                        .get_mut(device_id)
                    {
                        Some(mut peer) if peer.conn_id == conn_id => {
                            let changed = !lan_addrs.is_empty() && peer.lan_addrs != lan_addrs;
                            if changed {
                                peer.lan_addrs = lan_addrs.clone();
                            }
                            apply_peer_nat_update(
                                &mut peer,
                                nat_type.as_deref(),
                                nat_port_delta,
                                nat_port_range,
                            );
                            if let Some(sample_ms) = rtt_ms {
                                peer.smoothed_rtt_ms =
                                    Some(update_smoothed_rtt_ms(peer.smoothed_rtt_ms, sample_ms));
                            }
                            (
                                peer.owner_user_id,
                                canonical_ip(peer.remote_addr.ip()).to_string(),
                                changed,
                            )
                        }
                        _ => return,
                    };

                    if let Err(err) = self
                        .ephemeral
                        .set_online(device_id, self.config.online_ttl)
                        .await
                    {
                        warn!(%device_id, error = %err, "failed to refresh ephemeral online TTL");
                    }

                    if has_wol_update || lan_addrs_changed {
                        let hb_lan_slice = lan_addrs_changed.then_some(lan_addrs.as_slice());
                        match self
                            .device_store
                            .update_device_wol_state(
                                device_id,
                                owner_uid,
                                normalized_mac.as_deref(),
                                wol_enabled,
                                hb_lan_slice,
                                Some(&public_ip_str),
                            )
                            .await
                        {
                            Ok(true) => {
                                if has_wol_update {
                                    if let Ok(Some(rec)) =
                                        self.device_store.get_by_id(device_id).await
                                    {
                                        let new_wol_capable = rec.wol_capable();
                                        let effective_mac = rec.effective_mac_address();
                                        self.peers.get_mut(device_id).and_then(|mut peer| {
                                            if peer.conn_id == conn_id
                                                && (peer.wol_capable != new_wol_capable
                                                    || peer.mac_address != effective_mac)
                                            {
                                                peer.wol_capable = new_wol_capable;
                                                peer.mac_address = effective_mac;
                                                Some(peer.to_owned_status())
                                            } else {
                                                None
                                            }
                                        })
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            }
                            Ok(false) => {
                                if owner_uid.is_none() {
                                    debug!(
                                        %device_id,
                                        "ignoring unauthenticated heartbeat WoL/topology update on bound or missing device"
                                    );
                                }
                                None
                            }
                            Err(err) => {
                                warn!(%device_id, error = %err, "heartbeat failed to persist WoL/network state");
                                None
                            }
                        }
                    } else {
                        None
                    }
                };

                if let Some(status) = changed_peer {
                    self.broadcast_user_device_status(DeviceStatusBroadcast {
                        owner_user_id: status.owner_user_id,
                        device_id,
                        online: true,
                        hostname: &status.hostname,
                        alias: &status.alias,
                        os: &status.os,
                        app_version: &status.app_version,
                        arch: &status.arch,
                        cpu_model: &status.cpu_model,
                        mac_address: &status.mac_address,
                        total_memory_mb: status.total_memory_mb,
                        os_version: &status.os_version,
                        gpu_model: &status.gpu_model,
                        allow_remote_assist: status.allow_remote_assist,
                        allow_remote_control: status.allow_remote_control,
                        wol_capable: status.wol_capable,
                    });
                }

                if let Err(err) = self.device_store.touch_last_seen(device_id).await {
                    warn!(%device_id, error = %err, "heartbeat failed to touch last_seen_at");
                }
                let public_udp_addr = self
                    .ephemeral
                    .get_public_udp(device_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|a| a.to_string());

                if !self.is_active_conn(device_id, conn_id, cancel) {
                    return;
                }
                Self::send_nonblocking(
                    self_tx,
                    device_id,
                    SignalMsg::HeartbeatAck {
                        server_time: Utc::now(),
                        public_udp_addr,
                        online_peers: self.peers.len(),
                    },
                );
            }

            SignalMsg::UpdateAssistState {
                allow_remote_assist,
                allow_remote_control,
                mac_addr,
                wol_enabled,
                cpu_model,
                mac_address,
                total_memory_mb,
                os_version,
                gpu_model,
            } => {
                let normalized_mac = match validate_optional_signal_mac_addr(mac_addr.as_deref()) {
                    Ok(mac) => mac,
                    Err(reason) => {
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: err_code::INVALID_INPUT.into(),
                                message: reason.into(),
                            },
                        );
                        return;
                    }
                };
                let clean_cpu_model = match validate_optional_signal_text(
                    cpu_model.as_deref(),
                    MAX_CPU_MODEL_LEN,
                    "cpu_model",
                ) {
                    Ok(v) => v,
                    Err(reason) => {
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: err_code::INVALID_INPUT.into(),
                                message: reason,
                            },
                        );
                        return;
                    }
                };
                let clean_mac_address =
                    match validate_optional_signal_mac_address(mac_address.as_deref()) {
                        Ok(v) => v,
                        Err(reason) => {
                            Self::send_nonblocking(
                                self_tx,
                                device_id,
                                SignalMsg::Error {
                                    code: err_code::INVALID_INPUT.into(),
                                    message: reason,
                                },
                            );
                            return;
                        }
                    };
                let clean_total_memory_mb =
                    match validate_optional_signal_total_memory_mb(total_memory_mb) {
                        Ok(v) => v,
                        Err(reason) => {
                            Self::send_nonblocking(
                                self_tx,
                                device_id,
                                SignalMsg::Error {
                                    code: err_code::INVALID_INPUT.into(),
                                    message: reason,
                                },
                            );
                            return;
                        }
                    };
                let clean_os_version = match validate_optional_signal_text(
                    os_version.as_deref(),
                    MAX_OS_VERSION_LEN,
                    "os_version",
                ) {
                    Ok(v) => v,
                    Err(reason) => {
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: err_code::INVALID_INPUT.into(),
                                message: reason,
                            },
                        );
                        return;
                    }
                };
                let clean_gpu_model = match validate_optional_signal_text(
                    gpu_model.as_deref(),
                    MAX_GPU_MODEL_LEN,
                    "gpu_model",
                ) {
                    Ok(v) => v,
                    Err(reason) => {
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: err_code::INVALID_INPUT.into(),
                                message: reason,
                            },
                        );
                        return;
                    }
                };
                let has_hardware_update = clean_cpu_model.is_some()
                    || clean_mac_address.is_some()
                    || clean_total_memory_mb.is_some()
                    || clean_os_version.is_some()
                    || clean_gpu_model.is_some();
                if allow_remote_assist.is_none()
                    && allow_remote_control.is_none()
                    && normalized_mac.is_none()
                    && wol_enabled.is_none()
                    && !has_hardware_update
                {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::Error {
                            code: err_code::INVALID_PAYLOAD.into(),
                            message: "at least one policy, Wake-on-LAN, or hardware metadata field is required"
                                .into(),
                        },
                    );
                    return;
                }

                let updated_peer = {
                    let _guard = self.lock_device(device_id).await;
                    if !self.is_active_conn(device_id, conn_id, cancel) {
                        return;
                    }
                    let owner = self.peers.get(device_id).and_then(|p| p.owner_user_id);
                    if owner.is_none() {
                        match self.device_store.get_by_id(device_id).await {
                            Ok(Some(rec)) if rec.owner_user_id.is_some() => {
                                Self::send_nonblocking(
                                    self_tx,
                                    device_id,
                                    SignalMsg::Error {
                                        code: err_code::UNAUTHORIZED.into(),
                                        message: "device ownership changed".into(),
                                    },
                                );
                                return;
                            }
                            Ok(Some(_)) => {}
                            Ok(None) => {
                                Self::send_nonblocking(
                                    self_tx,
                                    device_id,
                                    SignalMsg::Error {
                                        code: err_code::UPDATE_FAILED.into(),
                                        message: "device not found".into(),
                                    },
                                );
                                return;
                            }
                            Err(err) => {
                                warn!(%device_id, error = %err, "failed to verify device owner before UpdateAssistState");
                                Self::send_nonblocking(
                                    self_tx,
                                    device_id,
                                    SignalMsg::Error {
                                        code: err_code::INTERNAL_ERROR.into(),
                                        message: "failed to verify device ownership".into(),
                                    },
                                );
                                return;
                            }
                        }
                    }

                    if let Some(allow_assist) = allow_remote_assist {
                        match self
                            .device_store
                            .set_device_allow_remote_assist(device_id, owner, allow_assist)
                            .await
                        {
                            Ok(true) => {}
                            Ok(false) => {
                                warn!(%device_id, "UpdateAssistState allow_remote_assist affected 0 rows");
                                Self::send_nonblocking(
                                    self_tx,
                                    device_id,
                                    SignalMsg::Error {
                                        code: err_code::UPDATE_FAILED.into(),
                                        message: "failed to update allow_remote_assist".into(),
                                    },
                                );
                                return;
                            }
                            Err(err) => {
                                warn!(%device_id, error = %err, "failed to persist allow_remote_assist");
                                Self::send_nonblocking(
                                    self_tx,
                                    device_id,
                                    SignalMsg::Error {
                                        code: err_code::INTERNAL_ERROR.into(),
                                        message: "failed to persist allow_remote_assist".into(),
                                    },
                                );
                                return;
                            }
                        }
                    }

                    if let Some(allow_rc) = allow_remote_control {
                        match self
                            .device_store
                            .set_device_allow_remote_control(device_id, owner, allow_rc)
                            .await
                        {
                            Ok(true) => {}
                            Ok(false) => {
                                warn!(%device_id, "UpdateAssistState allow_remote_control affected 0 rows");
                                Self::send_nonblocking(
                                    self_tx,
                                    device_id,
                                    SignalMsg::Error {
                                        code: err_code::UPDATE_FAILED.into(),
                                        message: "failed to update allow_remote_control".into(),
                                    },
                                );
                                return;
                            }
                            Err(err) => {
                                warn!(%device_id, error = %err, "failed to persist allow_remote_control");
                                Self::send_nonblocking(
                                    self_tx,
                                    device_id,
                                    SignalMsg::Error {
                                        code: err_code::INTERNAL_ERROR.into(),
                                        message: "failed to persist allow_remote_control".into(),
                                    },
                                );
                                return;
                            }
                        }
                    }

                    let mut refreshed_wol_capable: Option<bool> = None;
                    let mut refreshed_mac_address: Option<String> = None;
                    if normalized_mac.is_some() || wol_enabled.is_some() {
                        match self
                            .device_store
                            .update_device_wol_state(
                                device_id,
                                owner,
                                normalized_mac.as_deref(),
                                wol_enabled,
                                None,
                                None,
                            )
                            .await
                        {
                            Ok(true) => {
                                if let Ok(Some(rec)) = self.device_store.get_by_id(device_id).await
                                {
                                    refreshed_wol_capable = Some(rec.wol_capable());
                                    refreshed_mac_address = Some(rec.effective_mac_address());
                                }
                            }
                            Ok(false) => {
                                warn!(%device_id, "UpdateAssistState WoL update affected 0 rows");
                                Self::send_nonblocking(
                                    self_tx,
                                    device_id,
                                    SignalMsg::Error {
                                        code: err_code::UPDATE_FAILED.into(),
                                        message: "failed to update Wake-on-LAN state".into(),
                                    },
                                );
                                return;
                            }
                            Err(err) => {
                                warn!(%device_id, error = %err, "failed to persist Wake-on-LAN state");
                                Self::send_nonblocking(
                                    self_tx,
                                    device_id,
                                    SignalMsg::Error {
                                        code: err_code::INTERNAL_ERROR.into(),
                                        message: "failed to persist Wake-on-LAN state".into(),
                                    },
                                );
                                return;
                            }
                        }
                    }

                    if has_hardware_update {
                        match self
                            .device_store
                            .update_device_hardware_info(
                                device_id,
                                owner,
                                DeviceHardwareUpdate {
                                    cpu_model: clean_cpu_model.as_deref(),
                                    mac_address: clean_mac_address.as_deref(),
                                    total_memory_mb: clean_total_memory_mb,
                                    os_version: clean_os_version.as_deref(),
                                    gpu_model: clean_gpu_model.as_deref(),
                                },
                            )
                            .await
                        {
                            Ok(true) => {
                                if let Ok(Some(rec)) = self.device_store.get_by_id(device_id).await
                                {
                                    refreshed_mac_address = Some(rec.effective_mac_address());
                                }
                            }
                            Ok(false) => {
                                warn!(%device_id, "UpdateAssistState hardware update affected 0 rows");
                                Self::send_nonblocking(
                                    self_tx,
                                    device_id,
                                    SignalMsg::Error {
                                        code: err_code::UPDATE_FAILED.into(),
                                        message: "failed to update hardware metadata".into(),
                                    },
                                );
                                return;
                            }
                            Err(err) => {
                                warn!(%device_id, error = %err, "failed to persist hardware metadata");
                                Self::send_nonblocking(
                                    self_tx,
                                    device_id,
                                    SignalMsg::Error {
                                        code: err_code::INTERNAL_ERROR.into(),
                                        message: "failed to persist hardware metadata".into(),
                                    },
                                );
                                return;
                            }
                        }
                    }

                    self.peers.get_mut(device_id).and_then(|mut peer| {
                        if peer.conn_id == conn_id {
                            if let Some(allow_assist) = allow_remote_assist {
                                peer.allow_remote_assist = allow_assist;
                            }
                            if let Some(allow_rc) = allow_remote_control {
                                peer.allow_remote_control = allow_rc;
                            }
                            if let Some(wol_cap) = refreshed_wol_capable {
                                peer.wol_capable = wol_cap;
                            }
                            if let Some(ref cpu) = clean_cpu_model {
                                peer.cpu_model = cpu.clone();
                            }
                            if let Some(ref mac) = refreshed_mac_address {
                                peer.mac_address = mac.clone();
                            } else if let Some(ref mac) = clean_mac_address {
                                peer.mac_address = mac.clone();
                            }
                            if let Some(mem) = clean_total_memory_mb {
                                peer.total_memory_mb = mem;
                            }
                            if let Some(ref ov) = clean_os_version {
                                peer.os_version = ov.clone();
                            }
                            if let Some(ref gpu) = clean_gpu_model {
                                peer.gpu_model = gpu.clone();
                            }
                            Some(peer.to_owned_status())
                        } else {
                            None
                        }
                    })
                };

                if let Some(status) = updated_peer {
                    self.broadcast_user_device_status(DeviceStatusBroadcast {
                        owner_user_id: status.owner_user_id,
                        device_id,
                        online: true,
                        hostname: &status.hostname,
                        alias: &status.alias,
                        os: &status.os,
                        app_version: &status.app_version,
                        arch: &status.arch,
                        cpu_model: &status.cpu_model,
                        mac_address: &status.mac_address,
                        total_memory_mb: status.total_memory_mb,
                        os_version: &status.os_version,
                        gpu_model: &status.gpu_model,
                        allow_remote_assist: status.allow_remote_assist,
                        allow_remote_control: status.allow_remote_control,
                        wol_capable: status.wol_capable,
                    });
                }
            }

            SignalMsg::ControlStateReport { active_controllers } => {
                self.handle_control_state_report(
                    device_id,
                    conn_id,
                    cancel,
                    self_tx,
                    active_controllers,
                )
                .await;
            }

            SignalMsg::ForceDisconnectRequest {
                target_id,
                controller_device_id,
                session_id,
            } => {
                self.handle_force_disconnect_request(
                    device_id,
                    conn_id,
                    cancel,
                    self_tx,
                    (target_id, controller_device_id, session_id),
                )
                .await;
            }

            SignalMsg::ConnectRequest {
                target_id,
                session_id,
                lan_addrs,
                nonce,
                nat_type,
                nat_port_delta,
                nat_port_range,
                takeover,
            } => {
                let target_norm = normalize_device_id(&target_id);
                if target_norm.is_empty() {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::Error {
                            code: err_code::INVALID_PAYLOAD.into(),
                            message: "target_id is required".into(),
                        },
                    );
                    return;
                }
                if target_norm == device_id {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::Error {
                            code: err_code::SELF_CONNECT.into(),
                            message: "cannot connect to self".into(),
                        },
                    );
                    return;
                }
                if let Err(reason) = validate_lan_addrs(&lan_addrs) {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::Error {
                            code: err_code::INVALID_PAYLOAD.into(),
                            message: reason,
                        },
                    );
                    return;
                }
                let session_id = match resolve_optional_ascii_token(
                    session_id,
                    MAX_SESSION_ID_LEN,
                    12,
                    "session_id",
                ) {
                    Ok(s) => s,
                    Err(reason) => {
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: err_code::INVALID_PAYLOAD.into(),
                                message: reason,
                            },
                        );
                        return;
                    }
                };
                let nonce = match resolve_optional_ascii_token(nonce, MAX_NONCE_LEN, 8, "nonce") {
                    Ok(n) => n,
                    Err(reason) => {
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: err_code::INVALID_PAYLOAD.into(),
                                message: reason,
                            },
                        );
                        return;
                    }
                };

                // H6: Per-peer rate limiting on ConnectRequest / RelayAlloc.
                if !check_sliding_window_rate_limit(
                    &self.connect_rate_limits,
                    device_id.to_string(),
                    self.config.connect_rate_limit_max,
                    self.config.connect_rate_limit_window,
                ) {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::Error {
                            code: err_code::RATE_LIMITED.into(),
                            message: "too many connect/relay requests".into(),
                        },
                    );
                    return;
                }

                // L5 + M4: Refresh ephemeral online TTL on authenticated peer activity.
                let updated_lan = if lan_addrs.is_empty() {
                    None
                } else {
                    Some(lan_addrs.clone())
                };
                let nat_update =
                    if nat_type.is_some() || nat_port_delta.is_some() || nat_port_range.is_some() {
                        Some(PeerNatUpdate {
                            nat_type,
                            nat_port_delta,
                            nat_port_range,
                        })
                    } else {
                        None
                    };
                if !self
                    .refresh_online_and_nat_under_lock(
                        device_id,
                        conn_id,
                        cancel,
                        updated_lan,
                        nat_update,
                    )
                    .await
                {
                    return;
                }

                let (
                    client_lan_addrs,
                    client_nat_type,
                    client_nat_port_delta,
                    client_nat_port_range,
                    client_rtt_ms,
                    client_rcp2_v2,
                    client_hostname,
                    client_os,
                ) = {
                    let snapshot = self
                        .peers
                        .get(device_id)
                        .filter(|p| p.conn_id == conn_id)
                        .map(|p| {
                            (
                                p.lan_addrs.clone(),
                                p.nat_type.clone(),
                                p.nat_port_delta,
                                p.nat_port_range,
                                p.smoothed_rtt_ms.unwrap_or(0),
                                p.rcp2_v2,
                                p.hostname.clone(),
                                p.os.clone(),
                            )
                        });
                    match snapshot {
                        Some((peer_lan, nt, delta, range, rtt, rcp2_v2, hostname, os)) => {
                            let addrs = if !lan_addrs.is_empty() {
                                lan_addrs
                            } else {
                                peer_lan
                            };
                            (addrs, nt, delta, range, rtt, rcp2_v2, hostname, os)
                        }
                        None => (
                            lan_addrs,
                            None,
                            None,
                            None,
                            0,
                            false,
                            String::new(),
                            String::new(),
                        ),
                    }
                };

                if !self.peers.contains_key(&target_norm) {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::PeerOffline {
                            target_id: target_norm,
                            session_id,
                        },
                    );
                    return;
                }

                let (owner_grant, is_owner_connection) = match self
                    .authorize_peer_connection(device_id, &target_norm, &session_id)
                    .await
                {
                    Ok(res) => res,
                    Err((code, message)) => {
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: code.into(),
                                message,
                            },
                        );
                        return;
                    }
                };

                let effective_takeover = match self.check_target_in_session_and_takeover(
                    device_id,
                    &target_norm,
                    is_owner_connection,
                    takeover,
                ) {
                    Ok(v) => v,
                    Err((code, message)) => {
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: code.into(),
                                message,
                            },
                        );
                        return;
                    }
                };

                let target_snapshot = self.peers.get(&target_norm).map(|p| {
                    (
                        p.tx.clone(),
                        p.lan_addrs.clone(),
                        p.nat_type.clone(),
                        p.nat_port_delta,
                        p.nat_port_range,
                        p.smoothed_rtt_ms.unwrap_or(0),
                        p.rcp2_v2,
                        p.hostname.clone(),
                        p.os.clone(),
                    )
                });

                let Some((
                    host_tx,
                    host_lan_addrs,
                    host_nat_type,
                    host_nat_port_delta,
                    host_nat_port_range,
                    host_rtt_ms,
                    host_rcp2_v2,
                    host_hostname,
                    host_os,
                )) = target_snapshot
                else {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::PeerOffline {
                            target_id: target_norm,
                            session_id,
                        },
                    );
                    return;
                };

                let client_udp_fallback = self
                    .ephemeral
                    .get_public_udp(device_id)
                    .await
                    .ok()
                    .flatten();
                let client_udp_all_addrs = self
                    .ephemeral
                    .get_public_udp_all(device_id)
                    .await
                    .unwrap_or_default();
                let host_udp_fallback = self
                    .ephemeral
                    .get_public_udp(&target_norm)
                    .await
                    .ok()
                    .flatten();
                let host_udp_all_addrs = self
                    .ephemeral
                    .get_public_udp_all(&target_norm)
                    .await
                    .unwrap_or_default();
                let (client_udp, host_udp) = select_legacy_public_udp_pair(
                    &client_udp_all_addrs,
                    client_udp_fallback,
                    &host_udp_all_addrs,
                    host_udp_fallback,
                );
                let client_udp_all: Vec<String> = client_udp_all_addrs
                    .into_iter()
                    .map(|a| a.to_string())
                    .collect();
                let host_udp_all: Vec<String> = host_udp_all_addrs
                    .into_iter()
                    .map(|a| a.to_string())
                    .collect();

                if !self.is_active_conn(device_id, conn_id, cancel) {
                    return;
                }

                let relay_token = random_hex(32);
                let punch_secret =
                    (client_rcp2_v2 && host_rcp2_v2).then(|| random_hex(PUNCH_SECRET_LEN));
                let client_start_after_ms =
                    compute_punch_start_after_ms(client_rtt_ms, host_rtt_ms);
                let host_start_after_ms = compute_punch_start_after_ms(host_rtt_ms, client_rtt_ms);
                let relay_fallback_after_ms = Some(self.config.relay_fallback_after_ms);
                let client_msg = SignalMsg::PunchCoord {
                    session_id: session_id.clone(),
                    role: "client".into(),
                    peer_id: target_norm.clone(),
                    peer_public_udp_addr: host_udp.clone(),
                    peer_public_udp_addrs: host_udp_all,
                    self_public_udp_addr: client_udp.clone(),
                    peer_nat_type: host_nat_type,
                    peer_nat_port_delta: host_nat_port_delta,
                    self_nat_port_range: client_nat_port_range,
                    peer_nat_port_range: host_nat_port_range,
                    peer_lan_addrs: host_lan_addrs,
                    nonce: nonce.clone(),
                    punch_secret: punch_secret.clone(),
                    start_after_ms: Some(client_start_after_ms),
                    relay_fallback_after_ms,
                    relay_token: relay_token.clone(),
                    relay_addr: self.config.public_relay_addr.clone(),
                    owner_grant,
                    is_owner_connection,
                    takeover: effective_takeover,
                    peer_hostname: non_empty_opt(&host_hostname),
                    peer_os: non_empty_opt(&host_os),
                };
                let host_msg = SignalMsg::PunchCoord {
                    session_id: session_id.clone(),
                    role: "host".into(),
                    peer_id: device_id.to_string(),
                    peer_public_udp_addr: client_udp,
                    peer_public_udp_addrs: client_udp_all,
                    self_public_udp_addr: host_udp,
                    peer_nat_type: client_nat_type,
                    peer_nat_port_delta: client_nat_port_delta,
                    self_nat_port_range: host_nat_port_range,
                    peer_nat_port_range: client_nat_port_range,
                    peer_lan_addrs: client_lan_addrs,
                    nonce,
                    punch_secret,
                    start_after_ms: Some(host_start_after_ms),
                    relay_fallback_after_ms,
                    relay_token: relay_token.clone(),
                    relay_addr: self.config.public_relay_addr.clone(),
                    owner_grant: None,
                    is_owner_connection,
                    takeover: effective_takeover,
                    peer_hostname: non_empty_opt(&client_hostname),
                    peer_os: non_empty_opt(&client_os),
                };

                // H5: Pre-check serialized frame length <= MAX_SIGNAL_FRAME_LEN before
                // allocating token or enqueueing to either peer.
                if encode_signal_frame(&client_msg).is_err()
                    || encode_signal_frame(&host_msg).is_err()
                {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::Error {
                            code: err_code::FRAME_TOO_LARGE.into(),
                            message: "punch_coord frame exceeds maximum length".into(),
                        },
                    );
                    return;
                }

                let token_record = RelayTokenRecord {
                    session_id: session_id.clone(),
                    host_id: target_norm.clone(),
                    client_id: device_id.to_string(),
                };
                if let Err(code) = self.allocate_relay_token(&relay_token, token_record).await {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::Error {
                            code: code.into(),
                            message: "failed to allocate fallback relay token".into(),
                        },
                    );
                    return;
                }

                if !self.is_active_conn(device_id, conn_id, cancel) {
                    self.cleanup_relay_token(&relay_token).await;
                    return;
                }

                // H6: Deliver to host first; if delivery fails, consume/delete the relay token
                // immediately so it never lingers in ephemeral storage.
                match Self::try_enqueue_checked(&host_tx, &target_norm, host_msg) {
                    Ok(()) => {
                        self.punch_coord_count.fetch_add(1, Ordering::Relaxed);
                        Self::send_nonblocking(self_tx, device_id, client_msg);
                    }
                    Err(EnqueueError::Closed) => {
                        self.cleanup_relay_token(&relay_token).await;
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::PeerOffline {
                                target_id: target_norm,
                                session_id,
                            },
                        );
                    }
                    Err(EnqueueError::Full) => {
                        self.cleanup_relay_token(&relay_token).await;
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: err_code::PEER_BUSY.into(),
                                message: "target peer signaling queue is full".into(),
                            },
                        );
                    }
                    Err(EnqueueError::FrameTooLarge) => {
                        self.cleanup_relay_token(&relay_token).await;
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: err_code::FRAME_TOO_LARGE.into(),
                                message: "punch_coord frame exceeds maximum length".into(),
                            },
                        );
                    }
                }
            }

            SignalMsg::RelayAlloc {
                target_id,
                session_id,
                takeover,
            } => {
                let target_norm = normalize_device_id(&target_id);
                if target_norm.is_empty() {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::Error {
                            code: err_code::INVALID_PAYLOAD.into(),
                            message: "target_id is required".into(),
                        },
                    );
                    return;
                }
                if target_norm == device_id {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::Error {
                            code: err_code::SELF_CONNECT.into(),
                            message: "cannot relay to self".into(),
                        },
                    );
                    return;
                }
                let session_id = match resolve_optional_ascii_token(
                    session_id,
                    MAX_SESSION_ID_LEN,
                    12,
                    "session_id",
                ) {
                    Ok(s) => s,
                    Err(reason) => {
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: err_code::INVALID_PAYLOAD.into(),
                                message: reason,
                            },
                        );
                        return;
                    }
                };

                // H6: Per-peer rate limiting on ConnectRequest / RelayAlloc.
                if !check_sliding_window_rate_limit(
                    &self.connect_rate_limits,
                    device_id.to_string(),
                    self.config.connect_rate_limit_max,
                    self.config.connect_rate_limit_window,
                ) {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::Error {
                            code: err_code::RATE_LIMITED.into(),
                            message: "too many connect/relay requests".into(),
                        },
                    );
                    return;
                }

                // L5 + M4: Refresh ephemeral online TTL on authenticated peer activity.
                if !self
                    .refresh_online_under_lock(device_id, conn_id, cancel, None)
                    .await
                {
                    return;
                }

                if !self.peers.contains_key(&target_norm) {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::PeerOffline {
                            target_id: target_norm,
                            session_id,
                        },
                    );
                    return;
                }

                let (owner_grant, is_owner_connection) = match self
                    .authorize_peer_connection(device_id, &target_norm, &session_id)
                    .await
                {
                    Ok(res) => res,
                    Err((code, message)) => {
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: code.into(),
                                message,
                            },
                        );
                        return;
                    }
                };

                let effective_takeover = match self.check_target_in_session_and_takeover(
                    device_id,
                    &target_norm,
                    is_owner_connection,
                    takeover,
                ) {
                    Ok(v) => v,
                    Err((code, message)) => {
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: code.into(),
                                message,
                            },
                        );
                        return;
                    }
                };

                let (client_hostname, client_os) = self
                    .peers
                    .get(device_id)
                    .filter(|p| p.conn_id == conn_id)
                    .map(|p| (p.hostname.clone(), p.os.clone()))
                    .unwrap_or_default();

                let target_snapshot = self
                    .peers
                    .get(&target_norm)
                    .map(|p| (p.tx.clone(), p.hostname.clone(), p.os.clone()));
                let Some((host_tx, host_hostname, host_os)) = target_snapshot else {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::PeerOffline {
                            target_id: target_norm,
                            session_id,
                        },
                    );
                    return;
                };

                if !self.is_active_conn(device_id, conn_id, cancel) {
                    return;
                }

                let relay_token = random_hex(32);
                let expires_in_sec = self.config.relay_token_ttl.as_secs();
                let client_msg = SignalMsg::RelayReady {
                    session_id: session_id.clone(),
                    role: "client".into(),
                    peer_id: target_norm.clone(),
                    relay_token: relay_token.clone(),
                    relay_addr: self.config.public_relay_addr.clone(),
                    expires_in_sec,
                    owner_grant,
                    is_owner_connection,
                    takeover: effective_takeover,
                    peer_hostname: non_empty_opt(&host_hostname),
                    peer_os: non_empty_opt(&host_os),
                };
                let host_msg = SignalMsg::RelayReady {
                    session_id: session_id.clone(),
                    role: "host".into(),
                    peer_id: device_id.to_string(),
                    relay_token: relay_token.clone(),
                    relay_addr: self.config.public_relay_addr.clone(),
                    expires_in_sec,
                    owner_grant: None,
                    is_owner_connection,
                    takeover: effective_takeover,
                    peer_hostname: non_empty_opt(&client_hostname),
                    peer_os: non_empty_opt(&client_os),
                };

                // H5: Pre-check serialized frame length before allocating token or enqueueing.
                if encode_signal_frame(&client_msg).is_err()
                    || encode_signal_frame(&host_msg).is_err()
                {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::Error {
                            code: err_code::FRAME_TOO_LARGE.into(),
                            message: "relay_ready frame exceeds maximum length".into(),
                        },
                    );
                    return;
                }

                let token_record = RelayTokenRecord {
                    session_id: session_id.clone(),
                    host_id: target_norm.clone(),
                    client_id: device_id.to_string(),
                };
                if let Err(code) = self.allocate_relay_token(&relay_token, token_record).await {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::Error {
                            code: code.into(),
                            message: "failed to allocate relay token".into(),
                        },
                    );
                    return;
                }

                if !self.is_active_conn(device_id, conn_id, cancel) {
                    self.cleanup_relay_token(&relay_token).await;
                    return;
                }

                // H6: Deliver to host first; delete relay token if delivery fails.
                match Self::try_enqueue_checked(&host_tx, &target_norm, host_msg) {
                    Ok(()) => {
                        Self::send_nonblocking(self_tx, device_id, client_msg);
                    }
                    Err(EnqueueError::Closed) => {
                        self.cleanup_relay_token(&relay_token).await;
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::PeerOffline {
                                target_id: target_norm,
                                session_id,
                            },
                        );
                    }
                    Err(EnqueueError::Full) => {
                        self.cleanup_relay_token(&relay_token).await;
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: err_code::PEER_BUSY.into(),
                                message: "target peer signaling queue is full".into(),
                            },
                        );
                    }
                    Err(EnqueueError::FrameTooLarge) => {
                        self.cleanup_relay_token(&relay_token).await;
                        Self::send_nonblocking(
                            self_tx,
                            device_id,
                            SignalMsg::Error {
                                code: err_code::FRAME_TOO_LARGE.into(),
                                message: "relay_ready frame exceeds maximum length".into(),
                            },
                        );
                    }
                }
            }

            SignalMsg::WolRequest {
                request_id,
                target_device_id,
            } => {
                self.handle_wol_request(
                    device_id,
                    conn_id,
                    cancel,
                    self_tx,
                    request_id,
                    target_device_id,
                )
                .await;
            }

            SignalMsg::Register { .. } => {
                Self::send_nonblocking(
                    self_tx,
                    device_id,
                    SignalMsg::Error {
                        code: err_code::ALREADY_REGISTERED.into(),
                        message: "connection is already registered".into(),
                    },
                );
            }

            _ => {
                Self::send_nonblocking(
                    self_tx,
                    device_id,
                    SignalMsg::Error {
                        code: err_code::UNEXPECTED_MESSAGE.into(),
                        message: "unsupported client-to-server signaling message".into(),
                    },
                );
            }
        }
    }

    async fn handle_control_state_report(
        &self,
        device_id: &str,
        conn_id: u64,
        cancel: &PeerCancel,
        self_tx: &mpsc::Sender<SignalMsg>,
        active_controllers: Vec<ActiveControllerSummary>,
    ) {
        if let Err(reason) = validate_active_controllers(&active_controllers) {
            Self::send_nonblocking(
                self_tx,
                device_id,
                SignalMsg::Error {
                    code: err_code::INVALID_PAYLOAD.into(),
                    message: reason,
                },
            );
            return;
        }
        let _guard = self.lock_device(device_id).await;
        if !self.is_active_conn(device_id, conn_id, cancel) {
            return;
        }
        let owner_user_id = {
            let Some(mut peer) = self.peers.get_mut(device_id) else {
                return;
            };
            if peer.conn_id != conn_id {
                return;
            }
            peer.active_controllers = active_controllers.clone();
            peer.owner_user_id
        };
        if let Err(err) = self
            .ephemeral
            .set_online(device_id, self.config.online_ttl)
            .await
        {
            warn!(
                %device_id,
                error = %err,
                "failed to refresh ephemeral online TTL on control_state_report"
            );
        }
        self.broadcast_device_control_state(owner_user_id, device_id, active_controllers);
    }

    async fn handle_force_disconnect_request(
        &self,
        device_id: &str,
        conn_id: u64,
        cancel: &PeerCancel,
        self_tx: &mpsc::Sender<SignalMsg>,
        (target_id, controller_device_id, session_id): (String, Option<String>, Option<String>),
    ) {
        let send_err = |code: &'static str, message: String| {
            Self::send_nonblocking(
                self_tx,
                device_id,
                SignalMsg::Error {
                    code: code.into(),
                    message,
                },
            );
        };

        let target_norm = normalize_device_id(&target_id);
        if target_norm.is_empty() {
            send_err(err_code::INVALID_PAYLOAD, "target_id is required".into());
            return;
        }

        let controller_device_id = match controller_device_id {
            Some(raw) => {
                if let Err(reason) = validate_metadata_field(
                    &raw,
                    MAX_CONTROLLER_DEVICE_ID_LEN,
                    "controller_device_id",
                ) {
                    send_err(err_code::INVALID_PAYLOAD, reason);
                    return;
                }
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            None => None,
        };

        let session_id = match session_id {
            Some(raw) if !raw.is_empty() => {
                if let Err(reason) = validate_ascii_token(&raw, MAX_SESSION_ID_LEN, "session_id") {
                    send_err(err_code::INVALID_PAYLOAD, reason);
                    return;
                }
                Some(raw)
            }
            _ => None,
        };

        if !check_sliding_window_rate_limit(
            &self.connect_rate_limits,
            device_id.to_string(),
            self.config.connect_rate_limit_max,
            self.config.connect_rate_limit_window,
        ) {
            send_err(
                err_code::RATE_LIMITED,
                "too many connect/relay/force_disconnect requests".into(),
            );
            return;
        }

        if !self
            .refresh_online_under_lock(device_id, conn_id, cancel, None)
            .await
        {
            return;
        }

        let caller_peer_owner = self.peers.get(device_id).and_then(|p| p.owner_user_id);
        let caller_uid = match self.device_store.get_by_id(device_id).await {
            Ok(Some(rec)) => {
                if rec.disabled {
                    send_err(err_code::PEER_DISABLED, "当前设备已被禁用".into());
                    return;
                }
                if self.peers.contains_key(device_id) && caller_peer_owner != rec.owner_user_id {
                    send_err(
                        err_code::UNAUTHORIZED,
                        "设备归属已变更，请重新登录认证".into(),
                    );
                    return;
                }
                match rec.owner_user_id {
                    Some(uid) => uid,
                    None => {
                        send_err(
                            err_code::UNAUTHORIZED,
                            "当前设备未绑定账号，无法发起远程断开".into(),
                        );
                        return;
                    }
                }
            }
            Ok(None) => {
                send_err(err_code::UNAUTHORIZED, "当前设备未注册或已失效".into());
                return;
            }
            Err(err) => {
                warn!(caller = %device_id, error = %err, "failed to load caller device for force_disconnect");
                send_err(err_code::INTERNAL_ERROR, "校验当前设备状态失败".into());
                return;
            }
        };

        match self.device_store.get_by_id(&target_norm).await {
            Ok(Some(rec)) => {
                if rec.owner_user_id != Some(caller_uid) {
                    send_err(
                        err_code::FORBIDDEN,
                        "仅允许断开同一账号下设备的远控连接".into(),
                    );
                    return;
                }
                if rec.disabled {
                    send_err(err_code::PEER_DISABLED, "目标设备已被禁用".into());
                    return;
                }
            }
            Ok(None) => {
                send_err(err_code::PEER_NOT_FOUND, "目标设备不存在".into());
                return;
            }
            Err(err) => {
                warn!(target = %target_norm, error = %err, "failed to load target device for force_disconnect");
                send_err(err_code::INTERNAL_ERROR, "校验目标设备状态失败".into());
                return;
            }
        }

        let target_peer = self
            .peers
            .get(&target_norm)
            .map(|p| (p.tx.clone(), p.owner_user_id));
        let Some((target_tx, target_peer_owner)) = target_peer else {
            send_err(err_code::PEER_OFFLINE, "目标设备当前不在线".into());
            return;
        };
        if target_peer_owner != Some(caller_uid) {
            send_err(
                err_code::FORBIDDEN,
                "仅允许断开同一账号下设备的远控连接".into(),
            );
            return;
        }

        if !self.is_active_conn(device_id, conn_id, cancel) {
            return;
        }

        let msg = SignalMsg::ForceDisconnect {
            requester_device_id: device_id.to_string(),
            controller_device_id,
            session_id,
        };
        match Self::try_enqueue_checked(&target_tx, &target_norm, msg) {
            Ok(()) => {}
            Err(EnqueueError::Closed) => {
                send_err(err_code::PEER_OFFLINE, "目标设备当前不在线".into());
            }
            Err(EnqueueError::Full) => {
                send_err(err_code::PEER_BUSY, "目标设备信令队列已满".into());
            }
            Err(EnqueueError::FrameTooLarge) => {
                send_err(
                    err_code::FRAME_TOO_LARGE,
                    "force_disconnect frame exceeds maximum length".into(),
                );
            }
        }
    }

    async fn handle_wol_request(
        &self,
        device_id: &str,
        conn_id: u64,
        cancel: &PeerCancel,
        self_tx: &mpsc::Sender<SignalMsg>,
        request_id: Option<String>,
        target_device_id: String,
    ) {
        let target_norm = normalize_device_id(&target_device_id);
        let caller_request_id = match request_id {
            Some(rid) if !rid.is_empty() => {
                if let Err(reason) = validate_ascii_token(&rid, MAX_SESSION_ID_LEN, "request_id") {
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::WolAck {
                            request_id: None,
                            target_device_id: target_norm,
                            ok: false,
                            method: WOL_METHOD_NONE.into(),
                            code: Some(err_code::INVALID_INPUT.into()),
                            message: reason,
                        },
                    );
                    return;
                }
                Some(rid)
            }
            _ => None,
        };

        let send_err = |code: &'static str, message: String| {
            Self::send_nonblocking(
                self_tx,
                device_id,
                SignalMsg::WolAck {
                    request_id: caller_request_id.clone(),
                    target_device_id: target_norm.clone(),
                    ok: false,
                    method: WOL_METHOD_NONE.into(),
                    code: Some(code.into()),
                    message,
                },
            );
        };

        if !is_valid_device_id(&target_norm) {
            send_err(err_code::INVALID_INPUT, "invalid target_device_id".into());
            return;
        }

        // Security gate 1: Caller must be authenticated with an active owner session.
        let caller_uid = match self
            .peers
            .get(device_id)
            .filter(|p| p.conn_id == conn_id)
            .and_then(|p| p.owner_user_id)
        {
            Some(uid) => uid,
            None => {
                send_err(
                    err_code::UNAUTHORIZED,
                    "authentication required for wake-on-lan".into(),
                );
                return;
            }
        };

        // Security gate 1b: Bounded per-caller rate limit BEFORE any DB/ephemeral lookups
        // to prevent device ID enumeration and DB read amplification.
        if !check_sliding_window_rate_limit(
            &self.wol_caller_rate_limits,
            device_id.to_string(),
            self.config.wol_caller_rate_limit_max,
            self.config.wol_caller_rate_limit_window,
        ) {
            send_err(
                err_code::RATE_LIMITED,
                "too many wake-on-lan requests from this caller".into(),
            );
            return;
        }

        match self.device_store.get_by_id(device_id).await {
            Ok(Some(rec)) => {
                if rec.disabled {
                    send_err(
                        err_code::DEVICE_DISABLED,
                        "caller device is disabled".into(),
                    );
                    return;
                }
                if rec.owner_user_id != Some(caller_uid) {
                    send_err(
                        err_code::UNAUTHORIZED,
                        "caller device ownership changed".into(),
                    );
                    return;
                }
            }
            Ok(None) => {
                send_err(
                    err_code::UNAUTHORIZED,
                    "caller device is not registered".into(),
                );
                return;
            }
            Err(err) => {
                warn!(caller = %device_id, error = %err, "failed to verify caller device for WoL");
                send_err(
                    err_code::INTERNAL_ERROR,
                    "failed to verify caller device".into(),
                );
                return;
            }
        }

        if !self
            .refresh_online_under_lock(device_id, conn_id, cancel, None)
            .await
        {
            return;
        }

        // Security gate 2: Target must exist, belong to the exact same owner account, and not be disabled.
        let target_rec = match self.device_store.get_by_id(&target_norm).await {
            Ok(Some(rec)) => rec,
            Ok(None) => {
                send_err(err_code::DEVICE_NOT_FOUND, "target device not found".into());
                return;
            }
            Err(err) => {
                warn!(target = %target_norm, error = %err, "failed to load target device for WoL");
                send_err(
                    err_code::INTERNAL_ERROR,
                    "failed to load target device".into(),
                );
                return;
            }
        };

        if target_rec.owner_user_id != Some(caller_uid) {
            send_err(
                err_code::FORBIDDEN,
                "target device is not owned by the authenticated user".into(),
            );
            return;
        }
        if target_rec.disabled {
            send_err(
                err_code::DEVICE_DISABLED,
                "target device is disabled".into(),
            );
            return;
        }

        // Security gate 3: Bounded per-target rate limit (1 request per 5 seconds).
        if !check_sliding_window_rate_limit(
            &self.wol_rate_limits,
            target_norm.clone(),
            1,
            self.config.wol_rate_limit_window,
        ) {
            send_err(
                err_code::RATE_LIMITED,
                "too many wake-on-lan requests for this target device".into(),
            );
            return;
        }

        // Security gate 4: Target must have WoL enabled with a valid unicast MAC address.
        let valid_mac = if target_rec.wol_enabled {
            target_rec.mac_addr.as_deref().and_then(normalize_mac_addr)
        } else {
            None
        };
        let Some(mac_addr) = valid_mac else {
            send_err(
                err_code::WOL_DISABLED,
                "wake-on-lan is disabled or no valid MAC address is configured for target device"
                    .into(),
            );
            return;
        };

        if !self.is_active_conn(device_id, conn_id, cancel) {
            return;
        }

        // Route 1: Target device is already online.
        if self.peers.contains_key(&target_norm) {
            Self::send_nonblocking(
                self_tx,
                device_id,
                SignalMsg::WolAck {
                    request_id: caller_request_id,
                    target_device_id: target_norm,
                    ok: true,
                    method: WOL_METHOD_ALREADY_ONLINE.into(),
                    code: None,
                    message: "target device is already online".into(),
                },
            );
            return;
        }

        // Route 2: Relay via another currently online peer under the same account on the same LAN.
        let mut candidates: Vec<(u8, String, mpsc::Sender<SignalMsg>)> = self
            .peers
            .iter()
            .filter(|entry| {
                let peer_id = entry.key().as_str();
                peer_id != target_norm
                    && peer_id != device_id
                    && entry.value().owner_user_id == Some(caller_uid)
            })
            .filter_map(|entry| {
                let peer = entry.value();
                let score = score_wol_relay_candidate(
                    &target_rec.last_public_ip,
                    &target_rec.last_lan_addrs,
                    peer.remote_addr.ip(),
                    &peer.lan_addrs,
                );
                if score > 0 {
                    Some((score, entry.key().clone(), peer.tx.clone()))
                } else {
                    None
                }
            })
            .collect();

        candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

        let relay_request_id = caller_request_id.clone().unwrap_or_else(|| random_hex(12));
        let relay_msg = SignalMsg::WolRelay {
            request_id: relay_request_id,
            target_device_id: target_norm.clone(),
            mac_addr: mac_addr.clone(),
            target_lan_addrs: target_rec.last_lan_addrs.clone(),
        };

        for (_, peer_id, peer_tx) in candidates {
            if Self::try_enqueue_checked(&peer_tx, &peer_id, relay_msg.clone()).is_ok() {
                info!(
                    caller = %device_id,
                    target = %target_norm,
                    relay_peer = %peer_id,
                    "relayed Wake-on-LAN request via same-account LAN peer"
                );
                Self::send_nonblocking(
                    self_tx,
                    device_id,
                    SignalMsg::WolAck {
                        request_id: caller_request_id,
                        target_device_id: target_norm,
                        ok: true,
                        method: WOL_METHOD_LAN_PEER.into(),
                        code: None,
                        message: "wake-on-lan magic packet relayed via same-LAN peer".into(),
                    },
                );
                return;
            }
        }

        // Route 3: Direct UDP broadcast from server when explicitly enabled via ALLOW_SERVER_WOL=true.
        if self.config.allow_server_wol {
            match send_server_wol_magic_packet(&mac_addr, &target_rec.last_lan_addrs).await {
                Ok(()) => {
                    info!(
                        caller = %device_id,
                        target = %target_norm,
                        "broadcast Wake-on-LAN magic packet directly from server"
                    );
                    Self::send_nonblocking(
                        self_tx,
                        device_id,
                        SignalMsg::WolAck {
                            request_id: caller_request_id,
                            target_device_id: target_norm,
                            ok: true,
                            method: WOL_METHOD_SERVER.into(),
                            code: None,
                            message: "wake-on-lan magic packet broadcast by server".into(),
                        },
                    );
                }
                Err(err) => {
                    warn!(
                        caller = %device_id,
                        target = %target_norm,
                        error = %err,
                        "server Wake-on-LAN UDP broadcast failed"
                    );
                    send_err(
                        err_code::WOL_SEND_FAILED,
                        format!("failed to send wake-on-lan magic packet: {err}"),
                    );
                }
            }
            return;
        }

        // Route 4: No relay peer available and server-side WoL disabled.
        send_err(
            err_code::WOL_NO_RELAY_PEER,
            "no online same-LAN peer available to relay wake-on-lan packet".into(),
        );
    }

    fn try_enqueue_checked(
        tx: &mpsc::Sender<SignalMsg>,
        target_id: &str,
        msg: SignalMsg,
    ) -> Result<(), EnqueueError> {
        if let Err(err) = encode_signal_frame(&msg) {
            warn!(
                peer = %target_id,
                error = %err,
                "refusing to enqueue oversized or unencodable signaling frame"
            );
            return Err(EnqueueError::FrameTooLarge);
        }
        match tx.try_send(msg) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!(peer = %target_id, "signaling outbound queue full");
                Err(EnqueueError::Full)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                debug!(peer = %target_id, "signaling outbound queue closed");
                Err(EnqueueError::Closed)
            }
        }
    }

    fn send_nonblocking(tx: &mpsc::Sender<SignalMsg>, target_id: &str, msg: SignalMsg) {
        let _ = Self::try_enqueue_checked(tx, target_id, msg);
    }
}

fn random_hex(num_bytes: usize) -> String {
    let mut bytes = vec![0u8; num_bytes];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ephemeral::MemoryEphemeralStore;
    use crate::store::MemoryDeviceStore;

    #[test]
    fn udp_rcsp_rcsa_codec_roundtrip_v4_and_v6() {
        let req = UdpProbeRequest {
            device_id: "123456789".into(),
            nonce: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let encoded = req.encode().expect("encode RCSP");
        assert_eq!(encoded.len(), 22);
        assert_eq!(&encoded[0..4], b"RCSP");
        assert_eq!(encoded[4], 1);
        assert_eq!(&encoded[5..14], b"123456789");
        assert_eq!(&encoded[14..22], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(UdpProbeRequest::decode(&encoded).unwrap(), req);

        // IPv4 RCSA (20 bytes)
        let resp_v4 = UdpProbeResponse {
            observed_addr: "203.0.113.42:54321".parse().unwrap(),
            nonce: req.nonce,
        };
        let enc_v4 = resp_v4.encode();
        assert_eq!(enc_v4.len(), 20);
        assert_eq!(&enc_v4[0..4], b"RCSA");
        assert_eq!(enc_v4[4], 1);
        assert_eq!(enc_v4[5], 4);
        assert_eq!(&enc_v4[6..10], &[203, 0, 113, 42]);
        assert_eq!(&enc_v4[10..12], &54321u16.to_be_bytes());
        assert_eq!(&enc_v4[12..20], &req.nonce);
        assert_eq!(UdpProbeResponse::decode(&enc_v4).unwrap(), resp_v4);

        // IPv6 RCSA (32 bytes)
        let resp_v6 = UdpProbeResponse {
            observed_addr: "[2001:db8::1]:60000".parse().unwrap(),
            nonce: [9, 8, 7, 6, 5, 4, 3, 2],
        };
        let enc_v6 = resp_v6.encode();
        assert_eq!(enc_v6.len(), 32);
        assert_eq!(enc_v6[5], 16);
        assert_eq!(UdpProbeResponse::decode(&enc_v6).unwrap(), resp_v6);

        // Reject bad magic / version / non-digit ID / length
        let mut bad = encoded;
        bad[0] = b'X';
        assert!(UdpProbeRequest::decode(&bad).is_err());
        assert!(UdpProbeRequest::decode(&encoded[..21]).is_err());
        let mut bad_id = encoded;
        bad_id[6] = b'z';
        assert!(UdpProbeRequest::decode(&bad_id).is_err());
    }

    #[test]
    fn tcp_framing_encode_decode_and_bounds() {
        let msg = SignalMsg::Heartbeat {
            lan_addrs: vec!["192.168.1.10:50000".into()],
            mac_addr: None,
            wol_enabled: None,
            nat_type: None,
            nat_port_delta: None,
            nat_port_range: None,
            rtt_ms: None,
        };
        let frame = encode_signal_frame(&msg).expect("encode frame");
        let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(len, frame.len() - 4);
        assert_eq!(decode_signal_frame(&frame).unwrap(), msg);

        // Zero-length rejected
        assert!(decode_signal_frame(&[0, 0, 0, 0]).is_err());
        // Oversized (>65536) rejected
        let mut oversized = (MAX_SIGNAL_FRAME_LEN as u32 + 1).to_be_bytes().to_vec();
        oversized.push(b'{');
        assert!(matches!(
            decode_signal_frame(&oversized),
            Err(SignalError::FrameTooLarge(_))
        ));
    }

    #[tokio::test]
    async fn udp_probe_listener_roundtrip_stores_public_addr() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store,
            ephemeral.clone(),
            SignalConfig::default(),
        ));

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let tcp_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(tcp_listener));

        // Authenticate and register online over TCP signaling first (required by H4).
        let mut sig = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut sig,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:udp-probe-key".into(),
                hostname: "udp-box".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let device_id = match read_signal_frame(&mut sig).await.unwrap().unwrap() {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered, got {other:?}"),
        };

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let udp_task = tokio::spawn(hub.clone().serve_udp_probe_on_socket(server_sock));

        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        let req = UdpProbeRequest {
            device_id: device_id.clone(),
            nonce: *b"rc-nonce",
        };
        client_sock
            .send_to(&req.encode().unwrap(), server_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = UdpProbeResponse::decode(&buf[..n]).unwrap();
        assert_eq!(resp.observed_addr, client_addr);
        assert_eq!(resp.nonce, *b"rc-nonce");

        // Wait briefly for the bounded background UDP update worker to persist the endpoint.
        let mut stored = None;
        for _ in 0..100 {
            stored = ephemeral.get_public_udp(&device_id).await.unwrap();
            if stored.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(stored, Some(client_addr));

        drop(sig);
        hub.shutdown_all().await;
        let _ = udp_task.await;
        let _ = tcp_task.await;
    }

    #[tokio::test]
    async fn native_tcp_signaling_full_flow_and_kick() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store.clone(),
            ephemeral.clone(),
            SignalConfig {
                public_udp_probe_addr: "127.0.0.1:21116".into(),
                public_relay_addr: "127.0.0.1:21117".into(),
                ..SignalConfig::default()
            },
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        // 1. Non-register first frame is rejected.
        {
            let mut bad = TcpStream::connect(tcp_addr).await.unwrap();
            write_signal_frame(
                &mut bad,
                &SignalMsg::Heartbeat {
                    lan_addrs: vec![],
                    mac_addr: None,
                    wol_enabled: None,
                    nat_type: None,
                    nat_port_delta: None,
                    nat_port_range: None,
                    rtt_ms: None,
                },
            )
            .await
            .unwrap();
            let reply = read_signal_frame(&mut bad).await.unwrap().unwrap();
            assert!(matches!(
                reply,
                SignalMsg::Error { code, .. } if code == "expected_register"
            ));
        }

        // 2. Register Host and Client over native framed TCP.
        let mut host = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut host,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:host-key".into(),
                hostname: "host-mac".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "lab".into(),
                lan_addrs: vec!["192.168.1.10:50000".into()],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let host_id = match read_signal_frame(&mut host).await.unwrap().unwrap() {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered for host, got {other:?}"),
        };

        let mut client = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut client,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:client-key".into(),
                hostname: "client-mac".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "lab".into(),
                lan_addrs: vec!["192.168.1.20:50001".into()],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let client_id = match read_signal_frame(&mut client).await.unwrap().unwrap() {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered for client, got {other:?}"),
        };

        // Simulate UDP probes stored in ephemeral store.
        let host_udp: SocketAddr = "198.51.100.10:40001".parse().unwrap();
        let client_udp: SocketAddr = "203.0.113.20:40002".parse().unwrap();
        ephemeral
            .set_public_udp(&host_id, host_udp, Duration::from_secs(60))
            .await
            .unwrap();
        ephemeral
            .set_public_udp(&client_id, client_udp, Duration::from_secs(60))
            .await
            .unwrap();

        // 3. Heartbeat reflects observed UDP addr and online count.
        write_signal_frame(
            &mut client,
            &SignalMsg::Heartbeat {
                lan_addrs: vec!["192.168.1.20:50001".into()],
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rtt_ms: None,
            },
        )
        .await
        .unwrap();
        match read_signal_frame(&mut client).await.unwrap().unwrap() {
            SignalMsg::HeartbeatAck {
                public_udp_addr,
                online_peers,
                ..
            } => {
                assert_eq!(public_udp_addr.as_deref(), Some("203.0.113.20:40002"));
                assert_eq!(online_peers, 2);
            }
            other => panic!("expected HeartbeatAck, got {other:?}"),
        }

        // 4. connect_request pushes punch_coord to BOTH client and host + stores fallback token.
        write_signal_frame(
            &mut client,
            &SignalMsg::ConnectRequest {
                target_id: host_id.clone(),
                session_id: Some("sess-punch-1".into()),
                lan_addrs: vec!["192.168.1.20:50001".into()],
                nonce: Some("deadbeef".into()),
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
        )
        .await
        .unwrap();

        let client_punch = read_signal_frame(&mut client).await.unwrap().unwrap();
        let host_punch = read_signal_frame(&mut host).await.unwrap().unwrap();

        let (c_tok, h_tok) = match (client_punch, host_punch) {
            (
                SignalMsg::PunchCoord {
                    session_id: cs,
                    role: cr,
                    peer_id: cp,
                    peer_public_udp_addr: c_udp,
                    peer_lan_addrs: c_lan,
                    relay_token: ct,
                    ..
                },
                SignalMsg::PunchCoord {
                    session_id: hs,
                    role: hr,
                    peer_id: hp,
                    peer_public_udp_addr: h_udp,
                    peer_lan_addrs: h_lan,
                    relay_token: ht,
                    ..
                },
            ) => {
                assert_eq!(cs, "sess-punch-1");
                assert_eq!(hs, "sess-punch-1");
                assert_eq!(cr, "client");
                assert_eq!(hr, "host");
                assert_eq!(cp, host_id);
                assert_eq!(hp, client_id);
                assert_eq!(c_udp.as_deref(), Some("198.51.100.10:40001"));
                assert_eq!(h_udp.as_deref(), Some("203.0.113.20:40002"));
                assert_eq!(c_lan, vec!["192.168.1.10:50000".to_string()]);
                assert_eq!(h_lan, vec!["192.168.1.20:50001".to_string()]);
                (ct, ht)
            }
            other => panic!("expected PunchCoord on both sides, got {other:?}"),
        };
        assert_eq!(c_tok, h_tok);
        let tok_rec = ephemeral
            .take_relay_token(&c_tok)
            .await
            .unwrap()
            .expect("relay token stored");
        assert_eq!(tok_rec.session_id, "sess-punch-1");
        assert_eq!(tok_rec.host_id, host_id);
        assert_eq!(tok_rec.client_id, client_id);

        // 5. relay_alloc pushes relay_ready to BOTH sides.
        write_signal_frame(
            &mut client,
            &SignalMsg::RelayAlloc {
                target_id: host_id.clone(),
                session_id: Some("sess-relay-2".into()),
                takeover: false,
            },
        )
        .await
        .unwrap();

        let client_ready = read_signal_frame(&mut client).await.unwrap().unwrap();
        let host_ready = read_signal_frame(&mut host).await.unwrap().unwrap();
        match (client_ready, host_ready) {
            (
                SignalMsg::RelayReady {
                    session_id: cs,
                    role: cr,
                    relay_token: ct,
                    ..
                },
                SignalMsg::RelayReady {
                    session_id: hs,
                    role: hr,
                    relay_token: ht,
                    ..
                },
            ) => {
                assert_eq!(cs, "sess-relay-2");
                assert_eq!(hs, "sess-relay-2");
                assert_eq!(cr, "client");
                assert_eq!(hr, "host");
                assert_eq!(ct, ht);
                assert!(ephemeral.take_relay_token(&ct).await.unwrap().is_some());
            }
            other => panic!("expected RelayReady on both sides, got {other:?}"),
        }

        // 6. Offline target returns peer_offline.
        write_signal_frame(
            &mut client,
            &SignalMsg::ConnectRequest {
                target_id: "999999999".into(),
                session_id: Some("sess-off".into()),
                lan_addrs: vec![],
                nonce: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut client).await.unwrap().unwrap(),
            SignalMsg::PeerOffline { target_id, session_id }
                if target_id == "999999999" && session_id == "sess-off"
        ));

        // 7. kick_device sends `kicked` and closes the TCP stream.
        assert!(hub.kick_device(&host_id, "admin_test").await);
        assert!(matches!(
            read_signal_frame(&mut host).await.unwrap().unwrap(),
            SignalMsg::Kicked { reason } if reason == "admin_test"
        ));
        assert_eq!(read_signal_frame(&mut host).await.unwrap(), None);
        assert!(!hub.is_peer_connected(&host_id));
        assert!(!ephemeral.is_online(&host_id).await.unwrap());

        // 8. Disabled device is rejected on register.
        store.set_disabled(&host_id, true).await.unwrap();
        let mut disabled_conn = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut disabled_conn,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:host-key".into(),
                hostname: "host-mac".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "lab".into(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut disabled_conn).await.unwrap().unwrap(),
            SignalMsg::Error { code, .. } if code == "device_disabled"
        ));

        server_task.abort();
    }

    #[tokio::test]
    async fn duplicate_reconnect_kicks_old_and_mismatch_rejected() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store,
            ephemeral.clone(),
            SignalConfig::default(),
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        let mut conn1 = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut conn1,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:dup-key".into(),
                hostname: "mac-1".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let device_id = match read_signal_frame(&mut conn1).await.unwrap().unwrap() {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered, got {other:?}"),
        };

        // Claiming wrong device_id for same device_key is rejected without kicking conn1.
        let mut wrong = TcpStream::connect(tcp_addr).await.unwrap();
        let wrong_id = if device_id == "111111111" {
            "222222222"
        } else {
            "111111111"
        };
        write_signal_frame(
            &mut wrong,
            &SignalMsg::Register {
                device_id: Some(wrong_id.into()),
                device_key: "ed25519:dup-key".into(),
                hostname: "mac-1".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut wrong).await.unwrap().unwrap(),
            SignalMsg::Error { code, .. } if code == "device_id_mismatch"
        ));

        // Reconnecting legitimately replaces conn1 and kicks conn1.
        let mut conn2 = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut conn2,
            &SignalMsg::Register {
                device_id: Some(device_id.clone()),
                device_key: "ed25519:dup-key".into(),
                hostname: "mac-1".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut conn2).await.unwrap().unwrap(),
            SignalMsg::Registered { device_id: id, .. } if id == device_id
        ));

        assert!(matches!(
            read_signal_frame(&mut conn1).await.unwrap().unwrap(),
            SignalMsg::Kicked { reason } if reason == "replaced_by_new_connection"
        ));
        assert_eq!(read_signal_frame(&mut conn1).await.unwrap(), None);

        // New connection remains online after old connection finishes cleanup.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(hub.is_peer_connected(&device_id));
        assert!(ephemeral.is_online(&device_id).await.unwrap());

        server_task.abort();
    }

    async fn accept_and_spawn_one(
        hub: Arc<SignalHub>,
        listener: &TcpListener,
    ) -> tokio::task::JoinHandle<()> {
        let (stream, addr) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            hub.handle_tcp_connection(stream, addr).await;
        })
    }

    async fn flood_peer_offline_to_stall(stream: &mut TcpStream) {
        // Shrink client receive buffer and flood valid `Heartbeat` frames without reading
        // `HeartbeatAck` replies so both kernel TCP buffers and the bounded server channel fill.
        let _ = socket2::SockRef::from(&*stream).set_recv_buffer_size(4096);
        for _ in 0..2048 {
            let msg = SignalMsg::Heartbeat {
                lan_addrs: vec![],
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rtt_ms: None,
            };
            if write_signal_frame(stream, &msg).await.is_err() {
                break;
            }
        }
    }

    #[tokio::test]
    async fn kick_and_replace_terminate_stalled_peer_and_protect_new_lan_addrs() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store,
            ephemeral.clone(),
            SignalConfig {
                channel_capacity: 2,
                write_timeout: Duration::from_millis(200),
                read_idle_timeout: Duration::from_secs(30),
                ..SignalConfig::default()
            },
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();

        // Register a target peer so we can prove kicked/stalled peers cannot allocate relay tokens.
        let mut target_client = TcpStream::connect(tcp_addr).await.unwrap();
        let target_task = accept_and_spawn_one(hub.clone(), &listener).await;
        write_signal_frame(
            &mut target_client,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:target-peer".into(),
                hostname: "target".into(),
                os: "linux".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let target_id = match read_signal_frame(&mut target_client)
            .await
            .unwrap()
            .unwrap()
        {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered for target, got {other:?}"),
        };

        // 1. Kick a stalled peer whose channel & kernel send buffer are full.
        let mut stalled = TcpStream::connect(tcp_addr).await.unwrap();
        let stalled_task = accept_and_spawn_one(hub.clone(), &listener).await;
        write_signal_frame(
            &mut stalled,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:stalled-kick-key".into(),
                hostname: "stalled-box".into(),
                os: "linux".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec!["10.0.0.1:5000".into()],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let stalled_id = match read_signal_frame(&mut stalled).await.unwrap().unwrap() {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered for stalled peer, got {other:?}"),
        };

        // Stop reading from `stalled` and saturate its outbound buffers + channel.
        flood_peer_offline_to_stall(&mut stalled).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(hub.kick_device(&stalled_id, "admin_stalled_kick").await);
        tokio::time::timeout(Duration::from_secs(2), stalled_task)
            .await
            .expect("kicked stalled connection must exit promptly")
            .unwrap();

        // Subsequent frames from the kicked socket cannot re-mark it online or allocate relay tokens.
        let _ = write_signal_frame(
            &mut stalled,
            &SignalMsg::Heartbeat {
                lan_addrs: vec!["10.99.99.99:9999".into()],
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rtt_ms: None,
            },
        )
        .await;
        let _ = write_signal_frame(
            &mut stalled,
            &SignalMsg::RelayAlloc {
                target_id: target_id.clone(),
                session_id: Some("sess-after-kick".into()),
                takeover: false,
            },
        )
        .await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(!hub.is_peer_connected(&stalled_id));
        assert!(!ephemeral.is_online(&stalled_id).await.unwrap());
        assert_eq!(ephemeral.active_token_count(), 0);

        // 2. Duplicate reconnect replaces a stalled old connection and protects new `lan_addrs`.
        let mut old_conn = TcpStream::connect(tcp_addr).await.unwrap();
        let old_task = accept_and_spawn_one(hub.clone(), &listener).await;
        write_signal_frame(
            &mut old_conn,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:replace-stalled-key".into(),
                hostname: "dup-box".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec!["10.1.0.1:1111".into()],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let dup_id = match read_signal_frame(&mut old_conn).await.unwrap().unwrap() {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered for old_conn, got {other:?}"),
        };

        flood_peer_offline_to_stall(&mut old_conn).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut new_conn = TcpStream::connect(tcp_addr).await.unwrap();
        let new_task = accept_and_spawn_one(hub.clone(), &listener).await;
        write_signal_frame(
            &mut new_conn,
            &SignalMsg::Register {
                device_id: Some(dup_id.clone()),
                device_key: "ed25519:replace-stalled-key".into(),
                hostname: "dup-box".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec!["10.2.0.2:2222".into()],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut new_conn).await.unwrap().unwrap(),
            SignalMsg::Registered { device_id, .. } if device_id == dup_id
        ));

        // Attempt a stale heartbeat from `old_conn` carrying old `lan_addrs`.
        let _ = write_signal_frame(
            &mut old_conn,
            &SignalMsg::Heartbeat {
                lan_addrs: vec!["10.99.99.99:9999".into()],
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rtt_ms: None,
            },
        )
        .await;

        tokio::time::timeout(Duration::from_secs(2), old_task)
            .await
            .expect("replaced stalled connection must exit promptly")
            .unwrap();

        assert!(hub.is_peer_connected(&dup_id));
        assert!(ephemeral.is_online(&dup_id).await.unwrap());
        assert_eq!(
            hub.peer_lan_addrs(&dup_id),
            Some(vec!["10.2.0.2:2222".to_string()])
        );

        drop(new_conn);
        drop(target_client);
        let _ = tokio::time::timeout(Duration::from_secs(2), new_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), target_task).await;
    }

    #[tokio::test]
    async fn idle_timeout_exits_promptly_when_writer_is_stalled() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store,
            ephemeral.clone(),
            SignalConfig {
                channel_capacity: 2,
                write_timeout: Duration::from_millis(200),
                read_idle_timeout: Duration::from_millis(150),
                ..SignalConfig::default()
            },
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();

        let mut client = TcpStream::connect(tcp_addr).await.unwrap();
        let conn_task = accept_and_spawn_one(hub.clone(), &listener).await;
        write_signal_frame(
            &mut client,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:idle-stalled-key".into(),
                hostname: "idle-box".into(),
                os: "linux".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let device_id = match read_signal_frame(&mut client).await.unwrap().unwrap() {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered, got {other:?}"),
        };

        flood_peer_offline_to_stall(&mut client).await;

        // Do not read or write anymore; idle timeout must abort the stalled writer without hanging.
        tokio::time::timeout(Duration::from_secs(2), conn_task)
            .await
            .expect("idle timeout must not hang waiting on stalled writer")
            .unwrap();
        assert!(!hub.is_peer_connected(&device_id));
        assert!(!ephemeral.is_online(&device_id).await.unwrap());
    }

    #[tokio::test]
    async fn claimed_device_id_mismatch_does_not_insert_or_mutate_store() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store.clone(),
            ephemeral,
            SignalConfig::default(),
        ));

        let rec_a = store
            .register_or_get(RegisterInput {
                device_key: "ed25519:key-a".into(),
                hostname: "host-a".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                device_group: "grp-a".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let rec_b = store
            .register_or_get(RegisterInput {
                device_key: "ed25519:key-b".into(),
                hostname: "host-b".into(),
                os: "linux".into(),
                app_version: String::new(),
                arch: String::new(),
                device_group: "grp-b".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(store.count_devices().await.unwrap(), 2);

        tokio::time::sleep(Duration::from_millis(20)).await;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        // 1. Unknown device_key claiming existing device A's ID -> rejected, no insert, no mutation.
        {
            let mut s = TcpStream::connect(tcp_addr).await.unwrap();
            write_signal_frame(
                &mut s,
                &SignalMsg::Register {
                    device_id: Some(rec_a.device_id.clone()),
                    device_key: "ed25519:unknown-attacker-key".into(),
                    hostname: "evil-host".into(),
                    os: "evil-os".into(),
                    app_version: String::new(),
                    arch: String::new(),
                    cpu_model: String::new(),
                    mac_address: String::new(),
                    total_memory_mb: 0,
                    os_version: String::new(),
                    gpu_model: String::new(),
                    device_group: "evil-grp".into(),
                    lan_addrs: vec![],
                    access_token: None,
                    device_pubkey: None,
                    allow_remote_assist: None,
                    allow_remote_control: None,
                    mac_addr: None,
                    wol_enabled: None,
                    nat_type: None,
                    nat_port_delta: None,
                    nat_port_range: None,
                    rcp2_v2: false,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                read_signal_frame(&mut s).await.unwrap().unwrap(),
                SignalMsg::Error { code, .. } if code == "device_id_mismatch"
            ));
        }

        // 2. Unknown device_key claiming non-existent ID -> rejected, no insert.
        {
            let mut s = TcpStream::connect(tcp_addr).await.unwrap();
            write_signal_frame(
                &mut s,
                &SignalMsg::Register {
                    device_id: Some("999999999".into()),
                    device_key: "ed25519:another-unknown-key".into(),
                    hostname: "ghost".into(),
                    os: "linux".into(),
                    app_version: String::new(),
                    arch: String::new(),
                    cpu_model: String::new(),
                    mac_address: String::new(),
                    total_memory_mb: 0,
                    os_version: String::new(),
                    gpu_model: String::new(),
                    device_group: "ghost".into(),
                    lan_addrs: vec![],
                    access_token: None,
                    device_pubkey: None,
                    allow_remote_assist: None,
                    allow_remote_control: None,
                    mac_addr: None,
                    wol_enabled: None,
                    nat_type: None,
                    nat_port_delta: None,
                    nat_port_range: None,
                    rcp2_v2: false,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                read_signal_frame(&mut s).await.unwrap().unwrap(),
                SignalMsg::Error { code, .. } if code == "device_id_mismatch"
            ));
        }

        // 3. Existing key-a claiming device B's ID -> rejected, neither A nor B mutated.
        {
            let mut s = TcpStream::connect(tcp_addr).await.unwrap();
            write_signal_frame(
                &mut s,
                &SignalMsg::Register {
                    device_id: Some(rec_b.device_id.clone()),
                    device_key: "ed25519:key-a".into(),
                    hostname: "mutated-a".into(),
                    os: "mutated-os".into(),
                    app_version: String::new(),
                    arch: String::new(),
                    cpu_model: String::new(),
                    mac_address: String::new(),
                    total_memory_mb: 0,
                    os_version: String::new(),
                    gpu_model: String::new(),
                    device_group: "mutated-grp".into(),
                    lan_addrs: vec![],
                    access_token: None,
                    device_pubkey: None,
                    allow_remote_assist: None,
                    allow_remote_control: None,
                    mac_addr: None,
                    wol_enabled: None,
                    nat_type: None,
                    nat_port_delta: None,
                    nat_port_range: None,
                    rcp2_v2: false,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                read_signal_frame(&mut s).await.unwrap().unwrap(),
                SignalMsg::Error { code, .. } if code == "device_id_mismatch"
            ));
        }

        assert_eq!(store.count_devices().await.unwrap(), 2);
        let after_a = store.get_by_id(&rec_a.device_id).await.unwrap().unwrap();
        let after_b = store.get_by_id(&rec_b.device_id).await.unwrap().unwrap();
        assert_eq!(after_a, rec_a);
        assert_eq!(after_b, rec_b);

        server_task.abort();
    }

    struct GatedEphemeralStore {
        inner: MemoryEphemeralStore,
        gate_enabled: std::sync::atomic::AtomicBool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
        remove_gate_enabled: std::sync::atomic::AtomicBool,
        remove_entered: tokio::sync::Notify,
        remove_release: tokio::sync::Notify,
    }

    impl GatedEphemeralStore {
        fn new() -> Self {
            Self {
                inner: MemoryEphemeralStore::new(),
                gate_enabled: std::sync::atomic::AtomicBool::new(false),
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
                remove_gate_enabled: std::sync::atomic::AtomicBool::new(false),
                remove_entered: tokio::sync::Notify::new(),
                remove_release: tokio::sync::Notify::new(),
            }
        }

        fn enable_gate(&self, enabled: bool) {
            self.gate_enabled
                .store(enabled, std::sync::atomic::Ordering::SeqCst);
        }

        fn enable_remove_gate(&self, enabled: bool) {
            self.remove_gate_enabled
                .store(enabled, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl EphemeralStore for GatedEphemeralStore {
        async fn set_online(
            &self,
            device_id: &str,
            ttl: Duration,
        ) -> Result<(), crate::ephemeral::EphemeralError> {
            if self
                .gate_enabled
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                self.entered.notify_one();
                self.release.notified().await;
            }
            self.inner.set_online(device_id, ttl).await
        }

        async fn remove_online(
            &self,
            device_id: &str,
        ) -> Result<(), crate::ephemeral::EphemeralError> {
            if self
                .remove_gate_enabled
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                self.remove_entered.notify_one();
                self.remove_release.notified().await;
            }
            self.inner.remove_online(device_id).await
        }

        async fn is_online(
            &self,
            device_id: &str,
        ) -> Result<bool, crate::ephemeral::EphemeralError> {
            self.inner.is_online(device_id).await
        }

        async fn online_ids(&self) -> Result<Vec<String>, crate::ephemeral::EphemeralError> {
            self.inner.online_ids().await
        }

        async fn set_public_udp(
            &self,
            device_id: &str,
            addr: SocketAddr,
            ttl: Duration,
        ) -> Result<(), crate::ephemeral::EphemeralError> {
            self.inner.set_public_udp(device_id, addr, ttl).await
        }

        async fn get_public_udp(
            &self,
            device_id: &str,
        ) -> Result<Option<SocketAddr>, crate::ephemeral::EphemeralError> {
            self.inner.get_public_udp(device_id).await
        }

        async fn get_public_udp_all(
            &self,
            device_id: &str,
        ) -> Result<Vec<SocketAddr>, crate::ephemeral::EphemeralError> {
            self.inner.get_public_udp_all(device_id).await
        }

        async fn put_relay_token(
            &self,
            token: &str,
            record: RelayTokenRecord,
            ttl: Duration,
        ) -> Result<(), crate::ephemeral::EphemeralError> {
            self.inner.put_relay_token(token, record, ttl).await
        }

        async fn take_relay_token(
            &self,
            token: &str,
        ) -> Result<Option<RelayTokenRecord>, crate::ephemeral::EphemeralError> {
            self.inner.take_relay_token(token).await
        }

        fn backend_name(&self) -> &'static str {
            "gated-memory"
        }

        async fn health_check(&self) -> Result<(), crate::ephemeral::EphemeralError> {
            self.inner.health_check().await
        }
    }

    #[tokio::test]
    async fn kick_during_inflight_register_and_heartbeat_clears_ephemeral_online() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(GatedEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store.clone(),
            ephemeral.clone(),
            SignalConfig::default(),
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();

        // Pre-register device so we know its device_id before Register's `set_online` completes.
        let rec = store
            .register_or_get(RegisterInput {
                device_key: "ed25519:race-key".into(),
                hostname: "race-box".into(),
                os: "linux".into(),
                app_version: String::new(),
                arch: String::new(),
                device_group: "".into(),
                ..Default::default()
            })
            .await
            .unwrap();

        // Sub-case A: Kick arrives while Register's `set_online` is in flight.
        ephemeral.enable_gate(true);
        let mut conn1 = TcpStream::connect(tcp_addr).await.unwrap();
        let conn1_task = accept_and_spawn_one(hub.clone(), &listener).await;
        write_signal_frame(
            &mut conn1,
            &SignalMsg::Register {
                device_id: Some(rec.device_id.clone()),
                device_key: "ed25519:race-key".into(),
                hostname: "race-box".into(),
                os: "linux".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(2), ephemeral.entered.notified())
            .await
            .expect("register must enter set_online");

        // M4 stripe lock serializes kick_device behind the in-flight Register transition;
        // spawn kick concurrently, then release the gate so kick executes immediately after.
        let kick_task1 = tokio::spawn({
            let hub = hub.clone();
            let id = rec.device_id.clone();
            async move { hub.kick_device(&id, "kick_during_register").await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        ephemeral.release.notify_one();

        assert!(tokio::time::timeout(Duration::from_secs(2), kick_task1)
            .await
            .expect("kick_device must complete after register releases stripe lock")
            .unwrap());

        tokio::time::timeout(Duration::from_secs(2), conn1_task)
            .await
            .expect("kicked conn1 must exit promptly")
            .unwrap();
        assert!(!hub.is_peer_connected(&rec.device_id));
        assert!(
            !ephemeral.is_online(&rec.device_id).await.unwrap(),
            "device must not remain falsely online after kick during Register"
        );

        // Sub-case B: Kick arrives while Heartbeat's `set_online` is in flight.
        let mut conn2 = TcpStream::connect(tcp_addr).await.unwrap();
        let conn2_task = accept_and_spawn_one(hub.clone(), &listener).await;
        write_signal_frame(
            &mut conn2,
            &SignalMsg::Register {
                device_id: Some(rec.device_id.clone()),
                device_key: "ed25519:race-key".into(),
                hostname: "race-box".into(),
                os: "linux".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut conn2).await.unwrap().unwrap(),
            SignalMsg::Registered { device_id, .. } if device_id == rec.device_id
        ));

        ephemeral.enable_gate(true);
        write_signal_frame(
            &mut conn2,
            &SignalMsg::Heartbeat {
                lan_addrs: vec!["10.0.0.5:5000".into()],
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rtt_ms: None,
            },
        )
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(2), ephemeral.entered.notified())
            .await
            .expect("heartbeat must enter set_online");

        let kick_task2 = tokio::spawn({
            let hub = hub.clone();
            let id = rec.device_id.clone();
            async move { hub.kick_device(&id, "kick_during_heartbeat").await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        ephemeral.release.notify_one();

        assert!(tokio::time::timeout(Duration::from_secs(2), kick_task2)
            .await
            .expect("kick_device must complete after heartbeat releases stripe lock")
            .unwrap());

        tokio::time::timeout(Duration::from_secs(2), conn2_task)
            .await
            .expect("kicked conn2 must exit promptly")
            .unwrap();
        assert!(!hub.is_peer_connected(&rec.device_id));
        assert!(
            !ephemeral.is_online(&rec.device_id).await.unwrap(),
            "device must not remain falsely online after kick during Heartbeat"
        );
    }

    async fn register_peer_helper(
        tcp_addr: SocketAddr,
        device_key: &str,
        lan_addrs: Vec<String>,
    ) -> (TcpStream, String) {
        let mut stream = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut stream,
            &SignalMsg::Register {
                device_id: None,
                device_key: device_key.into(),
                hostname: "test-host".into(),
                os: "linux".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "test".into(),
                lan_addrs,
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let device_id = match read_signal_frame(&mut stream).await.unwrap().unwrap() {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered, got {other:?}"),
        };
        (stream, device_id)
    }

    #[tokio::test]
    async fn h4_udp_spoof_offline_invalid_id_and_ip_mismatch_rejected() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store,
            ephemeral.clone(),
            SignalConfig {
                udp_rate_limit_max: 4,
                udp_rate_limit_window: Duration::from_secs(10),
                ..SignalConfig::default()
            },
        ));

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();

        // Register a victim peer whose recorded TCP remote IP is 198.51.100.99 (different from 127.0.0.1!).
        let mut victim_client = TcpStream::connect(tcp_addr).await.unwrap();
        let (victim_srv, _) = tcp_listener.accept().await.unwrap();
        let spoofed_remote: SocketAddr = "198.51.100.99:44444".parse().unwrap();
        let victim_task = tokio::spawn(
            hub.clone()
                .handle_tcp_connection(victim_srv, spoofed_remote),
        );
        write_signal_frame(
            &mut victim_client,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:h4-victim".into(),
                hostname: "victim".into(),
                os: "linux".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let victim_id = match read_signal_frame(&mut victim_client)
            .await
            .unwrap()
            .unwrap()
        {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered, got {other:?}"),
        };

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let udp_task = tokio::spawn(hub.clone().serve_udp_probe_on_socket(server_sock));

        let attacker_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = [0u8; 64];

        // 1. Invalid device_id ("012345678", starts with 0 and is not ANONYMOUS_DEVICE_ID) -> dropped.
        let invalid_req = UdpProbeRequest {
            device_id: "012345678".into(),
            nonce: *b"bad00001",
        };
        attacker_sock
            .send_to(&invalid_req.encode().unwrap(), server_addr)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(80), attacker_sock.recv_from(&mut buf))
                .await
                .is_err(),
            "invalid device_id RCSP must be dropped without RCSA"
        );
        assert_eq!(ephemeral.get_public_udp("012345678").await.unwrap(), None);

        // 2. Offline valid device_id -> echoes RCSA, but MUST NOT store public_udp!
        let offline_req = UdpProbeRequest {
            device_id: "987654321".into(),
            nonce: *b"off00002",
        };
        attacker_sock
            .send_to(&offline_req.encode().unwrap(), server_addr)
            .await
            .unwrap();
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(2), attacker_sock.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            UdpProbeResponse::decode(&buf[..n]).unwrap().nonce,
            *b"off00002"
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(ephemeral.get_public_udp("987654321").await.unwrap(), None);

        // 3. Online victim_id probed from mismatched IP (127.0.0.1 != 198.51.100.99) -> spoof rejected!
        let spoof_req = UdpProbeRequest {
            device_id: victim_id.clone(),
            nonce: *b"spf00003",
        };
        attacker_sock
            .send_to(&spoof_req.encode().unwrap(), server_addr)
            .await
            .unwrap();
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(2), attacker_sock.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            UdpProbeResponse::decode(&buf[..n]).unwrap().nonce,
            *b"spf00003"
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(
            ephemeral.get_public_udp(&victim_id).await.unwrap(),
            None,
            "mismatched-IP UDP probe must NOT poison victim's public_udp"
        );

        // 4. Anonymous probe consumes 4th rate-limit slot, then 5th probe is rate-limited!
        let anon_req = UdpProbeRequest {
            device_id: ANONYMOUS_DEVICE_ID.into(),
            nonce: *b"ann00004",
        };
        attacker_sock
            .send_to(&anon_req.encode().unwrap(), server_addr)
            .await
            .unwrap();
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(2), attacker_sock.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            UdpProbeResponse::decode(&buf[..n]).unwrap().nonce,
            *b"ann00004"
        );

        // 5th packet from same IP exceeds udp_rate_limit_max (4) -> dropped!
        attacker_sock
            .send_to(&anon_req.encode().unwrap(), server_addr)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(80), attacker_sock.recv_from(&mut buf))
                .await
                .is_err(),
            "UDP probe exceeding per-IP rate limit must be dropped"
        );

        drop(victim_client);
        hub.shutdown_all().await;
        let _ = victim_task.await;
        let _ = udp_task.await;
    }

    struct SlowUdpEphemeralStore {
        inner: MemoryEphemeralStore,
        udp_delay: Duration,
    }

    #[async_trait::async_trait]
    impl EphemeralStore for SlowUdpEphemeralStore {
        async fn set_online(&self, device_id: &str, ttl: Duration) -> Result<(), EphemeralError> {
            self.inner.set_online(device_id, ttl).await
        }
        async fn remove_online(&self, device_id: &str) -> Result<(), EphemeralError> {
            self.inner.remove_online(device_id).await
        }
        async fn is_online(&self, device_id: &str) -> Result<bool, EphemeralError> {
            self.inner.is_online(device_id).await
        }
        async fn online_ids(&self) -> Result<Vec<String>, EphemeralError> {
            self.inner.online_ids().await
        }
        async fn set_public_udp(
            &self,
            device_id: &str,
            addr: SocketAddr,
            ttl: Duration,
        ) -> Result<(), EphemeralError> {
            tokio::time::sleep(self.udp_delay).await;
            self.inner.set_public_udp(device_id, addr, ttl).await
        }
        async fn get_public_udp(
            &self,
            device_id: &str,
        ) -> Result<Option<SocketAddr>, EphemeralError> {
            self.inner.get_public_udp(device_id).await
        }
        async fn get_public_udp_all(
            &self,
            device_id: &str,
        ) -> Result<Vec<SocketAddr>, EphemeralError> {
            self.inner.get_public_udp_all(device_id).await
        }
        async fn put_relay_token(
            &self,
            token: &str,
            record: RelayTokenRecord,
            ttl: Duration,
        ) -> Result<(), EphemeralError> {
            self.inner.put_relay_token(token, record, ttl).await
        }
        async fn take_relay_token(
            &self,
            token: &str,
        ) -> Result<Option<RelayTokenRecord>, EphemeralError> {
            self.inner.take_relay_token(token).await
        }
        fn backend_name(&self) -> &'static str {
            "slow-udp-memory"
        }
        async fn health_check(&self) -> Result<(), EphemeralError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn m5_ipv4_mapped_ipv6_canonicalized_and_slow_backend_does_not_block_udp() {
        // 1. Canonicalization of IPv4-mapped IPv6 addresses in helper & RCSA wire encoding.
        let mapped: SocketAddr = "[::ffff:203.0.113.42]:54321".parse().unwrap();
        let expected_v4: SocketAddr = "203.0.113.42:54321".parse().unwrap();
        assert_eq!(canonical_socket_addr(mapped), expected_v4);

        let encoded = UdpProbeResponse {
            observed_addr: mapped,
            nonce: *b"12345678",
        }
        .encode();
        assert_eq!(
            encoded.len(),
            20,
            "IPv4-mapped IPv6 must encode as 20B IPv4"
        );
        let decoded = UdpProbeResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.observed_addr, expected_v4);

        // 2. Slow ephemeral backend must NEVER head-of-line block UDP RCSA replies.
        let store = Arc::new(MemoryDeviceStore::new());
        let slow_ephemeral = Arc::new(SlowUdpEphemeralStore {
            inner: MemoryEphemeralStore::new(),
            udp_delay: Duration::from_secs(2),
        });
        let hub = Arc::new(SignalHub::new(
            store,
            slow_ephemeral,
            SignalConfig::default(),
        ));

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let tcp_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(tcp_listener));
        let (sig, device_id) = register_peer_helper(tcp_addr, "ed25519:m5-slow", vec![]).await;

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let udp_task = tokio::spawn(hub.clone().serve_udp_probe_on_socket(server_sock));

        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let started = Instant::now();
        let mut buf = [0u8; 64];
        for i in 0u8..5 {
            let req = UdpProbeRequest {
                device_id: device_id.clone(),
                nonce: [i; 8],
            };
            client_sock
                .send_to(&req.encode().unwrap(), server_addr)
                .await
                .unwrap();
            let (n, _) =
                tokio::time::timeout(Duration::from_millis(200), client_sock.recv_from(&mut buf))
                    .await
                    .expect("RCSA must not be head-of-line blocked by slow ephemeral store")
                    .unwrap();
            assert_eq!(UdpProbeResponse::decode(&buf[..n]).unwrap().nonce, [i; 8]);
        }
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "5 RCSA roundtrips should complete rapidly without waiting for 2s backend delay"
        );

        drop(sig);
        hub.shutdown_all().await;
        let _ = udp_task.await;
        let _ = tcp_task.await;
    }

    #[tokio::test]
    async fn h5_oversized_fields_rejected_without_kicking_victim_and_writer_skips_bad_frames() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store,
            ephemeral.clone(),
            SignalConfig::default(),
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        // 1. Register with oversized hostname / NUL in os / >16 lan_addrs is rejected.
        for bad_reg in [
            SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:bad-host".into(),
                hostname: "h".repeat(MAX_HOSTNAME_LEN + 1),
                os: "linux".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
            SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:bad-os".into(),
                hostname: "ok".into(),
                os: "lin\0ux".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
            SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:bad-lan".into(),
                hostname: "ok".into(),
                os: "linux".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec!["10.0.0.1:5000".into(); MAX_LAN_ADDRS + 1],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        ] {
            let mut s = TcpStream::connect(tcp_addr).await.unwrap();
            write_signal_frame(&mut s, &bad_reg).await.unwrap();
            assert!(matches!(
                read_signal_frame(&mut s).await.unwrap().unwrap(),
                SignalMsg::Error { code, .. } if code == "invalid_payload"
            ));
        }

        // 2. Register victim and attacker.
        let (mut victim, victim_id) =
            register_peer_helper(tcp_addr, "ed25519:h5-victim", vec!["10.0.0.2:5000".into()]).await;
        let (mut attacker, _) = register_peer_helper(tcp_addr, "ed25519:h5-attacker", vec![]).await;

        // Attacker sends oversized/control-char ConnectRequest & RelayAlloc payloads.
        for bad_msg in [
            SignalMsg::ConnectRequest {
                target_id: victim_id.clone(),
                session_id: Some("a".repeat(MAX_SESSION_ID_LEN + 1)),
                lan_addrs: vec![],
                nonce: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
            SignalMsg::ConnectRequest {
                target_id: victim_id.clone(),
                session_id: Some("bad\nsess".into()),
                lan_addrs: vec![],
                nonce: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
            SignalMsg::ConnectRequest {
                target_id: victim_id.clone(),
                session_id: Some("ok-sess".into()),
                lan_addrs: vec![],
                nonce: Some("n".repeat(MAX_NONCE_LEN + 1)),
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
            SignalMsg::ConnectRequest {
                target_id: victim_id.clone(),
                session_id: Some("ok-sess".into()),
                lan_addrs: vec!["10.0.0.9:5000".into(); MAX_LAN_ADDRS + 1],
                nonce: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
            SignalMsg::ConnectRequest {
                target_id: victim_id.clone(),
                session_id: Some("ok-sess".into()),
                lan_addrs: vec!["x".repeat(MAX_LAN_ADDR_LEN + 1)],
                nonce: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
            SignalMsg::RelayAlloc {
                target_id: victim_id.clone(),
                session_id: Some("r".repeat(MAX_SESSION_ID_LEN + 1)),
                takeover: false,
            },
        ] {
            write_signal_frame(&mut attacker, &bad_msg).await.unwrap();
            assert!(matches!(
                read_signal_frame(&mut attacker).await.unwrap().unwrap(),
                SignalMsg::Error { code, .. } if code == "invalid_payload"
            ));
        }
        assert_eq!(ephemeral.active_token_count(), 0);

        // 3. Directly enqueue an oversized frame (>64 KiB) to victim's channel to prove the
        // writer task logs and skips SignalError::FrameTooLarge WITHOUT kicking the victim!
        {
            let victim_tx = hub.peers.get(&victim_id).unwrap().tx.clone();
            victim_tx
                .try_send(SignalMsg::Error {
                    code: "oversized_test".into(),
                    message: "Z".repeat(MAX_SIGNAL_FRAME_LEN + 1024),
                })
                .unwrap();
        }

        // Victim must remain connected and receive a normal HeartbeatAck!
        write_signal_frame(
            &mut victim,
            &SignalMsg::Heartbeat {
                lan_addrs: vec![],
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rtt_ms: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), read_signal_frame(&mut victim))
                .await
                .expect("victim must stay alive after writer skips oversized frame")
                .unwrap()
                .unwrap(),
            SignalMsg::HeartbeatAck { .. }
        ));
        assert!(hub.is_peer_connected(&victim_id));

        drop(victim);
        drop(attacker);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn h6_rate_limit_token_cap_and_failed_delivery_token_cleanup() {
        // Sub-case A: Per-peer rate limit on ConnectRequest & RelayAlloc.
        {
            let store = Arc::new(MemoryDeviceStore::new());
            let ephemeral = Arc::new(MemoryEphemeralStore::new());
            let hub = Arc::new(SignalHub::new(
                store,
                ephemeral.clone(),
                SignalConfig {
                    connect_rate_limit_max: 2,
                    connect_rate_limit_window: Duration::from_secs(10),
                    ..SignalConfig::default()
                },
            ));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let tcp_addr = listener.local_addr().unwrap();
            let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

            let (mut host, host_id) =
                register_peer_helper(tcp_addr, "ed25519:rl-host", vec![]).await;
            let (mut client, _) = register_peer_helper(tcp_addr, "ed25519:rl-client", vec![]).await;

            // Request 1 (ConnectRequest) -> succeeds.
            write_signal_frame(
                &mut client,
                &SignalMsg::ConnectRequest {
                    target_id: host_id.clone(),
                    session_id: Some("s1".into()),
                    lan_addrs: vec![],
                    nonce: None,
                    nat_type: None,
                    nat_port_delta: None,
                    nat_port_range: None,
                    takeover: false,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                read_signal_frame(&mut client).await.unwrap().unwrap(),
                SignalMsg::PunchCoord { .. }
            ));
            assert!(matches!(
                read_signal_frame(&mut host).await.unwrap().unwrap(),
                SignalMsg::PunchCoord { .. }
            ));

            // Request 2 (RelayAlloc) -> succeeds.
            write_signal_frame(
                &mut client,
                &SignalMsg::RelayAlloc {
                    target_id: host_id.clone(),
                    session_id: Some("s2".into()),
                    takeover: false,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                read_signal_frame(&mut client).await.unwrap().unwrap(),
                SignalMsg::RelayReady { .. }
            ));
            assert!(matches!(
                read_signal_frame(&mut host).await.unwrap().unwrap(),
                SignalMsg::RelayReady { .. }
            ));
            assert_eq!(ephemeral.active_token_count(), 2);

            // Request 3 -> rejected with rate_limited and NO token allocated!
            write_signal_frame(
                &mut client,
                &SignalMsg::RelayAlloc {
                    target_id: host_id.clone(),
                    session_id: Some("s3".into()),
                    takeover: false,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                read_signal_frame(&mut client).await.unwrap().unwrap(),
                SignalMsg::Error { code, .. } if code == "rate_limited"
            ));
            assert_eq!(ephemeral.active_token_count(), 2);

            drop(host);
            drop(client);
            hub.shutdown_all().await;
            let _ = server_task.await;
        }

        // Sub-case B: Global active relay token cap enforced in SignalHub & MemoryEphemeralStore.
        {
            let store = Arc::new(MemoryDeviceStore::new());
            let ephemeral = Arc::new(MemoryEphemeralStore::with_max_relay_tokens(2));
            let hub = Arc::new(SignalHub::new(
                store,
                ephemeral.clone(),
                SignalConfig {
                    max_relay_tokens: 2,
                    connect_rate_limit_max: 20,
                    ..SignalConfig::default()
                },
            ));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let tcp_addr = listener.local_addr().unwrap();
            let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

            let (mut host, host_id) =
                register_peer_helper(tcp_addr, "ed25519:cap-host", vec![]).await;
            let (mut client, _) =
                register_peer_helper(tcp_addr, "ed25519:cap-client", vec![]).await;

            for i in 1..=2 {
                write_signal_frame(
                    &mut client,
                    &SignalMsg::RelayAlloc {
                        target_id: host_id.clone(),
                        session_id: Some(format!("cap-{i}")),
                        takeover: false,
                    },
                )
                .await
                .unwrap();
                assert!(matches!(
                    read_signal_frame(&mut client).await.unwrap().unwrap(),
                    SignalMsg::RelayReady { .. }
                ));
                assert!(matches!(
                    read_signal_frame(&mut host).await.unwrap().unwrap(),
                    SignalMsg::RelayReady { .. }
                ));
            }
            assert_eq!(ephemeral.active_token_count(), 2);

            // 3rd request hits max_relay_tokens = 2.
            write_signal_frame(
                &mut client,
                &SignalMsg::RelayAlloc {
                    target_id: host_id.clone(),
                    session_id: Some("cap-3".into()),
                    takeover: false,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                read_signal_frame(&mut client).await.unwrap().unwrap(),
                SignalMsg::Error { code, .. } if code == "relay_capacity_exceeded"
            ));
            assert_eq!(ephemeral.active_token_count(), 2);

            drop(host);
            drop(client);
            hub.shutdown_all().await;
            let _ = server_task.await;
        }

        // Sub-case C: Failed delivery to host_tx immediately deletes the allocated relay token!
        {
            let store = Arc::new(MemoryDeviceStore::new());
            let ephemeral = Arc::new(MemoryEphemeralStore::new());
            let hub = Arc::new(SignalHub::new(
                store,
                ephemeral.clone(),
                SignalConfig {
                    channel_capacity: 1,
                    ..SignalConfig::default()
                },
            ));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let tcp_addr = listener.local_addr().unwrap();
            let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

            let (mut client, _) = register_peer_helper(tcp_addr, "ed25519:fd-client", vec![]).await;

            // Insert a synthetic host peer whose mpsc channel (cap 1) is permanently full
            // (receiver kept alive and never drained) to deterministically trigger TrySendError::Full.
            let (full_tx, _hold_rx) = mpsc::channel::<SignalMsg>(1);
            full_tx
                .try_send(SignalMsg::Heartbeat {
                    lan_addrs: vec![],
                    mac_addr: None,
                    wol_enabled: None,
                    nat_type: None,
                    nat_port_delta: None,
                    nat_port_range: None,
                    rtt_ms: None,
                })
                .unwrap();
            let full_host_id = "888777666".to_string();
            hub.peers.insert(
                full_host_id.clone(),
                ActivePeer {
                    conn_id: 999_999,
                    tx: full_tx,
                    cancel: PeerCancel::new(),
                    lan_addrs: vec![],
                    remote_addr: "127.0.0.1:50000".parse().unwrap(),
                    connected_at: Utc::now(),
                    owner_user_id: None,
                    device_pubkey: String::new(),
                    allow_remote_assist: false,
                    allow_remote_control: true,
                    wol_capable: false,
                    hostname: String::new(),
                    alias: String::new(),
                    os: String::new(),
                    app_version: String::new(),
                    arch: String::new(),
                    cpu_model: String::new(),
                    mac_address: String::new(),
                    total_memory_mb: 0,
                    os_version: String::new(),
                    gpu_model: String::new(),
                    udp_probe_token: None,
                    nat_type: None,
                    nat_port_delta: None,
                    nat_port_range: None,
                    smoothed_rtt_ms: None,
                    rcp2_v2: false,
                    active_controllers: Vec::new(),
                },
            );

            // ConnectRequest fails to deliver PunchCoord to full_host -> token must be deleted!
            write_signal_frame(
                &mut client,
                &SignalMsg::ConnectRequest {
                    target_id: full_host_id.clone(),
                    session_id: Some("full-punch".into()),
                    lan_addrs: vec![],
                    nonce: None,
                    nat_type: None,
                    nat_port_delta: None,
                    nat_port_range: None,
                    takeover: false,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                read_signal_frame(&mut client).await.unwrap().unwrap(),
                SignalMsg::Error { code, .. } if code == "peer_busy"
            ));
            assert_eq!(
                ephemeral.active_token_count(),
                0,
                "failed PunchCoord delivery must delete allocated relay token"
            );

            // RelayAlloc fails to deliver RelayReady to full_host -> token must be deleted!
            write_signal_frame(
                &mut client,
                &SignalMsg::RelayAlloc {
                    target_id: full_host_id.clone(),
                    session_id: Some("full-relay".into()),
                    takeover: false,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                read_signal_frame(&mut client).await.unwrap().unwrap(),
                SignalMsg::Error { code, .. } if code == "peer_busy"
            ));
            assert_eq!(
                ephemeral.active_token_count(),
                0,
                "failed RelayReady delivery must delete allocated relay token"
            );

            // Closed host_tx -> returns PeerOffline and deletes allocated relay token!
            drop(_hold_rx);
            write_signal_frame(
                &mut client,
                &SignalMsg::RelayAlloc {
                    target_id: full_host_id.clone(),
                    session_id: Some("closed-relay".into()),
                    takeover: false,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                read_signal_frame(&mut client).await.unwrap().unwrap(),
                SignalMsg::PeerOffline { target_id, session_id }
                    if target_id == full_host_id && session_id == "closed-relay"
            ));
            assert_eq!(
                ephemeral.active_token_count(),
                0,
                "closed-peer RelayReady delivery must delete allocated relay token"
            );

            hub.peers.remove(&full_host_id);
            drop(client);
            hub.shutdown_all().await;
            let _ = server_task.await;
        }
    }

    #[tokio::test]
    async fn h7_max_connections_and_incremental_truncated_frame_read() {
        // 1. Incremental payload read rejects truncated 64 KiB frame cleanly without over-allocating.
        let mut wire = (MAX_SIGNAL_FRAME_LEN as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(b"{\"type\":\"");
        let mut cursor = std::io::Cursor::new(wire);
        let err = read_signal_frame(&mut cursor).await.unwrap_err();
        assert!(matches!(err, SignalError::InvalidFrame(_)));

        // 2. Semaphore bounds concurrent TCP signaling connections.
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store,
            ephemeral,
            SignalConfig {
                max_connections: 2,
                ..SignalConfig::default()
            },
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        let (c1, _) = register_peer_helper(tcp_addr, "ed25519:h7-1", vec![]).await;
        let (c2, _) = register_peer_helper(tcp_addr, "ed25519:h7-2", vec![]).await;

        // 3rd connection cannot complete handshake while 2 permits are held.
        let mut c3 = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut c3,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:h7-3".into(),
                hostname: "h7-3".into(),
                os: "linux".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: "".into(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(80), read_signal_frame(&mut c3))
                .await
                .is_err(),
            "3rd connection must wait while max_connections=2 permits are held"
        );

        // Dropping c1 frees a permit so c3 registers immediately.
        drop(c1);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), read_signal_frame(&mut c3))
                .await
                .expect("3rd connection must succeed once a permit is released")
                .unwrap()
                .unwrap(),
            SignalMsg::Registered { .. }
        ));

        drop(c2);
        drop(c3);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn m4_concurrent_register_disable_and_kick_maintains_consistency() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store.clone(),
            ephemeral.clone(),
            SignalConfig::default(),
        ));

        let rec = store
            .register_or_get(RegisterInput {
                device_key: "ed25519:m4-storm".into(),
                hostname: "storm".into(),
                os: "linux".into(),
                app_version: String::new(),
                arch: String::new(),
                device_group: "".into(),
                ..Default::default()
            })
            .await
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        // 1. Concurrent register & kick storm on the same device_id.
        let mut handles = Vec::new();
        for _ in 0..12 {
            let id = rec.device_id.clone();
            handles.push(tokio::spawn(async move {
                let mut s = TcpStream::connect(tcp_addr).await.unwrap();
                let _ = write_signal_frame(
                    &mut s,
                    &SignalMsg::Register {
                        device_id: Some(id),
                        device_key: "ed25519:m4-storm".into(),
                        hostname: "storm".into(),
                        os: "linux".into(),
                        app_version: String::new(),
                        arch: String::new(),
                        cpu_model: String::new(),
                        mac_address: String::new(),
                        total_memory_mb: 0,
                        os_version: String::new(),
                        gpu_model: String::new(),
                        device_group: "".into(),
                        lan_addrs: vec![],
                        access_token: None,
                        device_pubkey: None,
                        allow_remote_assist: None,
                        allow_remote_control: None,
                        mac_addr: None,
                        wol_enabled: None,
                        nat_type: None,
                        nat_port_delta: None,
                        nat_port_range: None,
                        rcp2_v2: false,
                    },
                )
                .await;
                let _ = read_signal_frame(&mut s).await;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }));
            let hub_k = hub.clone();
            let id_k = rec.device_id.clone();
            handles.push(tokio::spawn(async move {
                let _ = hub_k.kick_device(&id_k, "storm_kick").await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        // Wait briefly for all disconnect cleanups to finish, then check invariant.
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(
            hub.is_peer_connected(&rec.device_id),
            ephemeral.is_online(&rec.device_id).await.unwrap(),
            "peers map and ephemeral online state must remain consistent after storm"
        );

        // 2. Concurrent disable + kick vs reconnect must NEVER leave a disabled device online.
        let disable_task = tokio::spawn({
            let store = store.clone();
            let hub = hub.clone();
            let id = rec.device_id.clone();
            async move {
                store.set_disabled(&id, true).await.unwrap();
                hub.kick_device(&id, "disabled_by_admin").await;
            }
        });
        let mut reg_tasks = Vec::new();
        for _ in 0..8 {
            let id = rec.device_id.clone();
            reg_tasks.push(tokio::spawn(async move {
                let mut s = TcpStream::connect(tcp_addr).await.unwrap();
                let _ = write_signal_frame(
                    &mut s,
                    &SignalMsg::Register {
                        device_id: Some(id),
                        device_key: "ed25519:m4-storm".into(),
                        hostname: "storm".into(),
                        os: "linux".into(),
                        app_version: String::new(),
                        arch: String::new(),
                        cpu_model: String::new(),
                        mac_address: String::new(),
                        total_memory_mb: 0,
                        os_version: String::new(),
                        gpu_model: String::new(),
                        device_group: "".into(),
                        lan_addrs: vec![],
                        access_token: None,
                        device_pubkey: None,
                        allow_remote_assist: None,
                        allow_remote_control: None,
                        mac_addr: None,
                        wol_enabled: None,
                        nat_type: None,
                        nat_port_delta: None,
                        nat_port_range: None,
                        rcp2_v2: false,
                    },
                )
                .await;
                let _ = read_signal_frame(&mut s).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }));
        }
        disable_task.await.unwrap();
        for t in reg_tasks {
            t.await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!hub.is_peer_connected(&rec.device_id));
        assert!(!ephemeral.is_online(&rec.device_id).await.unwrap());

        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn l5_default_online_ttl_exceeds_idle_timeout_and_activity_refreshes_ttl() {
        let default_cfg = SignalConfig::default();
        assert_eq!(default_cfg.online_ttl, Duration::from_secs(150));
        assert!(
            default_cfg.online_ttl > default_cfg.read_idle_timeout,
            "default online_ttl ({:?}) must exceed read_idle_timeout ({:?})",
            default_cfg.online_ttl,
            default_cfg.read_idle_timeout
        );

        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store,
            ephemeral.clone(),
            SignalConfig {
                online_ttl: Duration::from_millis(120),
                read_idle_timeout: Duration::from_secs(10),
                ..SignalConfig::default()
            },
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        let (mut client, client_id) =
            register_peer_helper(tcp_addr, "ed25519:l5-activity", vec![]).await;
        assert!(ephemeral.is_online(&client_id).await.unwrap());

        // Sleep past half of online_ttl, then perform authenticated non-heartbeat activity.
        tokio::time::sleep(Duration::from_millis(70)).await;
        write_signal_frame(
            &mut client,
            &SignalMsg::ConnectRequest {
                target_id: "999999999".into(),
                session_id: Some("l5-keepalive".into()),
                lan_addrs: vec![],
                nonce: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut client).await.unwrap().unwrap(),
            SignalMsg::PeerOffline { .. }
        ));

        // Total elapsed > 140ms > original 120ms TTL, yet device must remain online!
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert!(
            ephemeral.is_online(&client_id).await.unwrap(),
            "authenticated ConnectRequest activity must refresh online_ttl"
        );

        drop(client);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn h10_shutdown_all_kicks_peers_stops_listeners_and_drains_tasks() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store,
            ephemeral.clone(),
            SignalConfig::default(),
        ));

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let udp_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let tcp_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(tcp_listener));
        let udp_task = tokio::spawn(hub.clone().serve_udp_probe_on_socket(udp_sock));

        // One authenticated peer + one idle unauthenticated pre-auth TCP peer.
        let (mut peer, peer_id) = register_peer_helper(tcp_addr, "ed25519:h10-peer", vec![]).await;
        let _idle_pre_auth = TcpStream::connect(tcp_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(hub.in_flight_task_count() >= 2);

        tokio::time::timeout(Duration::from_secs(2), hub.shutdown_all())
            .await
            .expect("shutdown_all must complete promptly");

        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), read_signal_frame(&mut peer))
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            SignalMsg::Kicked { reason } if reason == "server_shutdown"
        ));
        assert_eq!(read_signal_frame(&mut peer).await.unwrap(), None);

        tokio::time::timeout(Duration::from_secs(2), tcp_task)
            .await
            .expect("TCP signaling listener must exit on shutdown_all")
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), udp_task)
            .await
            .expect("UDP probe listener must exit on shutdown_all")
            .unwrap()
            .unwrap();

        assert_eq!(hub.in_flight_task_count(), 0);
        assert_eq!(hub.online_count(), 0);
        assert!(!ephemeral.is_online(&peer_id).await.unwrap());
    }

    #[tokio::test]
    async fn memory_ephemeral_does_not_leak_issued_relay_tokens_and_os_len_matches_store() {
        assert_eq!(MAX_OS_LEN, crate::store::MAX_OS_LEN);
        assert_eq!(MAX_OS_LEN, 128);
        assert_eq!(MAX_APP_VERSION_LEN, crate::store::MAX_APP_VERSION_LEN);
        assert_eq!(MAX_ARCH_LEN, crate::store::MAX_ARCH_LEN);
        let long_os = "o".repeat(128);
        let long_ver = "1".repeat(33);
        let long_arch = "a".repeat(33);
        validate_register_fields(RegisterMetadataFields {
            hostname: "host",
            os: &long_os,
            app_version: "0.1.10",
            arch: "arm64",
            cpu_model: "",
            mac_address: "",
            total_memory_mb: 0,
            os_version: "",
            gpu_model: "",
            device_group: "grp",
            lan_addrs: &[],
        })
        .unwrap();
        assert!(validate_register_fields(RegisterMetadataFields {
            hostname: "host",
            os: "macos",
            app_version: &long_ver,
            arch: "arm64",
            cpu_model: "",
            mac_address: "",
            total_memory_mb: 0,
            os_version: "",
            gpu_model: "",
            device_group: "grp",
            lan_addrs: &[],
        })
        .is_err());
        assert!(validate_register_fields(RegisterMetadataFields {
            hostname: "host",
            os: "macos",
            app_version: "0.1.10",
            arch: &long_arch,
            cpu_model: "",
            mac_address: "",
            total_memory_mb: 0,
            os_version: "",
            gpu_model: "",
            device_group: "grp",
            lan_addrs: &[],
        })
        .is_err());

        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(store, ephemeral, SignalConfig::default()));

        for i in 0..8 {
            hub.allocate_relay_token(
                &format!("tok-{i}"),
                RelayTokenRecord {
                    session_id: format!("sess-{i}"),
                    host_id: "100000001".to_string(),
                    client_id: "100000002".to_string(),
                },
            )
            .await
            .unwrap();
        }
        assert_eq!(
            hub.issued_relay_tokens.len(),
            0,
            "MemoryEphemeralStore reports exact counts so fallback issued_relay_tokens must not accumulate"
        );
    }

    #[test]
    fn legacy_wire_frames_without_allow_remote_control_deserialize_cleanly() {
        let reg_json = br#"{"type":"register","device_key":"ed25519:legacy-k","hostname":"old-box","os":"macos","allow_remote_assist":false}"#;
        let reg: SignalMsg = serde_json::from_slice(reg_json).unwrap();
        assert!(matches!(
            reg,
            SignalMsg::Register {
                allow_remote_assist: Some(false),
                allow_remote_control: None,
                ..
            }
        ));

        let upd_json = br#"{"type":"update_assist_state","allow_remote_assist":true}"#;
        let upd: SignalMsg = serde_json::from_slice(upd_json).unwrap();
        assert_eq!(
            upd,
            SignalMsg::UpdateAssistState {
                allow_remote_assist: Some(true),
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                cpu_model: None,
                mac_address: None,
                total_memory_mb: None,
                os_version: None,
                gpu_model: None,
            }
        );

        let upd_rc_only_json = br#"{"type":"update_assist_state","allow_remote_control":false}"#;
        let upd_rc_only: SignalMsg = serde_json::from_slice(upd_rc_only_json).unwrap();
        assert_eq!(
            upd_rc_only,
            SignalMsg::UpdateAssistState {
                allow_remote_assist: None,
                allow_remote_control: Some(false),
                mac_addr: None,
                wol_enabled: None,
                cpu_model: None,
                mac_address: None,
                total_memory_mb: None,
                os_version: None,
                gpu_model: None,
            }
        );

        let upd_full_json =
            br#"{"type":"update_assist_state","allow_remote_assist":false,"allow_remote_control":true}"#;
        let upd_full: SignalMsg = serde_json::from_slice(upd_full_json).unwrap();
        assert_eq!(
            upd_full,
            SignalMsg::UpdateAssistState {
                allow_remote_assist: Some(false),
                allow_remote_control: Some(true),
                mac_addr: None,
                wol_enabled: None,
                cpu_model: None,
                mac_address: None,
                total_memory_mb: None,
                os_version: None,
                gpu_model: None,
            }
        );

        let status_json = br#"{"type":"device_status_changed","device_id":"123456789","online":true,"hostname":"h","alias":"","os":"macos","allow_remote_assist":false}"#;
        let status: SignalMsg = serde_json::from_slice(status_json).unwrap();
        assert!(matches!(
            status,
            SignalMsg::DeviceStatusChanged {
                allow_remote_assist: false,
                allow_remote_control: true,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn anonymous_no_auth_mode_still_blocks_remote_control_disabled_and_partial_update_preserves_assist(
    ) {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        // Legacy constructor forces `require_auth = false`.
        let hub = Arc::new(SignalHub::new(
            store.clone(),
            ephemeral.clone(),
            SignalConfig::default(),
        ));
        assert!(!hub.config().require_auth);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        // 1. Register anonymous desktop client and anonymous Android host (allow_remote_control defaults to false).
        let (mut desktop, _) = register_peer_helper(tcp_addr, "ed25519:anon-desktop", vec![]).await;

        let mut android = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut android,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:anon-android".into(),
                hostname: "Pixel-Anon".into(),
                os: "Android 15".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: Some(true),
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let android_id = match read_signal_frame(&mut android).await.unwrap().unwrap() {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered for android, got {other:?}"),
        };
        let android_rec = store.get_by_id(&android_id).await.unwrap().unwrap();
        assert!(android_rec.allow_remote_assist);
        assert!(!android_rec.allow_remote_control);

        // Even with require_auth == false and both peers anonymous, ConnectRequest & RelayAlloc MUST be rejected!
        write_signal_frame(
            &mut desktop,
            &SignalMsg::ConnectRequest {
                target_id: android_id.clone(),
                session_id: Some("anon-blocked-punch".into()),
                lan_addrs: vec![],
                nonce: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut desktop).await.unwrap().unwrap(),
            SignalMsg::Error { ref code, .. } if code == "remote_control_disabled"
        ));
        assert_eq!(ephemeral.active_token_count(), 0);

        write_signal_frame(
            &mut desktop,
            &SignalMsg::RelayAlloc {
                target_id: android_id.clone(),
                session_id: Some("anon-blocked-relay".into()),
                takeover: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut desktop).await.unwrap().unwrap(),
            SignalMsg::Error { ref code, .. } if code == "remote_control_disabled"
        ));
        assert_eq!(ephemeral.active_token_count(), 0);

        // Synthetic in-peers-only target (no DB row) with allow_remote_control = false MUST also be rejected!
        let (synth_tx, _synth_rx) = mpsc::channel::<SignalMsg>(4);
        let synth_id = "777666555".to_string();
        hub.peers.insert(
            synth_id.clone(),
            ActivePeer {
                conn_id: 777_777,
                tx: synth_tx,
                cancel: PeerCancel::new(),
                lan_addrs: vec![],
                remote_addr: "127.0.0.1:50000".parse().unwrap(),
                connected_at: Utc::now(),
                owner_user_id: None,
                device_pubkey: String::new(),
                allow_remote_assist: true,
                allow_remote_control: false,
                wol_capable: false,
                hostname: "synth".into(),
                alias: String::new(),
                os: "android".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                udp_probe_token: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                smoothed_rtt_ms: None,
                rcp2_v2: false,
                active_controllers: Vec::new(),
            },
        );
        write_signal_frame(
            &mut desktop,
            &SignalMsg::ConnectRequest {
                target_id: synth_id.clone(),
                session_id: Some("synth-blocked".into()),
                lan_addrs: vec![],
                nonce: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut desktop).await.unwrap().unwrap(),
            SignalMsg::Error { ref code, .. } if code == "remote_control_disabled"
        ));
        hub.peers.remove(&synth_id);

        // 2. Partial UpdateAssistState with ONLY allow_remote_control=Some(true) (allow_remote_assist omitted)
        //    must preserve existing allow_remote_assist=true without overwriting it!
        write_signal_frame(
            &mut android,
            &SignalMsg::UpdateAssistState {
                allow_remote_assist: None,
                allow_remote_control: Some(true),
                mac_addr: None,
                wol_enabled: None,
                cpu_model: None,
                mac_address: None,
                total_memory_mb: None,
                os_version: None,
                gpu_model: None,
            },
        )
        .await
        .unwrap();
        // Wait briefly for server loop to persist, then verify via ConnectRequest + DB.
        tokio::time::sleep(Duration::from_millis(30)).await;
        let after_enable = store.get_by_id(&android_id).await.unwrap().unwrap();
        assert!(after_enable.allow_remote_control);
        assert!(
            after_enable.allow_remote_assist,
            "omitting allow_remote_assist must preserve existing true value"
        );

        // Now turn off allow_remote_control ONLY (allow_remote_assist omitted) -> assist stays true, rc becomes false!
        write_signal_frame(
            &mut android,
            &SignalMsg::UpdateAssistState {
                allow_remote_assist: None,
                allow_remote_control: Some(false),
                mac_addr: None,
                wol_enabled: None,
                cpu_model: None,
                mac_address: None,
                total_memory_mb: None,
                os_version: None,
                gpu_model: None,
            },
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let after_disable = store.get_by_id(&android_id).await.unwrap().unwrap();
        assert!(!after_disable.allow_remote_control);
        assert!(
            after_disable.allow_remote_assist,
            "partial UpdateAssistState with only allow_remote_control=Some(false) must not overwrite allow_remote_assist"
        );

        // Empty UpdateAssistState (both None) returns invalid_payload error.
        write_signal_frame(
            &mut android,
            &SignalMsg::UpdateAssistState {
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                cpu_model: None,
                mac_address: None,
                total_memory_mb: None,
                os_version: None,
                gpu_model: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut android).await.unwrap().unwrap(),
            SignalMsg::Error { ref code, .. } if code == "invalid_payload"
        ));

        drop(desktop);
        drop(android);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[test]
    fn all_signal_emitted_wire_codes_exist_in_spec() {
        use crate::generated::error_codes;

        // Every SignalMsg::Error.code and SignalMsg::Kicked.reason emitted by signal.rs,
        // paired with its legacy snake_case string to enforce 100% wire compatibility.
        let emitted: &[(&str, &str)] = &[
            (err_code::ACCOUNT_DISABLED, "account_disabled"),
            (err_code::ALREADY_REGISTERED, "already_registered"),
            (err_code::ASSIST_DISABLED, "assist_disabled"),
            (err_code::DEVICE_DISABLED, "device_disabled"),
            (err_code::DEVICE_ID_MISMATCH, "device_id_mismatch"),
            (err_code::DEVICE_NOT_FOUND, "device_not_found"),
            (err_code::DEVICE_UNBOUND, "device_unbound"),
            (err_code::EXPECTED_REGISTER, "expected_register"),
            (err_code::FORBIDDEN, "forbidden"),
            (err_code::FRAME_TOO_LARGE, "frame_too_large"),
            (err_code::HANDSHAKE_TIMEOUT, "handshake_timeout"),
            (err_code::INTERNAL_ERROR, "internal_error"),
            (err_code::INVALID_FRAME, "invalid_frame"),
            (err_code::INVALID_INPUT, "invalid_input"),
            (err_code::INVALID_PAYLOAD, "invalid_payload"),
            (
                err_code::PASSWORD_CHANGE_REQUIRED,
                "password_change_required",
            ),
            (err_code::PEER_BUSY, "peer_busy"),
            (err_code::PEER_DISABLED, "peer_disabled"),
            (err_code::PEER_NOT_FOUND, "peer_not_found"),
            (err_code::RATE_LIMITED, "rate_limited"),
            (err_code::REGISTER_FAILED, "register_failed"),
            (err_code::RELAY_CAPACITY_EXCEEDED, "relay_capacity_exceeded"),
            (err_code::RELAY_TOKEN_ERROR, "relay_token_error"),
            (err_code::REMOTE_CONTROL_DISABLED, "remote_control_disabled"),
            (
                err_code::REPLACED_BY_NEW_CONNECTION,
                "replaced_by_new_connection",
            ),
            (err_code::SELF_CONNECT, "self_connect"),
            (err_code::SERVER_MISCONFIGURED, "server_misconfigured"),
            (err_code::SERVER_SHUTDOWN, "server_shutdown"),
            (err_code::SERVICE_UNAVAILABLE, "service_unavailable"),
            (err_code::TARGET_IN_SESSION, "target_in_session"),
            (err_code::TOKEN_EXPIRED, "token_expired"),
            (err_code::TOKEN_REVOKED, "token_revoked"),
            (err_code::UNAUTHORIZED, "unauthorized"),
            (err_code::UNEXPECTED_MESSAGE, "unexpected_message"),
            (err_code::UPDATE_FAILED, "update_failed"),
            (err_code::WOL_DISABLED, "wol_disabled"),
            (err_code::WOL_NO_RELAY_PEER, "wol_no_relay_peer"),
            (err_code::WOL_SEND_FAILED, "wol_send_failed"),
        ];

        for &(constant, expected_wire) in emitted {
            assert_eq!(
                constant, expected_wire,
                "wire code drift for {expected_wire}"
            );
            assert!(
                error_codes::WIRE_ALIAS_MAP
                    .iter()
                    .any(|&(alias, _)| alias == constant),
                "signaling wire code {constant} missing from WIRE_ALIAS_MAP"
            );
            assert!(
                error_codes::canonical_for_wire(constant).is_some(),
                "signaling wire code {constant} failed canonical_for_wire lookup"
            );
        }

        // Verify JSON serialization format of Error and Kicked frames stays backward compatible.
        let err_json = serde_json::to_value(SignalMsg::Error {
            code: err_code::REMOTE_CONTROL_DISABLED.into(),
            message: "对方未开启允许远程控制".into(),
        })
        .unwrap();
        assert_eq!(err_json["type"], "error");
        assert_eq!(err_json["code"], "remote_control_disabled");
        assert_eq!(err_json["message"], "对方未开启允许远程控制");

        let kicked_json = serde_json::to_value(SignalMsg::Kicked {
            reason: err_code::REPLACED_BY_NEW_CONNECTION.into(),
        })
        .unwrap();
        assert_eq!(kicked_json["type"], "kicked");
        assert_eq!(kicked_json["reason"], "replaced_by_new_connection");
    }

    #[test]
    fn wol_magic_packet_102b_format_and_broadcast_targets() {
        let pkt = build_wol_magic_packet("AA-BB-CC-DD-EE-FF").expect("valid unicast MAC");
        assert_eq!(pkt.len(), 102);
        assert_eq!(&pkt[0..6], &[0xFF; 6]);
        let expected_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        for i in 0..16 {
            let start = 6 + i * 6;
            assert_eq!(&pkt[start..start + 6], &expected_mac);
        }

        assert!(build_wol_magic_packet("00:00:00:00:00:00").is_none());
        assert!(build_wol_magic_packet("ff:ff:ff:ff:ff:ff").is_none());
        assert!(build_wol_magic_packet("01:00:5e:00:00:01").is_none());
        assert!(build_wol_magic_packet("not-a-mac").is_none());

        let targets = wol_broadcast_targets(&[
            "192.168.1.20:50000".into(),
            "192.168.1.44:50001".into(),
            "10.20.30.40".into(),
            "8.8.8.8:50000".into(),
            "127.0.0.1:50000".into(),
        ]);
        assert_eq!(
            targets,
            vec![
                "192.168.1.255:9".parse().unwrap(),
                "10.20.30.255:9".parse().unwrap(),
                "255.255.255.255:9".parse().unwrap(),
            ]
        );

        assert!(share_private_ipv4_slash24(
            &["192.168.50.10:50000".into()],
            &["192.168.50.99:40000".into()]
        ));
        assert!(!share_private_ipv4_slash24(
            &["192.168.50.10:50000".into()],
            &["192.168.51.10:50000".into()]
        ));
        assert!(!share_private_ipv4_slash24(
            &["8.8.8.1:50000".into()],
            &["8.8.8.2:50000".into()]
        ));

        // Legacy client frames without WoL fields deserialize cleanly.
        let legacy_reg: SignalMsg = serde_json::from_str(
            r#"{"type":"register","device_key":"dk-legacy","hostname":"old-host","os":"macos"}"#,
        )
        .unwrap();
        assert!(matches!(
            legacy_reg,
            SignalMsg::Register {
                mac_addr: None,
                wol_enabled: None,
                ..
            }
        ));
        let legacy_hb: SignalMsg =
            serde_json::from_str(r#"{"type":"heartbeat","lan_addrs":["192.168.1.2:50000"]}"#)
                .unwrap();
        assert!(matches!(
            legacy_hb,
            SignalMsg::Heartbeat {
                mac_addr: None,
                wol_enabled: None,
                ..
            }
        ));

        // DeviceStatusChanged includes wol_capable and never exposes mac_addr.
        let status_json = serde_json::to_string(&SignalMsg::DeviceStatusChanged {
            device_id: "123456789".into(),
            online: true,
            hostname: "host".into(),
            alias: String::new(),
            os: "macos".into(),
            app_version: String::new(),
            arch: String::new(),
            cpu_model: String::new(),
            mac_address: String::new(),
            total_memory_mb: 0,
            os_version: String::new(),
            gpu_model: String::new(),
            allow_remote_assist: false,
            allow_remote_control: true,
            wol_capable: true,
        })
        .unwrap();
        assert!(status_json.contains("\"wol_capable\":true"));
        assert!(!status_json.contains("mac_addr"));
    }

    async fn create_test_authed_user(
        store: &Arc<MemoryDeviceStore>,
        auth_authority: &Arc<AuthAuthority>,
        email: &str,
    ) -> (Uuid, String) {
        use crate::auth::ACCESS_TOKEN_TTL;
        use crate::store::{CreateSessionInput, CreateUserInput, UserStore, ROLE_USER};

        let user = store
            .create_user(CreateUserInput {
                email: email.into(),
                display_name: email.into(),
                password_hash: "hash".into(),
                role: ROLE_USER.into(),
                status: STATUS_ACTIVE.into(),
                must_change_password: false,
            })
            .await
            .unwrap();
        let sess = store
            .create_user_session(CreateSessionInput {
                user_id: user.id,
                device_id: None,
                family_id: None,
                token_hash: format!("{:064x}", user.id.as_u128()),
                expires_at: Utc::now() + chrono::Duration::hours(24),
                client_info: "test".into(),
            })
            .await
            .unwrap();
        let token = auth_authority
            .issue_access_token_for_user(&user, sess.id, None, ACCESS_TOKEN_TTL)
            .unwrap();
        (user.id, token)
    }

    #[tokio::test]
    async fn wol_signaling_auth_cross_account_disabled_online_and_rate_limit() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let auth_authority = Arc::new(AuthAuthority::load_or_create(store.as_ref()).await.unwrap());

        let (_alice_id, alice_token) =
            create_test_authed_user(&store, &auth_authority, "alice-wol@example.com").await;
        let (_bob_id, bob_token) =
            create_test_authed_user(&store, &auth_authority, "bob-wol@example.com").await;

        // First verify unauthenticated peer (require_auth=false) is strictly rejected with unauthorized.
        let anon_cfg = SignalConfig {
            require_auth: false,
            ..SignalConfig::default()
        };
        let anon_hub = Arc::new(SignalHub::with_auth(
            store.clone(),
            ephemeral.clone(),
            auth_authority.clone(),
            anon_cfg,
        ));
        let anon_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let anon_addr = anon_listener.local_addr().unwrap();
        let anon_task = tokio::spawn(
            anon_hub
                .clone()
                .serve_tcp_signaling_on_listener(anon_listener),
        );

        let mut anon_stream = TcpStream::connect(anon_addr).await.unwrap();
        write_signal_frame(
            &mut anon_stream,
            &SignalMsg::Register {
                device_id: None,
                device_key: "dk-anon-wol".into(),
                hostname: "anon".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut anon_stream).await.unwrap().unwrap(),
            SignalMsg::Registered { .. }
        ));
        write_signal_frame(
            &mut anon_stream,
            &SignalMsg::WolRequest {
                request_id: Some("unauth-1".into()),
                target_device_id: "123456789".into(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut anon_stream).await.unwrap().unwrap(),
            SignalMsg::WolAck {
                request_id: Some(ref rid),
                ok: false,
                ref method,
                code: Some(ref c),
                ..
            } if rid == "unauth-1" && method == WOL_METHOD_NONE && c == err_code::UNAUTHORIZED
        ));
        drop(anon_stream);
        anon_hub.shutdown_all().await;
        let _ = anon_task.await;

        // Authenticated hub for cross-account, wol_disabled, already_online, and 5s rate limit.
        assert_eq!(
            SignalConfig::default().wol_rate_limit_window,
            Duration::from_secs(5)
        );
        let hub = Arc::new(SignalHub::with_auth(
            store.clone(),
            ephemeral.clone(),
            auth_authority.clone(),
            SignalConfig::default(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        let mut alice_caller = TcpStream::connect(addr).await.unwrap();
        write_signal_frame(
            &mut alice_caller,
            &SignalMsg::Register {
                device_id: None,
                device_key: "dk-alice-caller".into(),
                hostname: "alice-laptop".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec!["192.168.1.10:50000".into()],
                access_token: Some(alice_token.clone()),
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut alice_caller).await.unwrap().unwrap(),
            SignalMsg::Registered { .. }
        ));

        let mut alice_target = TcpStream::connect(addr).await.unwrap();
        write_signal_frame(
            &mut alice_target,
            &SignalMsg::Register {
                device_id: None,
                device_key: "dk-alice-target".into(),
                hostname: "alice-studio".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec!["192.168.1.20:50000".into()],
                access_token: Some(alice_token.clone()),
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: Some("AA-BB-CC-DD-EE-FF".into()),
                wol_enabled: Some(false),
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let target_id = match read_signal_frame(&mut alice_target).await.unwrap().unwrap() {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered, got {other:?}"),
        };
        // Consume DeviceStatusChanged pushed to alice_caller (wol_capable=false)
        assert!(matches!(
            read_signal_frame(&mut alice_caller).await.unwrap().unwrap(),
            SignalMsg::DeviceStatusChanged {
                ref device_id,
                wol_capable: false,
                ..
            } if device_id == &target_id
        ));

        let mut bob_caller = TcpStream::connect(addr).await.unwrap();
        write_signal_frame(
            &mut bob_caller,
            &SignalMsg::Register {
                device_id: None,
                device_key: "dk-bob-caller".into(),
                hostname: "bob-laptop".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec!["192.168.1.30:50000".into()],
                access_token: Some(bob_token),
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut bob_caller).await.unwrap().unwrap(),
            SignalMsg::Registered { .. }
        ));

        // 1. Cross-account attempt by Bob is rejected with forbidden (and does NOT consume Alice's rate limit).
        write_signal_frame(
            &mut bob_caller,
            &SignalMsg::WolRequest {
                request_id: Some("cross-1".into()),
                target_device_id: target_id.clone(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut bob_caller).await.unwrap().unwrap(),
            SignalMsg::WolAck {
                request_id: Some(ref rid),
                ok: false,
                ref method,
                code: Some(ref c),
                ..
            } if rid == "cross-1" && method == WOL_METHOD_NONE && c == err_code::FORBIDDEN
        ));

        // 2. Non-existent target returns device_not_found; invalid ID returns invalid_input.
        write_signal_frame(
            &mut alice_caller,
            &SignalMsg::WolRequest {
                request_id: Some("missing-1".into()),
                target_device_id: "999999999".into(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut alice_caller).await.unwrap().unwrap(),
            SignalMsg::WolAck {
                ok: false,
                ref method,
                code: Some(ref c),
                ..
            } if method == WOL_METHOD_NONE && c == err_code::DEVICE_NOT_FOUND
        ));

        write_signal_frame(
            &mut alice_caller,
            &SignalMsg::WolRequest {
                request_id: Some("bad-id".into()),
                target_device_id: "abc".into(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut alice_caller).await.unwrap().unwrap(),
            SignalMsg::WolAck {
                ok: false,
                ref method,
                code: Some(ref c),
                ..
            } if method == WOL_METHOD_NONE && c == err_code::INVALID_INPUT
        ));

        // 3. Target has wol_enabled = false -> returns wol_disabled.
        write_signal_frame(
            &mut alice_caller,
            &SignalMsg::WolRequest {
                request_id: Some("dis-1".into()),
                target_device_id: target_id.clone(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut alice_caller).await.unwrap().unwrap(),
            SignalMsg::WolAck {
                ok: false,
                ref method,
                code: Some(ref c),
                ..
            } if method == WOL_METHOD_NONE && c == err_code::WOL_DISABLED
        ));

        // 4. Enable WoL via UpdateAssistState -> broadcast wol_capable=true to alice_caller.
        write_signal_frame(
            &mut alice_target,
            &SignalMsg::UpdateAssistState {
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: Some(true),
                cpu_model: None,
                mac_address: None,
                total_memory_mb: None,
                os_version: None,
                gpu_model: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut alice_caller).await.unwrap().unwrap(),
            SignalMsg::DeviceStatusChanged {
                ref device_id,
                wol_capable: true,
                ..
            } if device_id == &target_id
        ));

        // 5. Immediate request within 5s window -> rate_limited!
        write_signal_frame(
            &mut alice_caller,
            &SignalMsg::WolRequest {
                request_id: Some("rl-1".into()),
                target_device_id: target_id.clone(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut alice_caller).await.unwrap().unwrap(),
            SignalMsg::WolAck {
                ok: false,
                ref method,
                code: Some(ref c),
                ..
            } if method == WOL_METHOD_NONE && c == err_code::RATE_LIMITED
        ));

        // Clear rate-limit bucket for target to deterministically verify already_online on same target.
        hub.wol_rate_limits.remove(&target_id);

        // 6. Target is online with wol_enabled = true -> returns already_online!
        write_signal_frame(
            &mut alice_caller,
            &SignalMsg::WolRequest {
                request_id: Some("online-1".into()),
                target_device_id: target_id.clone(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut alice_caller).await.unwrap().unwrap(),
            SignalMsg::WolAck {
                request_id: Some(ref rid),
                ok: true,
                ref method,
                code: None,
                ..
            } if rid == "online-1" && method == WOL_METHOD_ALREADY_ONLINE
        ));

        drop(alice_caller);
        drop(alice_target);
        drop(bob_caller);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn wol_signaling_lan_peer_relay_and_no_relay_peer() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let auth_authority = Arc::new(AuthAuthority::load_or_create(store.as_ref()).await.unwrap());

        let (alice_id, alice_token) =
            create_test_authed_user(&store, &auth_authority, "alice-relay@example.com").await;
        let (_bob_id, bob_token) =
            create_test_authed_user(&store, &auth_authority, "bob-relay@example.com").await;

        let hub = Arc::new(SignalHub::with_auth(
            store.clone(),
            ephemeral.clone(),
            auth_authority.clone(),
            SignalConfig::default(), // allow_server_wol = false
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        // Create two offline target devices owned by Alice with distinct WAN IPs & private /24 LANs.
        let target_no_peer = store
            .register_or_get(RegisterInput {
                device_key: "dk-wol-offline-1".into(),
                hostname: "home-box-1".into(),
                os: "macos".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .bind_device_to_user(&target_no_peer.device_id, alice_id, None, None)
            .await
            .unwrap();
        store
            .update_device_wol_state(
                &target_no_peer.device_id,
                Some(alice_id),
                Some("02:11:22:33:44:55"),
                Some(true),
                Some(&["192.168.50.20:50000".into()]),
                Some("203.0.113.50"),
            )
            .await
            .unwrap();

        let target_with_peer = store
            .register_or_get(RegisterInput {
                device_key: "dk-wol-offline-2".into(),
                hostname: "home-box-2".into(),
                os: "macos".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .bind_device_to_user(&target_with_peer.device_id, alice_id, None, None)
            .await
            .unwrap();
        store
            .update_device_wol_state(
                &target_with_peer.device_id,
                Some(alice_id),
                Some("AA-BB-CC-DD-EE-FF"),
                Some(true),
                Some(&["192.168.60.20:50000".into()]),
                Some("203.0.113.60"),
            )
            .await
            .unwrap();

        // Connect Alice's caller (remote WAN/different subnet).
        let mut alice_caller = TcpStream::connect(addr).await.unwrap();
        write_signal_frame(
            &mut alice_caller,
            &SignalMsg::Register {
                device_id: None,
                device_key: "dk-alice-mobile".into(),
                hostname: "alice-phone".into(),
                os: "ios".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec!["10.99.0.5:50000".into()],
                access_token: Some(alice_token.clone()),
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut alice_caller).await.unwrap().unwrap(),
            SignalMsg::Registered { .. }
        ));

        // Connect Bob's peer on 192.168.50.0/24 (different account -> MUST NOT be chosen!).
        let mut bob_peer = TcpStream::connect(addr).await.unwrap();
        write_signal_frame(
            &mut bob_peer,
            &SignalMsg::Register {
                device_id: None,
                device_key: "dk-bob-lan".into(),
                hostname: "bob-mini".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec!["192.168.50.99:50000".into()],
                access_token: Some(bob_token),
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut bob_peer).await.unwrap().unwrap(),
            SignalMsg::Registered { .. }
        ));

        // Connect Alice's helper peer on 192.168.60.0/24 (matches target_with_peer, NOT target_no_peer).
        let mut alice_helper = TcpStream::connect(addr).await.unwrap();
        write_signal_frame(
            &mut alice_helper,
            &SignalMsg::Register {
                device_id: None,
                device_key: "dk-alice-helper".into(),
                hostname: "alice-mini".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec!["192.168.60.88:50000".into()],
                access_token: Some(alice_token),
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut alice_helper).await.unwrap().unwrap(),
            SignalMsg::Registered { .. }
        ));
        // Drain DeviceStatusChanged sent to alice_caller when alice_helper joined.
        assert!(matches!(
            read_signal_frame(&mut alice_caller).await.unwrap().unwrap(),
            SignalMsg::DeviceStatusChanged { .. }
        ));

        // Case 1: target_no_peer has no eligible same-account LAN peer -> wol_no_relay_peer!
        write_signal_frame(
            &mut alice_caller,
            &SignalMsg::WolRequest {
                request_id: Some("nopeer-1".into()),
                target_device_id: target_no_peer.device_id.clone(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut alice_caller).await.unwrap().unwrap(),
            SignalMsg::WolAck {
                request_id: Some(ref rid),
                ok: false,
                ref method,
                code: Some(ref c),
                ..
            } if rid == "nopeer-1" && method == WOL_METHOD_NONE && c == err_code::WOL_NO_RELAY_PEER
        ));

        // Case 2: target_with_peer matches alice_helper on 192.168.60.0/24 -> WolRelay + WolAck(lan_peer)!
        write_signal_frame(
            &mut alice_caller,
            &SignalMsg::WolRequest {
                request_id: Some("relay-42".into()),
                target_device_id: target_with_peer.device_id.clone(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut alice_caller).await.unwrap().unwrap(),
            SignalMsg::WolAck {
                request_id: Some(ref rid),
                ref target_device_id,
                ok: true,
                ref method,
                code: None,
                ..
            } if rid == "relay-42"
                && target_device_id == &target_with_peer.device_id
                && method == WOL_METHOD_LAN_PEER
        ));
        assert!(matches!(
            read_signal_frame(&mut alice_helper).await.unwrap().unwrap(),
            SignalMsg::WolRelay {
                ref request_id,
                ref target_device_id,
                ref mac_addr,
                ref target_lan_addrs,
            } if request_id == "relay-42"
                && target_device_id == &target_with_peer.device_id
                && mac_addr == "aa:bb:cc:dd:ee:ff"
                && target_lan_addrs == &vec!["192.168.60.20:50000".to_string()]
        ));

        drop(alice_caller);
        drop(alice_helper);
        drop(bob_peer);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[test]
    fn wol_relay_scoring_rejects_cross_site_public_ip_overlap_and_prioritizes_same_public_ip() {
        let home_pub = "203.0.113.10";
        let home_lan = vec!["192.168.1.20:50000".to_string()];

        // 1. Different routable public IP (office) with identical 192.168.1.0/24 MUST be rejected (score = 0)!
        assert_eq!(
            score_wol_relay_candidate(
                home_pub,
                &home_lan,
                "198.51.100.77".parse().unwrap(),
                &["192.168.1.35:50000".into()],
            ),
            0,
            "cross-site peer with different public IP must never match on RFC1918 /24 overlap"
        );

        // 2. Same public IP AND same /24 -> highest priority (3).
        let score_both = score_wol_relay_candidate(
            home_pub,
            &home_lan,
            "203.0.113.10".parse().unwrap(),
            &["192.168.1.50:50000".into()],
        );
        // 3. Same public IP without /24 match -> priority 2 (strictly beats pure /24 fallback).
        let score_pub_only = score_wol_relay_candidate(
            home_pub,
            &home_lan,
            "203.0.113.10".parse().unwrap(),
            &["10.0.0.5:50000".into()],
        );
        // 4. Pure /24 fallback when either side is private/loopback or last_public_ip is empty -> priority 1.
        let score_lan_fallback_loopback = score_wol_relay_candidate(
            home_pub,
            &home_lan,
            "127.0.0.1".parse().unwrap(),
            &["192.168.1.99:50000".into()],
        );
        let score_lan_fallback_empty_pub = score_wol_relay_candidate(
            "",
            &home_lan,
            "198.51.100.77".parse().unwrap(),
            &["192.168.1.99:50000".into()],
        );
        let score_lan_fallback_private_server = score_wol_relay_candidate(
            "192.168.1.20",
            &home_lan,
            "192.168.1.50".parse().unwrap(),
            &["192.168.1.50:50000".into()],
        );

        assert_eq!(score_both, 3);
        assert_eq!(score_pub_only, 2);
        assert_eq!(score_lan_fallback_loopback, 1);
        assert_eq!(score_lan_fallback_empty_pub, 1);
        assert_eq!(score_lan_fallback_private_server, 1);
        assert!(score_both > score_pub_only);
        assert!(score_pub_only > score_lan_fallback_loopback);
    }

    #[tokio::test]
    async fn wol_regressions_anon_heartbeat_protection_caller_rate_limit_and_empty_mac_update() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let auth_authority = Arc::new(AuthAuthority::load_or_create(store.as_ref()).await.unwrap());

        let (alice_id, alice_token) =
            create_test_authed_user(&store, &auth_authority, "alice-reg@example.com").await;

        // 1. Bound device with WoL state must NEVER be polluted by unauthenticated Heartbeat (require_auth=false).
        let bound_dev = store
            .register_or_get(RegisterInput {
                device_key: "dk-bound-victim".into(),
                hostname: "victim".into(),
                os: "macos".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .bind_device_to_user(&bound_dev.device_id, alice_id, None, None)
            .await
            .unwrap();
        store
            .update_device_wol_state(
                &bound_dev.device_id,
                Some(alice_id),
                Some("aa:bb:cc:dd:ee:ff"),
                Some(true),
                Some(&["192.168.88.10:50000".into()]),
                Some("203.0.113.88"),
            )
            .await
            .unwrap();

        let anon_hub = Arc::new(SignalHub::with_auth(
            store.clone(),
            ephemeral.clone(),
            auth_authority.clone(),
            SignalConfig {
                require_auth: false,
                ..SignalConfig::default()
            },
        ));
        let anon_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let anon_addr = anon_listener.local_addr().unwrap();
        let anon_task = tokio::spawn(
            anon_hub
                .clone()
                .serve_tcp_signaling_on_listener(anon_listener),
        );

        let mut anon_conn = TcpStream::connect(anon_addr).await.unwrap();
        write_signal_frame(
            &mut anon_conn,
            &SignalMsg::Register {
                device_id: Some(bound_dev.device_id.clone()),
                device_key: "dk-bound-victim".into(),
                hostname: "victim".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec!["10.66.66.66:50000".into()],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: Some("02:66:66:66:66:66".into()),
                wol_enabled: Some(false),
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut anon_conn).await.unwrap().unwrap(),
            SignalMsg::Registered { .. }
        ));
        // Send anonymous Heartbeat attempting to poison LAN addrs, public IP, MAC, and wol_enabled.
        write_signal_frame(
            &mut anon_conn,
            &SignalMsg::Heartbeat {
                lan_addrs: vec!["10.77.77.77:50000".into()],
                mac_addr: Some("02:77:77:77:77:77".into()),
                wol_enabled: Some(false),
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rtt_ms: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut anon_conn).await.unwrap().unwrap(),
            SignalMsg::HeartbeatAck { .. }
        ));
        // Verify stored WoL + network topology is 100% untouched!
        let after_anon = store
            .get_by_id(&bound_dev.device_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_anon.mac_addr.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert!(after_anon.wol_enabled);
        assert_eq!(
            after_anon.last_lan_addrs,
            vec!["192.168.88.10:50000".to_string()]
        );
        assert_eq!(after_anon.last_public_ip, "203.0.113.88");

        drop(anon_conn);
        anon_hub.shutdown_all().await;
        let _ = anon_task.await;

        // 2. Per-caller WoL rate limit blocks rapid device ID enumeration BEFORE DB lookup,
        //    AND UpdateAssistState with only empty mac_addr returns invalid_payload.
        let hub = Arc::new(SignalHub::with_auth(
            store.clone(),
            ephemeral.clone(),
            auth_authority.clone(),
            SignalConfig {
                wol_caller_rate_limit_max: 2,
                wol_caller_rate_limit_window: Duration::from_secs(10),
                ..SignalConfig::default()
            },
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        let mut caller = TcpStream::connect(addr).await.unwrap();
        write_signal_frame(
            &mut caller,
            &SignalMsg::Register {
                device_id: None,
                device_key: "dk-enum-caller".into(),
                hostname: "caller".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec!["192.168.1.10:50000".into()],
                access_token: Some(alice_token),
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut caller).await.unwrap().unwrap(),
            SignalMsg::Registered { .. }
        ));

        // UpdateAssistState with only empty mac_addr must return invalid_payload.
        write_signal_frame(
            &mut caller,
            &SignalMsg::UpdateAssistState {
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: Some("   ".into()),
                wol_enabled: None,
                cpu_model: None,
                mac_address: None,
                total_memory_mb: None,
                os_version: None,
                gpu_model: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut caller).await.unwrap().unwrap(),
            SignalMsg::Error { ref code, .. } if code == err_code::INVALID_PAYLOAD
        ));

        // 2 distinct missing targets consume the per-caller limit (max = 2), 3rd returns rate_limited!
        for (idx, target) in ["111111111", "222222222"].iter().enumerate() {
            write_signal_frame(
                &mut caller,
                &SignalMsg::WolRequest {
                    request_id: Some(format!("enum-{idx}")),
                    target_device_id: (*target).into(),
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                read_signal_frame(&mut caller).await.unwrap().unwrap(),
                SignalMsg::WolAck {
                    ok: false,
                    code: Some(ref c),
                    ..
                } if c == err_code::DEVICE_NOT_FOUND
            ));
        }

        write_signal_frame(
            &mut caller,
            &SignalMsg::WolRequest {
                request_id: Some("enum-3".into()),
                target_device_id: "333333333".into(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut caller).await.unwrap().unwrap(),
            SignalMsg::WolAck {
                request_id: Some(ref rid),
                ok: false,
                ref method,
                code: Some(ref c),
                ..
            } if rid == "enum-3" && method == WOL_METHOD_NONE && c == err_code::RATE_LIMITED
        ));

        // 3. Cross-site online peer with distinct public IP and overlapping 192.168.88.0/24
        //    must NOT be picked for WoL relay (returns wol_no_relay_peer)!
        hub.wol_caller_rate_limits.clear();
        let (office_tx, mut office_rx) = mpsc::channel::<SignalMsg>(8);
        hub.peers.insert(
            "444555666".to_string(),
            ActivePeer {
                conn_id: 444_555,
                tx: office_tx,
                cancel: PeerCancel::new(),
                lan_addrs: vec!["192.168.88.55:50000".into()],
                remote_addr: "198.51.100.77:55555".parse().unwrap(),
                connected_at: Utc::now(),
                owner_user_id: Some(alice_id),
                device_pubkey: String::new(),
                allow_remote_assist: false,
                allow_remote_control: true,
                wol_capable: false,
                hostname: "office-pc".into(),
                alias: String::new(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                udp_probe_token: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                smoothed_rtt_ms: None,
                rcp2_v2: false,
                active_controllers: Vec::new(),
            },
        );
        write_signal_frame(
            &mut caller,
            &SignalMsg::WolRequest {
                request_id: Some("cross-site-1".into()),
                target_device_id: bound_dev.device_id.clone(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut caller).await.unwrap().unwrap(),
            SignalMsg::WolAck {
                request_id: Some(ref rid),
                ok: false,
                ref method,
                code: Some(ref c),
                ..
            } if rid == "cross-site-1"
                && method == WOL_METHOD_NONE
                && c == err_code::WOL_NO_RELAY_PEER
        ));
        assert!(
            office_rx.try_recv().is_err(),
            "cross-site office peer must never receive WolRelay"
        );
        hub.peers.remove("444555666");

        drop(caller);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[test]
    fn rcsp_v1_and_v2_codec_and_constant_time_eq() {
        let req_v1 = UdpProbeRequest {
            device_id: "123456789".into(),
            nonce: *b"nonce001",
        };
        let enc_v1 = req_v1.encode().unwrap();
        assert_eq!(enc_v1.len(), UDP_PROBE_LEN);
        assert_eq!(enc_v1[4], UDP_PROTO_VERSION);
        assert_eq!(
            DecodedUdpProbe::decode(&enc_v1).unwrap(),
            DecodedUdpProbe::V1(req_v1.clone())
        );

        let token = [0xABu8; UDP_PROBE_TOKEN_LEN];
        let req_v2 = UdpProbeRequestV2 {
            device_id: "987654321".into(),
            nonce: *b"nonce002",
            token,
        };
        let enc_v2 = req_v2.encode().unwrap();
        assert_eq!(enc_v2.len(), UDP_PROBE_V2_LEN);
        assert_eq!(enc_v2[4], UDP_PROTO_VERSION_V2);
        assert_eq!(&enc_v2[22..38], &token);
        assert_eq!(UdpProbeRequestV2::decode(&enc_v2).unwrap(), req_v2);
        assert_eq!(
            DecodedUdpProbe::decode(&enc_v2).unwrap(),
            DecodedUdpProbe::V2(req_v2.clone())
        );

        // Wrong lengths or unknown versions must fail.
        assert!(UdpProbeRequest::decode(&enc_v2).is_err());
        assert!(UdpProbeRequestV2::decode(&enc_v1).is_err());
        let mut bad_ver = enc_v2;
        bad_ver[4] = 0x03;
        assert!(DecodedUdpProbe::decode(&bad_ver).is_err());
        assert!(DecodedUdpProbe::decode(&enc_v2[..37]).is_err());

        // Constant-time byte comparison.
        assert!(constant_time_eq_bytes(&token, &[0xABu8; 16]));
        let mut diff_token = token;
        diff_token[15] ^= 0x01;
        assert!(!constant_time_eq_bytes(&token, &diff_token));
        assert!(!constant_time_eq_bytes(&token, &[0xABu8; 15]));
    }

    #[tokio::test]
    async fn rcsp_v2_cross_ip_token_verification_and_alt_port_no_overwrite() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());

        let primary_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let primary_addr = primary_udp.local_addr().unwrap();
        let alt_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let alt_addr = alt_udp.local_addr().unwrap();

        let hub = Arc::new(SignalHub::new(
            store,
            ephemeral.clone(),
            SignalConfig {
                public_udp_probe_addr: primary_addr.to_string(),
                public_udp_probe_alt_addr: Some(alt_addr.to_string()),
                ..SignalConfig::default()
            },
        ));

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let tcp_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(tcp_listener));
        let primary_task = tokio::spawn(hub.clone().serve_udp_probe_on_socket(primary_udp));
        let alt_task = tokio::spawn(hub.clone().serve_udp_probe_alt_on_socket(alt_udp));

        let mut sig = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut sig,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:v2-probe-key".into(),
                hostname: "v2-box".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: Some("Cone".into()),
                nat_port_delta: Some(0),
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();

        let (device_id, probe_token_hex) = match read_signal_frame(&mut sig).await.unwrap().unwrap()
        {
            SignalMsg::Registered {
                device_id,
                udp_probe_alt_addr,
                udp_probe_token,
                ..
            } => {
                assert_eq!(
                    udp_probe_alt_addr.as_deref(),
                    Some(alt_addr.to_string().as_str())
                );
                let tok = udp_probe_token.expect("udp_probe_token must be issued");
                assert_eq!(tok.len(), 32);
                assert!(tok
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
                (device_id, tok)
            }
            other => panic!("expected Registered, got {other:?}"),
        };
        let mut token_bytes = [0u8; UDP_PROBE_TOKEN_LEN];
        hex::decode_to_slice(&probe_token_hex, &mut token_bytes).unwrap();

        // Simulate TCP connection from a different public IP (multi-egress NAT / IPv6 TCP + IPv4 UDP).
        hub.peers.get_mut(&device_id).unwrap().remote_addr = "198.51.100.99:55555".parse().unwrap();

        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let mut buf = [0u8; 64];

        // 1. RCSP v1 from mismatched IP (127.0.0.1 != 198.51.100.99) replies RCSA but does NOT store.
        let v1_req = UdpProbeRequest {
            device_id: device_id.clone(),
            nonce: *b"v1mismat",
        };
        client_sock
            .send_to(&v1_req.encode().unwrap(), primary_addr)
            .await
            .unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let rcsa_v1 = UdpProbeResponse::decode(&buf[..n]).unwrap();
        assert_eq!(rcsa_v1.observed_addr, client_addr);
        assert_eq!(rcsa_v1.nonce, *b"v1mismat");
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(ephemeral.get_public_udp(&device_id).await.unwrap(), None);

        // 2. RCSP v2 with WRONG token replies RCSA but does NOT store.
        let mut wrong_token = token_bytes;
        wrong_token[0] ^= 0xFF;
        let bad_v2_req = UdpProbeRequestV2 {
            device_id: device_id.clone(),
            nonce: *b"v2wrongt",
            token: wrong_token,
        };
        client_sock
            .send_to(&bad_v2_req.encode().unwrap(), primary_addr)
            .await
            .unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            UdpProbeResponse::decode(&buf[..n]).unwrap().nonce,
            *b"v2wrongt"
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(ephemeral.get_public_udp(&device_id).await.unwrap(), None);

        // 3. RCSP v2 with CORRECT token succeeds even when TCP IP != UDP IP!
        let good_v2_req = UdpProbeRequestV2 {
            device_id: device_id.clone(),
            nonce: *b"v2goodok",
            token: token_bytes,
        };
        client_sock
            .send_to(&good_v2_req.encode().unwrap(), primary_addr)
            .await
            .unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let rcsa_v2 = UdpProbeResponse::decode(&buf[..n]).unwrap();
        assert_eq!(rcsa_v2.observed_addr, client_addr);
        assert_eq!(rcsa_v2.nonce, *b"v2goodok");

        let mut stored = None;
        for _ in 0..100 {
            stored = ephemeral.get_public_udp(&device_id).await.unwrap();
            if stored.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(stored, Some(client_addr));

        // 4. Secondary alt UDP port echoes RCSA from a distinct client socket/port but NEVER overwrites EphemeralStore!
        let alt_client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let alt_client_addr = alt_client_sock.local_addr().unwrap();
        assert_ne!(alt_client_addr, client_addr);
        let alt_req = UdpProbeRequestV2 {
            device_id: device_id.clone(),
            nonce: *b"altprobe",
            token: token_bytes,
        };
        alt_client_sock
            .send_to(&alt_req.encode().unwrap(), alt_addr)
            .await
            .unwrap();
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(2), alt_client_sock.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        let alt_resp = UdpProbeResponse::decode(&buf[..n]).unwrap();
        assert_eq!(alt_resp.observed_addr, alt_client_addr);
        assert_eq!(alt_resp.nonce, *b"altprobe");

        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(
            ephemeral.get_public_udp(&device_id).await.unwrap(),
            Some(client_addr)
        );
        assert_eq!(
            ephemeral.get_public_udp_all(&device_id).await.unwrap(),
            vec![client_addr]
        );

        drop(sig);
        hub.shutdown_all().await;
        let _ = primary_task.await;
        let _ = alt_task.await;
        let _ = tcp_task.await;
    }

    #[tokio::test]
    async fn dual_stack_udp_and_nat_fields_propagate_in_punch_coord() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store,
            ephemeral.clone(),
            SignalConfig::default(),
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        // Host registers with mixed-case nat_type="Symmetric_Seq" and nat_port_delta=3.
        let mut host = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut host,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:ds-host".into(),
                hostname: "ds-host".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec!["192.168.10.2:50000".into()],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: Some("Symmetric_Seq".into()),
                nat_port_delta: Some(3),
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let host_id = match read_signal_frame(&mut host).await.unwrap().unwrap() {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered for host, got {other:?}"),
        };

        // Client registers with invalid nat_type (ignored -> None) and oversized delta (clamped -> 1024).
        let mut client = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut client,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:ds-client".into(),
                hostname: "ds-client".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec!["192.168.20.2:50001".into()],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: Some("bogus_nat".into()),
                nat_port_delta: Some(9999),
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let client_id = match read_signal_frame(&mut client).await.unwrap().unwrap() {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered for client, got {other:?}"),
        };
        {
            let client_peer = hub.peers.get(&client_id).unwrap();
            assert_eq!(client_peer.nat_type, None);
            assert_eq!(client_peer.nat_port_delta, Some(NAT_PORT_DELTA_MAX));
        }

        // Client updates via Heartbeat to "CONE" / 0.
        write_signal_frame(
            &mut client,
            &SignalMsg::Heartbeat {
                lan_addrs: vec![],
                mac_addr: None,
                wol_enabled: None,
                nat_type: Some("CONE".into()),
                nat_port_delta: Some(0),
                nat_port_range: None,
                rtt_ms: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut client).await.unwrap().unwrap(),
            SignalMsg::HeartbeatAck { .. }
        ));

        // Seed dual-stack endpoints for host (v6 + v4) and single v4 for client.
        let host_v6: SocketAddr = "[2001:db8::20]:50002".parse().unwrap();
        let host_v4: SocketAddr = "198.51.100.20:50001".parse().unwrap();
        let client_v4: SocketAddr = "203.0.113.10:40001".parse().unwrap();
        ephemeral
            .set_public_udp(&host_id, host_v6, Duration::from_secs(60))
            .await
            .unwrap();
        ephemeral
            .set_public_udp(&host_id, host_v4, Duration::from_secs(60))
            .await
            .unwrap();
        ephemeral
            .set_public_udp(&client_id, client_v4, Duration::from_secs(60))
            .await
            .unwrap();

        // Client updates NAT profile in ConnectRequest (clamped to -1024).
        write_signal_frame(
            &mut client,
            &SignalMsg::ConnectRequest {
                target_id: host_id.clone(),
                session_id: Some("sess-ds-1".into()),
                lan_addrs: vec![],
                nonce: Some("dsnonce1".into()),
                nat_type: Some("symmetric_random".into()),
                nat_port_delta: Some(-5000),
                nat_port_range: None,
                takeover: false,
            },
        )
        .await
        .unwrap();

        let client_punch = read_signal_frame(&mut client).await.unwrap().unwrap();
        let host_punch = read_signal_frame(&mut host).await.unwrap().unwrap();

        match client_punch {
            SignalMsg::PunchCoord {
                peer_public_udp_addr,
                peer_public_udp_addrs,
                self_public_udp_addr,
                peer_nat_type,
                peer_nat_port_delta,
                ..
            } => {
                assert_eq!(peer_public_udp_addr.as_deref(), Some("198.51.100.20:50001"));
                assert_eq!(
                    peer_public_udp_addrs,
                    vec![
                        "[2001:db8::20]:50002".to_string(),
                        "198.51.100.20:50001".to_string()
                    ]
                );
                assert_eq!(self_public_udp_addr.as_deref(), Some("203.0.113.10:40001"));
                assert_eq!(peer_nat_type.as_deref(), Some("symmetric_seq"));
                assert_eq!(peer_nat_port_delta, Some(3));
            }
            other => panic!("expected PunchCoord for client, got {other:?}"),
        }

        match host_punch {
            SignalMsg::PunchCoord {
                peer_public_udp_addr,
                peer_public_udp_addrs,
                self_public_udp_addr,
                peer_nat_type,
                peer_nat_port_delta,
                ..
            } => {
                assert_eq!(peer_public_udp_addr.as_deref(), Some("203.0.113.10:40001"));
                assert_eq!(
                    peer_public_udp_addrs,
                    vec!["203.0.113.10:40001".to_string()]
                );
                assert_eq!(self_public_udp_addr.as_deref(), Some("198.51.100.20:50001"));
                assert_eq!(peer_nat_type.as_deref(), Some("symmetric_random"));
                assert_eq!(peer_nat_port_delta, Some(-1024));
            }
            other => panic!("expected PunchCoord for host, got {other:?}"),
        }

        drop(client);
        drop(host);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[test]
    fn legacy_json_without_p1_udp_fields_remains_compatible() {
        let legacy_register = br#"{"type":"register","device_key":"ed25519:old"}"#;
        let reg: SignalMsg = serde_json::from_slice(legacy_register).unwrap();
        assert!(matches!(
            reg,
            SignalMsg::Register {
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
                ..
            }
        ));

        let legacy_registered = br#"{"type":"registered","device_id":"123456789","formatted_id":"123 456 789","server_time":"2026-11-22T10:00:00Z","udp_probe_addr":"172.16.1.2:21116","relay_addr":"172.16.1.2:21117"}"#;
        let reg_ack: SignalMsg = serde_json::from_slice(legacy_registered).unwrap();
        assert!(matches!(
            reg_ack,
            SignalMsg::Registered {
                udp_probe_alt_addr: None,
                udp_probe_token: None,
                ..
            }
        ));

        let legacy_hb = br#"{"type":"heartbeat"}"#;
        let hb: SignalMsg = serde_json::from_slice(legacy_hb).unwrap();
        assert!(matches!(
            hb,
            SignalMsg::Heartbeat {
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rtt_ms: None,
                ..
            }
        ));

        let legacy_conn = br#"{"type":"connect_request","target_id":"987654321"}"#;
        let conn: SignalMsg = serde_json::from_slice(legacy_conn).unwrap();
        assert!(matches!(
            conn,
            SignalMsg::ConnectRequest {
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                ..
            }
        ));

        let legacy_punch = br#"{"type":"punch_coord","session_id":"s1","role":"client","peer_id":"987654321","peer_lan_addrs":[],"nonce":"n1","relay_token":"t1","relay_addr":"172.16.1.2:21117"}"#;
        let punch: SignalMsg = serde_json::from_slice(legacy_punch).unwrap();
        assert!(matches!(
            punch,
            SignalMsg::PunchCoord {
                ref peer_public_udp_addrs,
                self_public_udp_addr: None,
                peer_nat_type: None,
                peer_nat_port_delta: None,
                ..
            } if peer_public_udp_addrs.is_empty()
        ));

        let serialized = serde_json::to_string(&punch).unwrap();
        assert!(!serialized.contains("peer_public_udp_addrs"));
        assert!(!serialized.contains("self_public_udp_addr"));
        assert!(!serialized.contains("peer_nat_type"));
        assert!(!serialized.contains("peer_nat_port_delta"));
    }

    #[test]
    fn select_legacy_public_udp_pair_prefers_same_family_ipv4_and_fallbacks() {
        let a_v4: SocketAddr = "203.0.113.10:40001".parse().unwrap();
        let a_v6: SocketAddr = "[2001:db8::10]:40002".parse().unwrap();
        let b_v4: SocketAddr = "198.51.100.20:50001".parse().unwrap();
        let b_v6: SocketAddr = "[2001:db8::20]:50002".parse().unwrap();

        // Both have IPv4 in *_all even when fallback is IPv6 (e.g. IPv6 probed last).
        assert_eq!(
            select_legacy_public_udp_pair(&[a_v6, a_v4], Some(a_v6), &[b_v4], Some(b_v4)),
            (Some(a_v4.to_string()), Some(b_v4.to_string()))
        );

        // One side dual-stack, other side IPv6-only: IPv4 preferred where present, fallback/first otherwise.
        assert_eq!(
            select_legacy_public_udp_pair(&[a_v6, a_v4], Some(a_v6), &[b_v6], Some(b_v6)),
            (Some(a_v4.to_string()), Some(b_v6.to_string()))
        );

        // Empty *_all falls back to *_fallback; missing fallback falls back to *_all.first().
        assert_eq!(
            select_legacy_public_udp_pair(&[], Some(a_v4), &[b_v6], None),
            (Some(a_v4.to_string()), Some(b_v6.to_string()))
        );

        // Neither side has any endpoints.
        assert_eq!(
            select_legacy_public_udp_pair(&[], None, &[], None),
            (None, None)
        );
    }

    #[tokio::test]
    async fn rcsp_v2_ipv4_then_ipv6_keeps_legacy_punch_coord_ipv4_while_preserving_dual_stack_addrs(
    ) {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());

        let udp_v4 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let udp_v4_addr = udp_v4.local_addr().unwrap();
        let udp_v6 = Arc::new(UdpSocket::bind("[::1]:0").await.unwrap());
        let udp_v6_addr = udp_v6.local_addr().unwrap();

        let hub = Arc::new(SignalHub::new(
            store,
            ephemeral.clone(),
            SignalConfig {
                public_udp_probe_addr: udp_v4_addr.to_string(),
                ..SignalConfig::default()
            },
        ));

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let tcp_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(tcp_listener));
        let udp_v4_task = tokio::spawn(hub.clone().serve_udp_probe_on_socket(udp_v4));
        let udp_v6_task = tokio::spawn(hub.clone().serve_udp_probe_on_socket(udp_v6));

        // Peer A registers over TCP.
        let mut peer_a = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut peer_a,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:peer-a-dual".into(),
                hostname: "peer-a".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: Some("cone".into()),
                nat_port_delta: Some(0),
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let (peer_a_id, peer_a_tok_hex) =
            match read_signal_frame(&mut peer_a).await.unwrap().unwrap() {
                SignalMsg::Registered {
                    device_id,
                    udp_probe_token,
                    ..
                } => (
                    device_id,
                    udp_probe_token.expect("peer_a udp_probe_token must be issued"),
                ),
                other => panic!("expected Registered for peer A, got {other:?}"),
            };
        let mut peer_a_tok = [0u8; UDP_PROBE_TOKEN_LEN];
        hex::decode_to_slice(&peer_a_tok_hex, &mut peer_a_tok).unwrap();

        // Peer B registers over TCP.
        let mut peer_b = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut peer_b,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:peer-b-v4".into(),
                hostname: "peer-b".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: Some("cone".into()),
                nat_port_delta: Some(0),
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let (peer_b_id, peer_b_tok_hex) =
            match read_signal_frame(&mut peer_b).await.unwrap().unwrap() {
                SignalMsg::Registered {
                    device_id,
                    udp_probe_token,
                    ..
                } => (
                    device_id,
                    udp_probe_token.expect("peer_b udp_probe_token must be issued"),
                ),
                other => panic!("expected Registered for peer B, got {other:?}"),
            };
        let mut peer_b_tok = [0u8; UDP_PROBE_TOKEN_LEN];
        hex::decode_to_slice(&peer_b_tok_hex, &mut peer_b_tok).unwrap();

        let mut buf = [0u8; 64];

        // Peer A probes IPv4 FIRST via RCSP v2.
        let peer_a_v4_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_a_v4_addr = peer_a_v4_sock.local_addr().unwrap();
        let req_a_v4 = UdpProbeRequestV2 {
            device_id: peer_a_id.clone(),
            nonce: *b"peera_v4",
            token: peer_a_tok,
        };
        peer_a_v4_sock
            .send_to(&req_a_v4.encode().unwrap(), udp_v4_addr)
            .await
            .unwrap();
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(2), peer_a_v4_sock.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            UdpProbeResponse::decode(&buf[..n]).unwrap().observed_addr,
            peer_a_v4_addr
        );
        for _ in 0..100 {
            if ephemeral.get_public_udp(&peer_a_id).await.unwrap() == Some(peer_a_v4_addr) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            ephemeral.get_public_udp(&peer_a_id).await.unwrap(),
            Some(peer_a_v4_addr)
        );

        // Peer A probes IPv6 SECOND via RCSP v2 (so legacy get_public_udp becomes IPv6).
        let peer_a_v6_sock = UdpSocket::bind("[::1]:0").await.unwrap();
        let peer_a_v6_addr = peer_a_v6_sock.local_addr().unwrap();
        let req_a_v6 = UdpProbeRequestV2 {
            device_id: peer_a_id.clone(),
            nonce: *b"peera_v6",
            token: peer_a_tok,
        };
        peer_a_v6_sock
            .send_to(&req_a_v6.encode().unwrap(), udp_v6_addr)
            .await
            .unwrap();
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(2), peer_a_v6_sock.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            UdpProbeResponse::decode(&buf[..n]).unwrap().observed_addr,
            peer_a_v6_addr
        );
        for _ in 0..100 {
            if ephemeral.get_public_udp(&peer_a_id).await.unwrap() == Some(peer_a_v6_addr) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            ephemeral.get_public_udp(&peer_a_id).await.unwrap(),
            Some(peer_a_v6_addr)
        );

        // Peer B probes IPv4 ONLY via RCSP v2.
        let peer_b_v4_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_b_v4_addr = peer_b_v4_sock.local_addr().unwrap();
        let req_b_v4 = UdpProbeRequestV2 {
            device_id: peer_b_id.clone(),
            nonce: *b"peerb_v4",
            token: peer_b_tok,
        };
        peer_b_v4_sock
            .send_to(&req_b_v4.encode().unwrap(), udp_v4_addr)
            .await
            .unwrap();
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(2), peer_b_v4_sock.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            UdpProbeResponse::decode(&buf[..n]).unwrap().observed_addr,
            peer_b_v4_addr
        );
        for _ in 0..100 {
            if ephemeral.get_public_udp(&peer_b_id).await.unwrap() == Some(peer_b_v4_addr) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            ephemeral.get_public_udp(&peer_b_id).await.unwrap(),
            Some(peer_b_v4_addr)
        );

        // Peer B sends ConnectRequest to Peer A.
        write_signal_frame(
            &mut peer_b,
            &SignalMsg::ConnectRequest {
                target_id: peer_a_id.clone(),
                session_id: Some("sess-v4-v6-legacy".into()),
                lan_addrs: vec![],
                nonce: Some("v4v6nonce".into()),
                nat_type: Some("cone".into()),
                nat_port_delta: Some(0),
                nat_port_range: None,
                takeover: false,
            },
        )
        .await
        .unwrap();

        let peer_b_punch = read_signal_frame(&mut peer_b).await.unwrap().unwrap();
        let peer_a_punch = read_signal_frame(&mut peer_a).await.unwrap().unwrap();

        match peer_b_punch {
            SignalMsg::PunchCoord {
                peer_public_udp_addr,
                peer_public_udp_addrs,
                self_public_udp_addr,
                ..
            } => {
                assert_eq!(
                    peer_public_udp_addr.as_deref(),
                    Some(peer_a_v4_addr.to_string().as_str())
                );
                assert_eq!(
                    self_public_udp_addr.as_deref(),
                    Some(peer_b_v4_addr.to_string().as_str())
                );
                assert!(
                    peer_public_udp_addrs.contains(&peer_a_v6_addr.to_string())
                        && peer_public_udp_addrs.contains(&peer_a_v4_addr.to_string()),
                    "expected both IPv6 and IPv4 endpoints for Peer A, got {peer_public_udp_addrs:?}"
                );
                assert_eq!(peer_public_udp_addrs.len(), 2);
            }
            other => panic!("expected PunchCoord for Peer B, got {other:?}"),
        }

        match peer_a_punch {
            SignalMsg::PunchCoord {
                peer_public_udp_addr,
                peer_public_udp_addrs,
                self_public_udp_addr,
                ..
            } => {
                assert_eq!(
                    peer_public_udp_addr.as_deref(),
                    Some(peer_b_v4_addr.to_string().as_str())
                );
                assert_eq!(
                    self_public_udp_addr.as_deref(),
                    Some(peer_a_v4_addr.to_string().as_str())
                );
                assert_eq!(peer_public_udp_addrs, vec![peer_b_v4_addr.to_string()]);
            }
            other => panic!("expected PunchCoord for Peer A, got {other:?}"),
        }

        drop(peer_a);
        drop(peer_b);
        hub.shutdown_all().await;
        let _ = udp_v4_task.await;
        let _ = udp_v6_task.await;
        let _ = tcp_task.await;
    }

    #[test]
    fn extended_nat_type_and_nat_port_range_validation() {
        for valid in [
            "unknown",
            "public",
            "cone",
            "cone_verified",
            "cone_unverified",
            "symmetric_seq",
            "symmetric_random",
            "adm_seq",
            "adm_random",
            "apdm_seq",
            "apdm_random",
            "udp_blocked",
        ] {
            let upper = valid.to_ascii_uppercase();
            assert_eq!(normalize_nat_type(Some(valid)).as_deref(), Some(valid));
            assert_eq!(
                normalize_nat_type(Some(&format!("  {upper}  "))).as_deref(),
                Some(valid)
            );
        }
        assert_eq!(normalize_nat_type(Some("bogus_type")), None);
        assert_eq!(normalize_nat_type(None), None);

        // Valid port ranges: 1..=min<=max<=65535
        assert_eq!(normalize_nat_port_range(Some([1, 65535])), Some([1, 65535]));
        assert_eq!(
            normalize_nat_port_range(Some([20000, 20000])),
            Some([20000, 20000])
        );
        // Invalid port ranges: zero port or inverted range
        assert_eq!(normalize_nat_port_range(Some([0, 1000])), None);
        assert_eq!(normalize_nat_port_range(Some([0, 0])), None);
        assert_eq!(normalize_nat_port_range(Some([5000, 4000])), None);
        assert_eq!(normalize_nat_port_range(None), None);

        // Malformed array lengths in JSON must be rejected at deserialization
        let bad_len_1 = br#"{"type":"register","device_key":"k","nat_port_range":[1000]}"#;
        assert!(serde_json::from_slice::<SignalMsg>(bad_len_1).is_err());
        let bad_len_3 = br#"{"type":"heartbeat","nat_port_range":[1000,2000,3000]}"#;
        assert!(serde_json::from_slice::<SignalMsg>(bad_len_3).is_err());
    }

    #[test]
    fn rtt_smoothing_and_punch_start_after_clamping() {
        // No previous sample -> takes sample clamped to PEER_RTT_MAX_MS
        assert_eq!(update_smoothed_rtt_ms(None, 40), 40);
        assert_eq!(update_smoothed_rtt_ms(None, 25_000), PEER_RTT_MAX_MS);
        // EWMA: (3 * 40 + 80 + 2) / 4 = 50
        assert_eq!(update_smoothed_rtt_ms(Some(40), 80), 50);

        // Equal / zero RTT -> 0 on both sides
        assert_eq!(compute_punch_start_after_ms(0, 0), 0);
        assert_eq!(compute_punch_start_after_ms(50, 50), 0);

        // Fast side waits (rtt_slow - rtt_fast) / 2, slow side waits 0
        assert_eq!(compute_punch_start_after_ms(20, 120), 50);
        assert_eq!(compute_punch_start_after_ms(120, 20), 0);

        // Difference > 1000ms clamps delay to 500ms
        assert_eq!(compute_punch_start_after_ms(10, 1_500), 500);
        assert_eq!(compute_punch_start_after_ms(0, u32::MAX), 500);
        assert_eq!(compute_punch_start_after_ms(1_500, 10), 0);
    }

    #[test]
    fn legacy_json_without_p2_nat_or_punch_sync_fields_remains_compatible() {
        let legacy_register = br#"{"type":"register","device_key":"ed25519:old"}"#;
        assert!(matches!(
            serde_json::from_slice::<SignalMsg>(legacy_register).unwrap(),
            SignalMsg::Register {
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
                ..
            }
        ));

        let legacy_registered = br#"{"type":"registered","device_id":"123456789","formatted_id":"123 456 789","server_time":"2026-11-22T10:00:00Z","udp_probe_addr":"172.16.1.2:21116","relay_addr":"172.16.1.2:21117"}"#;
        let reg_ack: SignalMsg = serde_json::from_slice(legacy_registered).unwrap();
        assert!(matches!(
            reg_ack,
            SignalMsg::Registered {
                udp_probe_alt_addr: None,
                udp_probe_alt_ip_addr: None,
                udp_probe_token: None,
                ..
            }
        ));
        let reg_ack_json = serde_json::to_string(&reg_ack).unwrap();
        assert!(!reg_ack_json.contains("udp_probe_alt_ip_addr"));

        let legacy_hb = br#"{"type":"heartbeat"}"#;
        assert!(matches!(
            serde_json::from_slice::<SignalMsg>(legacy_hb).unwrap(),
            SignalMsg::Heartbeat {
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rtt_ms: None,
                ..
            }
        ));

        let legacy_conn = br#"{"type":"connect_request","target_id":"987654321"}"#;
        assert!(matches!(
            serde_json::from_slice::<SignalMsg>(legacy_conn).unwrap(),
            SignalMsg::ConnectRequest {
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                ..
            }
        ));

        let legacy_punch = br#"{"type":"punch_coord","session_id":"s1","role":"client","peer_id":"987654321","peer_lan_addrs":[],"nonce":"n1","relay_token":"t1","relay_addr":"172.16.1.2:21117"}"#;
        let punch: SignalMsg = serde_json::from_slice(legacy_punch).unwrap();
        assert!(matches!(
            punch,
            SignalMsg::PunchCoord {
                self_nat_port_range: None,
                peer_nat_port_range: None,
                punch_secret: None,
                start_after_ms: None,
                relay_fallback_after_ms: None,
                ..
            }
        ));
        let serialized = serde_json::to_string(&punch).unwrap();
        assert!(!serialized.contains("self_nat_port_range"));
        assert!(!serialized.contains("peer_nat_port_range"));
        assert!(!serialized.contains("punch_secret"));
        assert!(!serialized.contains("start_after_ms"));
        assert!(!serialized.contains("relay_fallback_after_ms"));
    }

    #[tokio::test]
    async fn punch_coord_delivers_alt_ip_secret_rtt_sync_and_nat_port_ranges() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(
            store,
            ephemeral,
            SignalConfig {
                public_udp_probe_addr: "198.51.100.1:21116".into(),
                public_udp_probe_alt_addr: Some("198.51.100.1:21119".into()),
                public_udp_probe_alt_ip_addr: Some("198.51.100.2:21116".into()),
                ..SignalConfig::default()
            },
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        // Host registers with adm_seq and valid nat_port_range [30000, 31000]
        let mut host = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut host,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:p2-host".into(),
                hostname: "p2-host".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: Some("adm_seq".into()),
                nat_port_delta: Some(2),
                nat_port_range: Some([30_000, 31_000]),
                rcp2_v2: true,
            },
        )
        .await
        .unwrap();
        let host_id = match read_signal_frame(&mut host).await.unwrap().unwrap() {
            SignalMsg::Registered {
                device_id,
                udp_probe_alt_ip_addr,
                ..
            } => {
                assert_eq!(udp_probe_alt_ip_addr.as_deref(), Some("198.51.100.2:21116"));
                device_id
            }
            other => panic!("expected Registered for host, got {other:?}"),
        };

        // Client registers with apdm_random and invalid nat_port_range [0, 1000] (ignored -> None)
        let mut client = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut client,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:p2-client".into(),
                hostname: "p2-client".into(),
                os: "macos".into(),
                app_version: String::new(),
                arch: String::new(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec![],
                access_token: None,
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: Some("apdm_random".into()),
                nat_port_delta: None,
                nat_port_range: Some([0, 1000]),
                rcp2_v2: true,
            },
        )
        .await
        .unwrap();
        let client_id = match read_signal_frame(&mut client).await.unwrap().unwrap() {
            SignalMsg::Registered {
                device_id,
                udp_probe_alt_ip_addr,
                ..
            } => {
                assert_eq!(udp_probe_alt_ip_addr.as_deref(), Some("198.51.100.2:21116"));
                device_id
            }
            other => panic!("expected Registered for client, got {other:?}"),
        };
        assert_eq!(hub.peer_smoothed_rtt_ms(&host_id), 0);
        assert_eq!(hub.peer_smoothed_rtt_ms(&client_id), 0);

        // Session 1 (before any RTT samples): both fallback to 0 -> start_after_ms == Some(0)
        write_signal_frame(
            &mut client,
            &SignalMsg::ConnectRequest {
                target_id: host_id.clone(),
                session_id: Some("sess-p2-1".into()),
                lan_addrs: vec![],
                nonce: Some("n1".into()),
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
        )
        .await
        .unwrap();
        let c1 = read_signal_frame(&mut client).await.unwrap().unwrap();
        let h1 = read_signal_frame(&mut host).await.unwrap().unwrap();

        let secret1 = match (c1, h1) {
            (
                SignalMsg::PunchCoord {
                    punch_secret: cs,
                    start_after_ms: c_start,
                    relay_fallback_after_ms: c_fb,
                    peer_nat_type: c_peer_nat,
                    self_nat_port_range: c_self_range,
                    peer_nat_port_range: c_peer_range,
                    ..
                },
                SignalMsg::PunchCoord {
                    punch_secret: hs,
                    start_after_ms: h_start,
                    relay_fallback_after_ms: h_fb,
                    peer_nat_type: h_peer_nat,
                    self_nat_port_range: h_self_range,
                    peer_nat_port_range: h_peer_range,
                    ..
                },
            ) => {
                let cs = cs.expect("client punch_secret must be set");
                let hs = hs.expect("host punch_secret must be set");
                assert_eq!(cs, hs);
                assert_eq!(cs.len(), 32);
                assert!(cs
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
                assert_eq!(c_start, Some(0));
                assert_eq!(h_start, Some(0));
                assert_eq!(c_fb, Some(400));
                assert_eq!(h_fb, Some(400));
                assert_eq!(c_peer_nat.as_deref(), Some("adm_seq"));
                assert_eq!(h_peer_nat.as_deref(), Some("apdm_random"));
                // Client's invalid [0, 1000] was ignored -> None
                assert_eq!(c_self_range, None);
                assert_eq!(c_peer_range, Some([30_000, 31_000]));
                assert_eq!(h_self_range, Some([30_000, 31_000]));
                assert_eq!(h_peer_range, None);
                cs
            }
            other => panic!("expected PunchCoord pair, got {other:?}"),
        };

        // Host reports RTT=160ms via Heartbeat; Client reports RTT=40ms + valid nat_port_range via Heartbeat
        write_signal_frame(
            &mut host,
            &SignalMsg::Heartbeat {
                lan_addrs: vec![],
                mac_addr: None,
                wol_enabled: None,
                nat_type: Some("cone_verified".into()),
                nat_port_delta: Some(0),
                nat_port_range: Some([40_000, 41_000]),
                rtt_ms: Some(160),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut host).await.unwrap().unwrap(),
            SignalMsg::HeartbeatAck { .. }
        ));

        write_signal_frame(
            &mut client,
            &SignalMsg::Heartbeat {
                lan_addrs: vec![],
                mac_addr: None,
                wol_enabled: None,
                nat_type: Some("cone_unverified".into()),
                nat_port_delta: None,
                nat_port_range: Some([12_000, 12_500]),
                rtt_ms: Some(40),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut client).await.unwrap().unwrap(),
            SignalMsg::HeartbeatAck { .. }
        ));

        // Session 2: fast client (40ms) gets (160 - 40)/2 = 60ms, slow host (160ms) gets 0ms
        // and punch_secret differs from Session 1.
        write_signal_frame(
            &mut client,
            &SignalMsg::ConnectRequest {
                target_id: host_id.clone(),
                session_id: Some("sess-p2-2".into()),
                lan_addrs: vec![],
                nonce: Some("n2".into()),
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
        )
        .await
        .unwrap();
        let c2 = read_signal_frame(&mut client).await.unwrap().unwrap();
        let h2 = read_signal_frame(&mut host).await.unwrap().unwrap();

        let secret2 = match (c2, h2) {
            (
                SignalMsg::PunchCoord {
                    punch_secret: cs,
                    start_after_ms: c_start,
                    relay_fallback_after_ms: c_fb,
                    peer_nat_type: c_peer_nat,
                    self_nat_port_range: c_self_range,
                    peer_nat_port_range: c_peer_range,
                    ..
                },
                SignalMsg::PunchCoord {
                    punch_secret: hs,
                    start_after_ms: h_start,
                    relay_fallback_after_ms: h_fb,
                    peer_nat_type: h_peer_nat,
                    self_nat_port_range: h_self_range,
                    peer_nat_port_range: h_peer_range,
                    ..
                },
            ) => {
                assert_eq!(cs, hs);
                assert_eq!(c_start, Some(60));
                assert_eq!(h_start, Some(0));
                assert_eq!(c_fb, Some(400));
                assert_eq!(h_fb, Some(400));
                assert_eq!(c_peer_nat.as_deref(), Some("cone_verified"));
                assert_eq!(h_peer_nat.as_deref(), Some("cone_unverified"));
                assert_eq!(c_self_range, Some([12_000, 12_500]));
                assert_eq!(c_peer_range, Some([40_000, 41_000]));
                assert_eq!(h_self_range, Some([40_000, 41_000]));
                assert_eq!(h_peer_range, Some([12_000, 12_500]));
                cs.unwrap()
            }
            other => panic!("expected PunchCoord pair, got {other:?}"),
        };
        assert_ne!(secret1, secret2);

        // Session 3: host RTT jumps high (e.g. 2000ms) -> client clamped to 500ms
        hub.record_peer_rtt_ms(&host_id, 2000);
        // After EWMA (3*160 + 2000 + 2)/4 = 620ms, (620 - 40)/2 = 290ms; push again to exceed 1040ms
        for _ in 0..8 {
            hub.record_peer_rtt_ms(&host_id, 2000);
        }
        write_signal_frame(
            &mut client,
            &SignalMsg::ConnectRequest {
                target_id: host_id.clone(),
                session_id: Some("sess-p2-3".into()),
                lan_addrs: vec![],
                nonce: Some("n3".into()),
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
        )
        .await
        .unwrap();
        let c3 = read_signal_frame(&mut client).await.unwrap().unwrap();
        let h3 = read_signal_frame(&mut host).await.unwrap().unwrap();
        match (c3, h3) {
            (
                SignalMsg::PunchCoord {
                    start_after_ms: c_start,
                    relay_fallback_after_ms: c_fb,
                    ..
                },
                SignalMsg::PunchCoord {
                    start_after_ms: h_start,
                    relay_fallback_after_ms: h_fb,
                    ..
                },
            ) => {
                assert_eq!(c_start, Some(500));
                assert_eq!(h_start, Some(0));
                assert_eq!(c_fb, Some(400));
                assert_eq!(h_fb, Some(400));
            }
            other => panic!("expected PunchCoord pair, got {other:?}"),
        }

        drop(client);
        drop(host);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn punch_secret_requires_both_peers_rcp2_v2() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(store, ephemeral, SignalConfig::default()));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        for (idx, (client_v2, host_v2)) in
            [(true, true), (true, false), (false, true), (false, false)]
                .into_iter()
                .enumerate()
        {
            let mut host = TcpStream::connect(tcp_addr).await.unwrap();
            write_signal_frame(
                &mut host,
                &SignalMsg::Register {
                    device_id: None,
                    device_key: format!("ed25519:neg-host-{idx}"),
                    hostname: format!("neg-host-{idx}"),
                    os: "macos".into(),
                    app_version: String::new(),
                    arch: String::new(),
                    cpu_model: String::new(),
                    mac_address: String::new(),
                    total_memory_mb: 0,
                    os_version: String::new(),
                    gpu_model: String::new(),
                    device_group: String::new(),
                    lan_addrs: vec![],
                    access_token: None,
                    device_pubkey: None,
                    allow_remote_assist: None,
                    allow_remote_control: None,
                    mac_addr: None,
                    wol_enabled: None,
                    nat_type: None,
                    nat_port_delta: None,
                    nat_port_range: None,
                    rcp2_v2: host_v2,
                },
            )
            .await
            .unwrap();
            let host_id = match read_signal_frame(&mut host).await.unwrap().unwrap() {
                SignalMsg::Registered { device_id, .. } => device_id,
                other => panic!("expected Registered for host, got {other:?}"),
            };

            let mut client = TcpStream::connect(tcp_addr).await.unwrap();
            write_signal_frame(
                &mut client,
                &SignalMsg::Register {
                    device_id: None,
                    device_key: format!("ed25519:neg-client-{idx}"),
                    hostname: format!("neg-client-{idx}"),
                    os: "macos".into(),
                    app_version: String::new(),
                    arch: String::new(),
                    cpu_model: String::new(),
                    mac_address: String::new(),
                    total_memory_mb: 0,
                    os_version: String::new(),
                    gpu_model: String::new(),
                    device_group: String::new(),
                    lan_addrs: vec![],
                    access_token: None,
                    device_pubkey: None,
                    allow_remote_assist: None,
                    allow_remote_control: None,
                    mac_addr: None,
                    wol_enabled: None,
                    nat_type: None,
                    nat_port_delta: None,
                    nat_port_range: None,
                    rcp2_v2: client_v2,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                read_signal_frame(&mut client).await.unwrap().unwrap(),
                SignalMsg::Registered { .. }
            ));

            write_signal_frame(
                &mut client,
                &SignalMsg::ConnectRequest {
                    target_id: host_id,
                    session_id: Some(format!("sess-neg-{idx}")),
                    lan_addrs: vec![],
                    nonce: Some(format!("nonce{idx}")),
                    nat_type: None,
                    nat_port_delta: None,
                    nat_port_range: None,
                    takeover: false,
                },
            )
            .await
            .unwrap();

            let c_msg = read_signal_frame(&mut client).await.unwrap().unwrap();
            let h_msg = read_signal_frame(&mut host).await.unwrap().unwrap();

            match (&c_msg, &h_msg) {
                (
                    SignalMsg::PunchCoord {
                        punch_secret: cs, ..
                    },
                    SignalMsg::PunchCoord {
                        punch_secret: hs, ..
                    },
                ) => {
                    if client_v2 && host_v2 {
                        let cs = cs
                            .as_ref()
                            .expect("both rcp2_v2=true must yield punch_secret");
                        let hs = hs
                            .as_ref()
                            .expect("both rcp2_v2=true must yield punch_secret");
                        assert_eq!(cs, hs);
                        assert_eq!(cs.len(), 32);
                        assert!(cs
                            .chars()
                            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
                    } else {
                        assert_eq!(
                            *cs, None,
                            "mixed/legacy ({client_v2}, {host_v2}) must not issue punch_secret to client"
                        );
                        assert_eq!(
                            *hs, None,
                            "mixed/legacy ({client_v2}, {host_v2}) must not issue punch_secret to host"
                        );
                        let c_json = serde_json::to_string(&c_msg).unwrap();
                        let h_json = serde_json::to_string(&h_msg).unwrap();
                        assert!(!c_json.contains("punch_secret"));
                        assert!(!h_json.contains("punch_secret"));
                    }
                }
                other => panic!("expected PunchCoord pair, got {other:?}"),
            }

            drop(client);
            drop(host);
        }

        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn hardware_metadata_register_update_assist_and_status_broadcast() {
        use crate::ephemeral::MemoryEphemeralStore;
        use crate::store::MemoryDeviceStore;

        // Legacy Register/DeviceStatusChanged frames without hardware fields deserialize cleanly,
        // and empty/zero hardware fields are omitted on DeviceStatusChanged serialization.
        let legacy_reg: SignalMsg = serde_json::from_str(
            r#"{"type":"register","device_key":"dk-hw-legacy","cpu_model":null,"total_memory_mb":null}"#,
        )
        .unwrap();
        assert!(matches!(
            legacy_reg,
            SignalMsg::Register {
                cpu_model,
                mac_address,
                total_memory_mb: 0,
                os_version,
                gpu_model,
                ..
            } if cpu_model.is_empty() && mac_address.is_empty() && os_version.is_empty() && gpu_model.is_empty()
        ));

        let empty_status_json = serde_json::to_string(&SignalMsg::DeviceStatusChanged {
            device_id: "123456789".into(),
            online: true,
            hostname: "host".into(),
            alias: String::new(),
            os: "macos".into(),
            app_version: String::new(),
            arch: String::new(),
            cpu_model: String::new(),
            mac_address: String::new(),
            total_memory_mb: 0,
            os_version: String::new(),
            gpu_model: String::new(),
            allow_remote_assist: false,
            allow_remote_control: true,
            wol_capable: false,
        })
        .unwrap();
        assert!(!empty_status_json.contains("cpu_model"));
        assert!(!empty_status_json.contains("mac_address"));
        assert!(!empty_status_json.contains("total_memory_mb"));
        assert!(!empty_status_json.contains("os_version"));
        assert!(!empty_status_json.contains("gpu_model"));

        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let auth_authority = Arc::new(AuthAuthority::load_or_create(store.as_ref()).await.unwrap());
        let hub = Arc::new(SignalHub::with_auth(
            store.clone(),
            ephemeral,
            auth_authority.clone(),
            SignalConfig::default(),
        ));

        let (_uid, token) =
            create_test_authed_user(&store, &auth_authority, "hw-sig@example.com").await;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        // Peer 1 connects first to receive DeviceStatusChanged broadcasts for Peer 2.
        let mut peer1 = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut peer1,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:hw-peer1".into(),
                hostname: "viewer".into(),
                os: "macos".into(),
                app_version: "0.2.0".into(),
                arch: "arm64".into(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec![],
                access_token: Some(token.clone()),
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut peer1).await.unwrap().unwrap(),
            SignalMsg::Registered { .. }
        ));

        // Peer 2 registers with full hardware metadata.
        let mut peer2 = TcpStream::connect(tcp_addr).await.unwrap();
        write_signal_frame(
            &mut peer2,
            &SignalMsg::Register {
                device_id: None,
                device_key: "ed25519:hw-peer2".into(),
                hostname: "studio-host".into(),
                os: "macos".into(),
                app_version: "0.2.0".into(),
                arch: "arm64".into(),
                cpu_model: "Apple M3 Max".into(),
                mac_address: "AA-BB-CC-DD-EE-02".into(),
                total_memory_mb: 65536,
                os_version: "macOS 15.1".into(),
                gpu_model: "Apple M3 Max".into(),
                device_group: String::new(),
                lan_addrs: vec![],
                access_token: Some(token),
                device_pubkey: None,
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let peer2_id = match read_signal_frame(&mut peer2).await.unwrap().unwrap() {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered for peer2, got {other:?}"),
        };

        // Peer 1 receives DeviceStatusChanged with hardware metadata.
        match read_signal_frame(&mut peer1).await.unwrap().unwrap() {
            SignalMsg::DeviceStatusChanged {
                device_id,
                online,
                cpu_model,
                mac_address,
                total_memory_mb,
                os_version,
                gpu_model,
                ..
            } => {
                assert_eq!(device_id, peer2_id);
                assert!(online);
                assert_eq!(cpu_model, "Apple M3 Max");
                assert_eq!(mac_address, "aa:bb:cc:dd:ee:02");
                assert_eq!(total_memory_mb, 65536);
                assert_eq!(os_version, "macOS 15.1");
                assert_eq!(gpu_model, "Apple M3 Max");
            }
            other => panic!("expected DeviceStatusChanged on peer1, got {other:?}"),
        }

        // Peer 2 sends incremental hardware update via UpdateAssistState.
        write_signal_frame(
            &mut peer2,
            &SignalMsg::UpdateAssistState {
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                cpu_model: None,
                mac_address: None,
                total_memory_mb: Some(131072),
                os_version: Some("macOS 15.2".into()),
                gpu_model: None,
            },
        )
        .await
        .unwrap();

        match read_signal_frame(&mut peer1).await.unwrap().unwrap() {
            SignalMsg::DeviceStatusChanged {
                device_id,
                cpu_model,
                mac_address,
                total_memory_mb,
                os_version,
                gpu_model,
                ..
            } => {
                assert_eq!(device_id, peer2_id);
                assert_eq!(cpu_model, "Apple M3 Max");
                assert_eq!(mac_address, "aa:bb:cc:dd:ee:02");
                assert_eq!(total_memory_mb, 131072);
                assert_eq!(os_version, "macOS 15.2");
                assert_eq!(gpu_model, "Apple M3 Max");
            }
            other => panic!("expected updated DeviceStatusChanged on peer1, got {other:?}"),
        }

        // Invalid oversized cpu_model in UpdateAssistState returns invalid_input without kicking peer2.
        write_signal_frame(
            &mut peer2,
            &SignalMsg::UpdateAssistState {
                allow_remote_assist: None,
                allow_remote_control: None,
                mac_addr: None,
                wol_enabled: None,
                cpu_model: Some("x".repeat(MAX_CPU_MODEL_LEN + 1)),
                mac_address: None,
                total_memory_mb: None,
                os_version: None,
                gpu_model: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut peer2).await.unwrap().unwrap(),
            SignalMsg::Error { code, .. } if code == "invalid_input"
        ));

        let stored = store.get_by_id(&peer2_id).await.unwrap().unwrap();
        assert_eq!(stored.cpu_model, "Apple M3 Max");
        assert_eq!(stored.mac_address, "aa:bb:cc:dd:ee:02");
        assert_eq!(stored.total_memory_mb, 131072);
        assert_eq!(stored.os_version, "macOS 15.2");
        assert_eq!(stored.gpu_model, "Apple M3 Max");

        drop(peer1);
        drop(peer2);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    async fn register_authed_peer_helper(
        addr: SocketAddr,
        device_key: &str,
        hostname: &str,
        os: &str,
        access_token: Option<&str>,
        allow_remote_assist: Option<bool>,
        allow_remote_control: Option<bool>,
    ) -> (TcpStream, String) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        write_signal_frame(
            &mut stream,
            &SignalMsg::Register {
                device_id: None,
                device_key: device_key.into(),
                hostname: hostname.into(),
                os: os.into(),
                app_version: "0.2.5".into(),
                arch: "arm64".into(),
                cpu_model: String::new(),
                mac_address: String::new(),
                total_memory_mb: 0,
                os_version: String::new(),
                gpu_model: String::new(),
                device_group: String::new(),
                lan_addrs: vec![],
                access_token: access_token.map(str::to_string),
                device_pubkey: None,
                allow_remote_assist,
                allow_remote_control,
                mac_addr: None,
                wol_enabled: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                rcp2_v2: false,
            },
        )
        .await
        .unwrap();
        let device_id = match read_signal_frame(&mut stream).await.unwrap().unwrap() {
            SignalMsg::Registered { device_id, .. } => device_id,
            other => panic!("expected Registered, got {other:?}"),
        };
        (stream, device_id)
    }

    #[tokio::test]
    async fn control_state_report_validation_and_backward_compatible_serde() {
        let legacy_conn: SignalMsg =
            serde_json::from_str(r#"{"type":"connect_request","target_id":"987654321"}"#).unwrap();
        assert!(matches!(
            legacy_conn,
            SignalMsg::ConnectRequest {
                takeover: false,
                ..
            }
        ));

        let legacy_relay: SignalMsg =
            serde_json::from_str(r#"{"type":"relay_alloc","target_id":"987654321"}"#).unwrap();
        assert!(matches!(
            legacy_relay,
            SignalMsg::RelayAlloc {
                takeover: false,
                ..
            }
        ));

        let legacy_punch: SignalMsg = serde_json::from_str(
            r#"{"type":"punch_coord","session_id":"s1","role":"client","peer_id":"987654321","peer_lan_addrs":[],"nonce":"n1","relay_token":"t1","relay_addr":"127.0.0.1:21117"}"#,
        )
        .unwrap();
        assert!(matches!(
            legacy_punch,
            SignalMsg::PunchCoord {
                takeover: false,
                peer_hostname: None,
                peer_os: None,
                ..
            }
        ));
        let punch_json = serde_json::to_string(&legacy_punch).unwrap();
        assert!(!punch_json.contains("peer_hostname"));
        assert!(!punch_json.contains("peer_os"));

        let legacy_ready: SignalMsg = serde_json::from_str(
            r#"{"type":"relay_ready","session_id":"s1","role":"host","peer_id":"123456789","relay_token":"t1","relay_addr":"127.0.0.1:21117","expires_in_sec":60}"#,
        )
        .unwrap();
        assert!(matches!(
            legacy_ready,
            SignalMsg::RelayReady {
                takeover: false,
                peer_hostname: None,
                peer_os: None,
                ..
            }
        ));
        let ready_json = serde_json::to_string(&legacy_ready).unwrap();
        assert!(!ready_json.contains("peer_hostname"));
        assert!(!ready_json.contains("peer_os"));

        let summary_min: ActiveControllerSummary =
            serde_json::from_str(r#"{"session_id":"sess-min"}"#).unwrap();
        assert_eq!(summary_min.session_id, "sess-min");
        assert_eq!(summary_min.controller_device_id, "");
        assert!(!summary_min.is_owner);
        assert_eq!(summary_min.connected_at_ms, 0);

        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let hub = Arc::new(SignalHub::new(store, ephemeral, SignalConfig::default()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        let (mut host, host_id) = register_peer_helper(addr, "ed25519:ctrl-val-host", vec![]).await;

        // Empty session_id is rejected without mutating active_controllers.
        write_signal_frame(
            &mut host,
            &SignalMsg::ControlStateReport {
                active_controllers: vec![ActiveControllerSummary {
                    session_id: String::new(),
                    controller_device_id: "111222333".into(),
                    controller_device_name: "ctrl".into(),
                    controller_os: "macos".into(),
                    is_owner: true,
                    mode: "remote_control".into(),
                    connected_at_ms: 1_700_000_000_000,
                }],
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut host).await.unwrap().unwrap(),
            SignalMsg::Error { ref code, .. } if code == err_code::INVALID_PAYLOAD
        ));
        assert!(hub.peer_active_controllers(&host_id).is_empty());

        // Exceeding MAX_ACTIVE_CONTROLLERS is rejected.
        let too_many: Vec<ActiveControllerSummary> = (0..=MAX_ACTIVE_CONTROLLERS)
            .map(|i| ActiveControllerSummary {
                session_id: format!("sess-{i}"),
                controller_device_id: String::new(),
                controller_device_name: String::new(),
                controller_os: String::new(),
                is_owner: false,
                mode: String::new(),
                connected_at_ms: 0,
            })
            .collect();
        write_signal_frame(
            &mut host,
            &SignalMsg::ControlStateReport {
                active_controllers: too_many,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut host).await.unwrap().unwrap(),
            SignalMsg::Error { ref code, .. } if code == err_code::INVALID_PAYLOAD
        ));
        assert!(hub.peer_active_controllers(&host_id).is_empty());

        drop(host);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn control_state_report_broadcasts_and_clears_on_disconnect_kick_and_replace() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let auth_authority = Arc::new(AuthAuthority::load_or_create(store.as_ref()).await.unwrap());
        let (_alice_id, alice_token) =
            create_test_authed_user(&store, &auth_authority, "alice-ctrl-state@example.com").await;
        let (_bob_id, bob_token) =
            create_test_authed_user(&store, &auth_authority, "bob-ctrl-state@example.com").await;

        let hub = Arc::new(SignalHub::with_auth(
            store,
            ephemeral,
            auth_authority,
            SignalConfig::default(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        let (mut watcher, _watcher_id) = register_authed_peer_helper(
            addr,
            "dk-ctrl-watcher",
            "watcher-mac",
            "macos",
            Some(&alice_token),
            None,
            None,
        )
        .await;
        let (mut host, host_id) = register_authed_peer_helper(
            addr,
            "dk-ctrl-host",
            "host-mac",
            "macos",
            Some(&alice_token),
            Some(true),
            Some(true),
        )
        .await;
        let (mut stranger, _stranger_id) = register_authed_peer_helper(
            addr,
            "dk-ctrl-stranger",
            "stranger-pc",
            "windows",
            Some(&bob_token),
            None,
            None,
        )
        .await;

        // Drain initial DeviceStatusChanged(online=true) for host on watcher.
        assert!(matches!(
            read_signal_frame(&mut watcher).await.unwrap().unwrap(),
            SignalMsg::DeviceStatusChanged { ref device_id, online: true, .. } if device_id == &host_id
        ));

        let summary = ActiveControllerSummary {
            session_id: "sess-sync-1".into(),
            controller_device_id: "555666777".into(),
            controller_device_name: "Alice iPad".into(),
            controller_os: "ios".into(),
            is_owner: true,
            mode: "remote_control".into(),
            connected_at_ms: 1_763_800_000_000,
        };
        write_signal_frame(
            &mut host,
            &SignalMsg::ControlStateReport {
                active_controllers: vec![summary.clone()],
            },
        )
        .await
        .unwrap();

        match read_signal_frame(&mut watcher).await.unwrap().unwrap() {
            SignalMsg::DeviceControlStateChanged {
                device_id,
                active_controllers,
            } => {
                assert_eq!(device_id, host_id);
                assert_eq!(active_controllers, vec![summary.clone()]);
            }
            other => panic!("expected DeviceControlStateChanged on watcher, got {other:?}"),
        }
        assert_eq!(hub.peer_active_controllers(&host_id), vec![summary.clone()]);

        // Cross-account stranger must NOT receive DeviceControlStateChanged.
        assert!(
            tokio::time::timeout(Duration::from_millis(80), read_signal_frame(&mut stranger))
                .await
                .is_err(),
            "cross-account stranger must not receive DeviceControlStateChanged"
        );

        // 1. Disconnecting host clears active_controllers and broadcasts empty list!
        drop(host);
        let mut saw_cleared = false;
        for _ in 0..2 {
            match read_signal_frame(&mut watcher).await.unwrap().unwrap() {
                SignalMsg::DeviceControlStateChanged {
                    device_id,
                    active_controllers,
                } if device_id == host_id => {
                    assert!(active_controllers.is_empty());
                    saw_cleared = true;
                }
                SignalMsg::DeviceStatusChanged {
                    device_id,
                    online: false,
                    ..
                } if device_id == host_id => {}
                other => panic!("unexpected frame on watcher after host disconnect: {other:?}"),
            }
        }
        assert!(
            saw_cleared,
            "watcher must receive cleared DeviceControlStateChanged on disconnect"
        );
        assert!(hub.peer_active_controllers(&host_id).is_empty());

        // 2. Reconnect host, report active controller, then kick_device -> clears & broadcasts [].
        let (mut host2, host_id2) = register_authed_peer_helper(
            addr,
            "dk-ctrl-host",
            "host-mac",
            "macos",
            Some(&alice_token),
            Some(true),
            Some(true),
        )
        .await;
        assert_eq!(host_id2, host_id);
        assert!(matches!(
            read_signal_frame(&mut watcher).await.unwrap().unwrap(),
            SignalMsg::DeviceStatusChanged { ref device_id, online: true, .. } if device_id == &host_id
        ));
        write_signal_frame(
            &mut host2,
            &SignalMsg::ControlStateReport {
                active_controllers: vec![summary.clone()],
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut watcher).await.unwrap().unwrap(),
            SignalMsg::DeviceControlStateChanged { ref device_id, ref active_controllers }
                if device_id == &host_id && active_controllers.len() == 1
        ));
        assert!(hub.kick_device(&host_id, err_code::DEVICE_UNBOUND).await);
        let mut saw_kick_clear = false;
        for _ in 0..2 {
            match read_signal_frame(&mut watcher).await.unwrap().unwrap() {
                SignalMsg::DeviceControlStateChanged {
                    device_id,
                    active_controllers,
                } if device_id == host_id => {
                    assert!(active_controllers.is_empty());
                    saw_kick_clear = true;
                }
                SignalMsg::DeviceStatusChanged {
                    device_id,
                    online: false,
                    ..
                } if device_id == host_id => {}
                other => panic!("unexpected frame after kick_device: {other:?}"),
            }
        }
        assert!(saw_kick_clear);

        // 3. Replacing an active host connection also clears active_controllers and broadcasts [].
        let (mut host3, _) = register_authed_peer_helper(
            addr,
            "dk-ctrl-host",
            "host-mac",
            "macos",
            Some(&alice_token),
            Some(true),
            Some(true),
        )
        .await;
        assert!(matches!(
            read_signal_frame(&mut watcher).await.unwrap().unwrap(),
            SignalMsg::DeviceStatusChanged { ref device_id, online: true, .. } if device_id == &host_id
        ));
        write_signal_frame(
            &mut host3,
            &SignalMsg::ControlStateReport {
                active_controllers: vec![summary],
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut watcher).await.unwrap().unwrap(),
            SignalMsg::DeviceControlStateChanged { ref device_id, ref active_controllers }
                if device_id == &host_id && active_controllers.len() == 1
        ));
        let (host4, _) = register_authed_peer_helper(
            addr,
            "dk-ctrl-host",
            "host-mac",
            "macos",
            Some(&alice_token),
            Some(true),
            Some(true),
        )
        .await;
        let mut saw_replace_clear = false;
        for _ in 0..2 {
            match read_signal_frame(&mut watcher).await.unwrap().unwrap() {
                SignalMsg::DeviceControlStateChanged {
                    device_id,
                    active_controllers,
                } if device_id == host_id => {
                    assert!(active_controllers.is_empty());
                    saw_replace_clear = true;
                }
                SignalMsg::DeviceStatusChanged {
                    device_id,
                    online: true,
                    ..
                } if device_id == host_id => {}
                other => panic!("unexpected frame on watcher after replacement: {other:?}"),
            }
        }
        assert!(saw_replace_clear);
        assert!(hub.peer_active_controllers(&host_id).is_empty());

        drop(host2);
        drop(host3);
        drop(host4);
        drop(watcher);
        drop(stranger);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn kick_and_replace_during_inflight_control_state_report_is_serialized() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(GatedEphemeralStore::new());
        let auth_authority = Arc::new(AuthAuthority::load_or_create(store.as_ref()).await.unwrap());
        let (_alice_id, alice_token) =
            create_test_authed_user(&store, &auth_authority, "alice-ctrl-race@example.com").await;

        let hub = Arc::new(SignalHub::with_auth(
            store,
            ephemeral.clone(),
            auth_authority,
            SignalConfig::default(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        let (mut watcher, _watcher_id) = register_authed_peer_helper(
            addr,
            "dk-ctrl-race-watcher",
            "watcher-mac",
            "macos",
            Some(&alice_token),
            None,
            None,
        )
        .await;
        let (mut host, host_id) = register_authed_peer_helper(
            addr,
            "dk-ctrl-race-host",
            "host-mac",
            "macos",
            Some(&alice_token),
            Some(true),
            Some(true),
        )
        .await;
        assert!(matches!(
            read_signal_frame(&mut watcher).await.unwrap().unwrap(),
            SignalMsg::DeviceStatusChanged { ref device_id, online: true, .. } if device_id == &host_id
        ));

        let summary = ActiveControllerSummary {
            session_id: "sess-race-1".into(),
            controller_device_id: "555666777".into(),
            controller_device_name: "Alice iPad".into(),
            controller_os: "ios".into(),
            is_owner: true,
            mode: "remote_control".into(),
            connected_at_ms: 1_763_800_000_000,
        };

        // Sub-case A: kick_device arrives while ControlStateReport's `set_online` is suspended.
        // The stripe lock must serialize kick_device behind `set_online` AND the broadcast of
        // `[summary]` so ephemeral stays offline and watcher observes `[summary]` before `[]`.
        ephemeral.enable_gate(true);
        write_signal_frame(
            &mut host,
            &SignalMsg::ControlStateReport {
                active_controllers: vec![summary.clone()],
            },
        )
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(2), ephemeral.entered.notified())
            .await
            .expect("control_state_report must enter set_online");

        let kick_task = tokio::spawn({
            let hub = hub.clone();
            let id = host_id.clone();
            async move {
                hub.kick_device(&id, "kick_during_control_state_report")
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        ephemeral.release.notify_one();

        assert!(tokio::time::timeout(Duration::from_secs(2), kick_task)
            .await
            .expect("kick_device must complete after control_state_report releases stripe lock")
            .unwrap());
        assert!(!hub.is_peer_connected(&host_id));
        assert!(
            !ephemeral.is_online(&host_id).await.unwrap(),
            "device must not remain falsely online after kick during ControlStateReport"
        );

        let mut control_state_events = Vec::new();
        let mut saw_offline = false;
        for _ in 0..3 {
            match read_signal_frame(&mut watcher).await.unwrap().unwrap() {
                SignalMsg::DeviceControlStateChanged {
                    device_id,
                    active_controllers,
                } if device_id == host_id => {
                    control_state_events.push(active_controllers);
                }
                SignalMsg::DeviceStatusChanged {
                    device_id,
                    online: false,
                    ..
                } if device_id == host_id => {
                    saw_offline = true;
                }
                other => panic!("unexpected frame on watcher during kick race: {other:?}"),
            }
        }
        assert!(saw_offline);
        assert_eq!(
            control_state_events,
            vec![vec![summary.clone()], Vec::new()],
            "watcher must observe non-empty control state strictly before cleared []"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), read_signal_frame(&mut watcher))
                .await
                .is_err(),
            "no stale trailing DeviceControlStateChanged should arrive after kick"
        );

        // Sub-case B: replacement Register arrives while ControlStateReport's `set_online` is suspended.
        let (mut host2, host_id2) = register_authed_peer_helper(
            addr,
            "dk-ctrl-race-host",
            "host-mac",
            "macos",
            Some(&alice_token),
            Some(true),
            Some(true),
        )
        .await;
        assert_eq!(host_id2, host_id);
        assert!(matches!(
            read_signal_frame(&mut watcher).await.unwrap().unwrap(),
            SignalMsg::DeviceStatusChanged { ref device_id, online: true, .. } if device_id == &host_id
        ));

        ephemeral.enable_gate(true);
        write_signal_frame(
            &mut host2,
            &SignalMsg::ControlStateReport {
                active_controllers: vec![summary.clone()],
            },
        )
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(2), ephemeral.entered.notified())
            .await
            .expect("second control_state_report must enter set_online");

        let replace_task = tokio::spawn({
            let token = alice_token.clone();
            async move {
                register_authed_peer_helper(
                    addr,
                    "dk-ctrl-race-host",
                    "host-mac",
                    "macos",
                    Some(&token),
                    Some(true),
                    Some(true),
                )
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        ephemeral.release.notify_one();

        let (host3, host_id3) = tokio::time::timeout(Duration::from_secs(2), replace_task)
            .await
            .expect("replacement register must complete after control_state_report releases stripe lock")
            .unwrap();
        assert_eq!(host_id3, host_id);
        assert!(hub.peer_active_controllers(&host_id).is_empty());
        assert!(ephemeral.is_online(&host_id).await.unwrap());

        let mut replace_events = Vec::new();
        let mut saw_online_again = false;
        for _ in 0..3 {
            match read_signal_frame(&mut watcher).await.unwrap().unwrap() {
                SignalMsg::DeviceControlStateChanged {
                    device_id,
                    active_controllers,
                } if device_id == host_id => {
                    replace_events.push(active_controllers);
                }
                SignalMsg::DeviceStatusChanged {
                    device_id,
                    online: true,
                    ..
                } if device_id == host_id => {
                    saw_online_again = true;
                }
                other => panic!("unexpected frame on watcher during replace race: {other:?}"),
            }
        }
        assert!(saw_online_again);
        assert_eq!(
            replace_events,
            vec![vec![summary.clone()], Vec::new()],
            "watcher must observe non-empty control state strictly before replacement cleared []"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), read_signal_frame(&mut watcher))
                .await
                .is_err(),
            "no stale trailing DeviceControlStateChanged should arrive after replacement"
        );

        // Sub-case C: a stale connection invoking handle_control_state_report after kick is a no-op.
        assert!(
            hub.kick_device(&host_id, "cleanup_before_stale_report")
                .await
        );
        assert!(matches!(
            read_signal_frame(&mut watcher).await.unwrap().unwrap(),
            SignalMsg::DeviceStatusChanged { ref device_id, online: false, .. } if device_id == &host_id
        ));
        let (stale_tx, _stale_rx) = mpsc::channel(4);
        let stale_cancel = PeerCancel::new();
        hub.handle_control_state_report(&host_id, 999_999, &stale_cancel, &stale_tx, vec![summary])
            .await;
        assert!(!ephemeral.is_online(&host_id).await.unwrap());
        assert!(hub.peer_active_controllers(&host_id).is_empty());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), read_signal_frame(&mut watcher))
                .await
                .is_err(),
            "stale connection control_state_report must not broadcast"
        );

        drop(host);
        drop(host2);
        drop(host3);
        drop(watcher);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconnect_control_state_report_after_kick_disconnect_and_replace_is_serialized() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(GatedEphemeralStore::new());
        let auth_authority = Arc::new(AuthAuthority::load_or_create(store.as_ref()).await.unwrap());
        let (_alice_id, alice_token) =
            create_test_authed_user(&store, &auth_authority, "alice-ctrl-rev-race@example.com")
                .await;

        let hub = Arc::new(SignalHub::with_auth(
            store,
            ephemeral.clone(),
            auth_authority,
            SignalConfig::default(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        let (mut watcher, _watcher_id) = register_authed_peer_helper(
            addr,
            "dk-ctrl-rev-watcher",
            "watcher-mac",
            "macos",
            Some(&alice_token),
            None,
            None,
        )
        .await;
        let (mut host1, host_id) = register_authed_peer_helper(
            addr,
            "dk-ctrl-rev-host",
            "host-mac",
            "macos",
            Some(&alice_token),
            Some(true),
            Some(true),
        )
        .await;
        assert!(matches!(
            read_signal_frame(&mut watcher).await.unwrap().unwrap(),
            SignalMsg::DeviceStatusChanged { ref device_id, online: true, .. } if device_id == &host_id
        ));

        let summary_old = ActiveControllerSummary {
            session_id: "sess-old".into(),
            controller_device_id: "111222333".into(),
            controller_device_name: "Old iPad".into(),
            controller_os: "ios".into(),
            is_owner: true,
            mode: "remote_control".into(),
            connected_at_ms: 1_763_800_000_000,
        };
        let summary_new_1 = ActiveControllerSummary {
            session_id: "sess-new-1".into(),
            controller_device_id: "444555666".into(),
            controller_device_name: "New Mac 1".into(),
            controller_os: "macos".into(),
            is_owner: true,
            mode: "remote_control".into(),
            connected_at_ms: 1_763_800_000_100,
        };
        let summary_new_2 = ActiveControllerSummary {
            session_id: "sess-new-2".into(),
            controller_device_id: "777888999".into(),
            controller_device_name: "New Mac 2".into(),
            controller_os: "macos".into(),
            is_owner: true,
            mode: "remote_control".into(),
            connected_at_ms: 1_763_800_000_200,
        };
        let summary_new_3 = ActiveControllerSummary {
            session_id: "sess-new-3".into(),
            controller_device_id: "101112131".into(),
            controller_device_name: "New Mac 3".into(),
            controller_os: "macos".into(),
            is_owner: true,
            mode: "remote_control".into(),
            connected_at_ms: 1_763_800_000_300,
        };

        // 1. Kick -> concurrent Register -> immediate ControlStateReport([summary_new_1])
        write_signal_frame(
            &mut host1,
            &SignalMsg::ControlStateReport {
                active_controllers: vec![summary_old.clone()],
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut watcher).await.unwrap().unwrap(),
            SignalMsg::DeviceControlStateChanged { ref device_id, ref active_controllers }
                if device_id == &host_id && active_controllers == &vec![summary_old.clone()]
        ));

        ephemeral.enable_remove_gate(true);
        let kick_task = tokio::spawn({
            let hub = hub.clone();
            let id = host_id.clone();
            async move { hub.kick_device(&id, "kick_before_reconnect").await }
        });
        tokio::time::timeout(Duration::from_secs(2), ephemeral.remove_entered.notified())
            .await
            .expect("kick_device must enter remove_online");

        let reconnect_task = tokio::spawn({
            let token = alice_token.clone();
            async move {
                register_authed_peer_helper(
                    addr,
                    "dk-ctrl-rev-host",
                    "host-mac",
                    "macos",
                    Some(&token),
                    Some(true),
                    Some(true),
                )
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        ephemeral.remove_release.notify_one();

        assert!(tokio::time::timeout(Duration::from_secs(2), kick_task)
            .await
            .unwrap()
            .unwrap());
        let (mut host2, host_id2) = tokio::time::timeout(Duration::from_secs(2), reconnect_task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(host_id2, host_id);

        write_signal_frame(
            &mut host2,
            &SignalMsg::ControlStateReport {
                active_controllers: vec![summary_new_1.clone()],
            },
        )
        .await
        .unwrap();

        let mut events_after_kick = Vec::new();
        for _ in 0..4 {
            match read_signal_frame(&mut watcher).await.unwrap().unwrap() {
                SignalMsg::DeviceControlStateChanged {
                    device_id,
                    active_controllers,
                } if device_id == host_id => {
                    events_after_kick.push(active_controllers);
                }
                SignalMsg::DeviceStatusChanged { device_id, .. } if device_id == host_id => {}
                other => panic!("unexpected frame after kick reconnect: {other:?}"),
            }
        }
        assert_eq!(
            events_after_kick,
            vec![Vec::new(), vec![summary_new_1.clone()]],
            "kick [] broadcast must strictly precede new connection's ControlStateReport broadcast"
        );
        assert_eq!(
            hub.peer_active_controllers(&host_id),
            vec![summary_new_1.clone()]
        );

        // 2. Disconnect cleanup -> concurrent Register -> immediate ControlStateReport([summary_new_2])
        ephemeral.enable_remove_gate(true);
        drop(host1);
        drop(host2);
        tokio::time::timeout(Duration::from_secs(2), ephemeral.remove_entered.notified())
            .await
            .expect("disconnect cleanup must enter remove_online");

        let reconnect_task_2 = tokio::spawn({
            let token = alice_token.clone();
            async move {
                register_authed_peer_helper(
                    addr,
                    "dk-ctrl-rev-host",
                    "host-mac",
                    "macos",
                    Some(&token),
                    Some(true),
                    Some(true),
                )
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        ephemeral.remove_release.notify_one();

        let (mut host3, host_id3) = tokio::time::timeout(Duration::from_secs(2), reconnect_task_2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(host_id3, host_id);

        write_signal_frame(
            &mut host3,
            &SignalMsg::ControlStateReport {
                active_controllers: vec![summary_new_2.clone()],
            },
        )
        .await
        .unwrap();

        let mut events_after_disconnect = Vec::new();
        for _ in 0..4 {
            match read_signal_frame(&mut watcher).await.unwrap().unwrap() {
                SignalMsg::DeviceControlStateChanged {
                    device_id,
                    active_controllers,
                } if device_id == host_id => {
                    events_after_disconnect.push(active_controllers);
                }
                SignalMsg::DeviceStatusChanged { device_id, .. } if device_id == host_id => {}
                other => panic!("unexpected frame after disconnect reconnect: {other:?}"),
            }
        }
        assert_eq!(
            events_after_disconnect,
            vec![Vec::new(), vec![summary_new_2.clone()]],
            "disconnect [] broadcast must strictly precede new connection's ControlStateReport broadcast"
        );
        assert_eq!(
            hub.peer_active_controllers(&host_id),
            vec![summary_new_2.clone()]
        );

        // 3. handle_register replacement -> immediate ControlStateReport([summary_new_3])
        ephemeral.enable_gate(true);
        let replace_task = tokio::spawn({
            let token = alice_token.clone();
            async move {
                register_authed_peer_helper(
                    addr,
                    "dk-ctrl-rev-host",
                    "host-mac",
                    "macos",
                    Some(&token),
                    Some(true),
                    Some(true),
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(2), ephemeral.entered.notified())
            .await
            .expect("replacement register must enter set_online");
        ephemeral.release.notify_one();

        let (mut host4, host_id4) = tokio::time::timeout(Duration::from_secs(2), replace_task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(host_id4, host_id);

        write_signal_frame(
            &mut host4,
            &SignalMsg::ControlStateReport {
                active_controllers: vec![summary_new_3.clone()],
            },
        )
        .await
        .unwrap();

        let mut events_after_replace = Vec::new();
        for _ in 0..3 {
            match read_signal_frame(&mut watcher).await.unwrap().unwrap() {
                SignalMsg::DeviceControlStateChanged {
                    device_id,
                    active_controllers,
                } if device_id == host_id => {
                    events_after_replace.push(active_controllers);
                }
                SignalMsg::DeviceStatusChanged { device_id, .. } if device_id == host_id => {}
                other => panic!("unexpected frame after replace report: {other:?}"),
            }
        }
        assert_eq!(
            events_after_replace,
            vec![Vec::new(), vec![summary_new_3.clone()]],
            "replacement [] broadcast must strictly precede new connection's ControlStateReport broadcast"
        );
        assert_eq!(hub.peer_active_controllers(&host_id), vec![summary_new_3]);

        drop(host3);
        drop(host4);
        drop(watcher);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn force_disconnect_request_auth_and_forwarding() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let auth_authority = Arc::new(AuthAuthority::load_or_create(store.as_ref()).await.unwrap());
        let (_alice_id, alice_token) =
            create_test_authed_user(&store, &auth_authority, "alice-fd@example.com").await;
        let (_bob_id, bob_token) =
            create_test_authed_user(&store, &auth_authority, "bob-fd@example.com").await;

        let hub = Arc::new(SignalHub::with_auth(
            store,
            ephemeral,
            auth_authority,
            SignalConfig {
                require_auth: false,
                ..SignalConfig::default()
            },
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        let (mut anon, _) =
            register_authed_peer_helper(addr, "dk-fd-anon", "anon", "macos", None, None, None)
                .await;
        let (mut alice_host, alice_host_id) = register_authed_peer_helper(
            addr,
            "dk-fd-alice-host",
            "alice-host",
            "macos",
            Some(&alice_token),
            Some(true),
            Some(true),
        )
        .await;
        let (mut alice_req, alice_req_id) = register_authed_peer_helper(
            addr,
            "dk-fd-alice-req",
            "alice-req",
            "macos",
            Some(&alice_token),
            None,
            None,
        )
        .await;
        let (mut bob_stranger, _) = register_authed_peer_helper(
            addr,
            "dk-fd-bob",
            "bob-pc",
            "windows",
            Some(&bob_token),
            None,
            None,
        )
        .await;
        // Drain DeviceStatusChanged on alice_host.
        let _ = read_signal_frame(&mut alice_host).await.unwrap().unwrap();

        // 1. Unauthenticated caller -> unauthorized.
        write_signal_frame(
            &mut anon,
            &SignalMsg::ForceDisconnectRequest {
                target_id: alice_host_id.clone(),
                controller_device_id: None,
                session_id: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut anon).await.unwrap().unwrap(),
            SignalMsg::Error { ref code, .. } if code == err_code::UNAUTHORIZED
        ));

        // 2. Cross-account caller -> forbidden (never kicks across accounts!).
        write_signal_frame(
            &mut bob_stranger,
            &SignalMsg::ForceDisconnectRequest {
                target_id: alice_host_id.clone(),
                controller_device_id: Some("111222333".into()),
                session_id: Some("sess-x".into()),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut bob_stranger).await.unwrap().unwrap(),
            SignalMsg::Error { ref code, .. } if code == err_code::FORBIDDEN
        ));
        assert!(
            tokio::time::timeout(
                Duration::from_millis(80),
                read_signal_frame(&mut alice_host)
            )
            .await
            .is_err(),
            "cross-account ForceDisconnectRequest must not reach target host"
        );

        // 3. Unknown target -> peer_not_found.
        write_signal_frame(
            &mut alice_req,
            &SignalMsg::ForceDisconnectRequest {
                target_id: "999999999".into(),
                controller_device_id: None,
                session_id: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut alice_req).await.unwrap().unwrap(),
            SignalMsg::Error { ref code, .. } if code == err_code::PEER_NOT_FOUND
        ));

        // 4. Same-account caller -> forwards ForceDisconnect to target host!
        write_signal_frame(
            &mut alice_req,
            &SignalMsg::ForceDisconnectRequest {
                target_id: alice_host_id.clone(),
                controller_device_id: Some("222333444".into()),
                session_id: Some("sess-kick-1".into()),
            },
        )
        .await
        .unwrap();
        match read_signal_frame(&mut alice_host).await.unwrap().unwrap() {
            SignalMsg::ForceDisconnect {
                requester_device_id,
                controller_device_id,
                session_id,
            } => {
                assert_eq!(requester_device_id, alice_req_id);
                assert_eq!(controller_device_id.as_deref(), Some("222333444"));
                assert_eq!(session_id.as_deref(), Some("sess-kick-1"));
            }
            other => panic!("expected ForceDisconnect on alice_host, got {other:?}"),
        }

        // 5. Offline same-account target -> peer_offline.
        drop(alice_host);
        assert!(matches!(
            read_signal_frame(&mut alice_req).await.unwrap().unwrap(),
            SignalMsg::DeviceStatusChanged { ref device_id, online: false, .. } if device_id == &alice_host_id
        ));
        write_signal_frame(
            &mut alice_req,
            &SignalMsg::ForceDisconnectRequest {
                target_id: alice_host_id,
                controller_device_id: None,
                session_id: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut alice_req).await.unwrap().unwrap(),
            SignalMsg::Error { ref code, .. } if code == err_code::PEER_OFFLINE
        ));

        drop(anon);
        drop(alice_req);
        drop(bob_stranger);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn connect_request_and_relay_alloc_target_in_session_and_takeover_boundaries() {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        let auth_authority = Arc::new(AuthAuthority::load_or_create(store.as_ref()).await.unwrap());
        let (_alice_id, alice_token) =
            create_test_authed_user(&store, &auth_authority, "alice-takeover@example.com").await;
        let (_bob_id, bob_token) =
            create_test_authed_user(&store, &auth_authority, "bob-takeover@example.com").await;

        let hub = Arc::new(SignalHub::with_auth(
            store,
            ephemeral.clone(),
            auth_authority,
            SignalConfig::default(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(hub.clone().serve_tcp_signaling_on_listener(listener));

        let (mut host, host_id) = register_authed_peer_helper(
            addr,
            "dk-tk-host",
            "host-studio",
            "macos",
            Some(&alice_token),
            Some(true),
            Some(true),
        )
        .await;
        let (mut owner1, owner1_id) = register_authed_peer_helper(
            addr,
            "dk-tk-owner1",
            "owner1-mac",
            "macos",
            Some(&alice_token),
            None,
            None,
        )
        .await;
        let (mut owner2, _owner2_id) = register_authed_peer_helper(
            addr,
            "dk-tk-owner2",
            "owner2-win",
            "windows",
            Some(&alice_token),
            None,
            None,
        )
        .await;
        let (mut guest, _guest_id) = register_authed_peer_helper(
            addr,
            "dk-tk-guest",
            "guest-linux",
            "linux",
            Some(&bob_token),
            None,
            None,
        )
        .await;

        // Drain initial DeviceStatusChanged frames on host.
        for _ in 0..2 {
            let _ = read_signal_frame(&mut host).await.unwrap().unwrap();
        }
        // Drain DeviceStatusChanged frames on owner1 & owner2.
        let _ = read_signal_frame(&mut owner1).await.unwrap().unwrap();

        // Host reports owner1 is actively controlling it.
        write_signal_frame(
            &mut host,
            &SignalMsg::ControlStateReport {
                active_controllers: vec![ActiveControllerSummary {
                    session_id: "active-sess-1".into(),
                    controller_device_id: owner1_id.clone(),
                    controller_device_name: "owner1-mac".into(),
                    controller_os: "macos".into(),
                    is_owner: true,
                    mode: "remote_control".into(),
                    connected_at_ms: 1_763_800_000_000,
                }],
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut owner1).await.unwrap().unwrap(),
            SignalMsg::DeviceControlStateChanged { .. }
        ));
        assert!(matches!(
            read_signal_frame(&mut owner2).await.unwrap().unwrap(),
            SignalMsg::DeviceControlStateChanged { .. }
        ));

        // A & B: owner2 with takeover=false -> TARGET_IN_SESSION on ConnectRequest & RelayAlloc!
        write_signal_frame(
            &mut owner2,
            &SignalMsg::ConnectRequest {
                target_id: host_id.clone(),
                session_id: Some("tk-denied-1".into()),
                lan_addrs: vec![],
                nonce: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut owner2).await.unwrap().unwrap(),
            SignalMsg::Error { ref code, .. } if code == err_code::TARGET_IN_SESSION
        ));
        write_signal_frame(
            &mut owner2,
            &SignalMsg::RelayAlloc {
                target_id: host_id.clone(),
                session_id: Some("tk-denied-relay-1".into()),
                takeover: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut owner2).await.unwrap().unwrap(),
            SignalMsg::Error { ref code, .. } if code == err_code::TARGET_IN_SESSION
        ));
        assert_eq!(ephemeral.active_token_count(), 0);

        // C & D: owner1 (same controller_device_id!) with takeover=false -> ALLOWED (reconnect/route switch)!
        write_signal_frame(
            &mut owner1,
            &SignalMsg::ConnectRequest {
                target_id: host_id.clone(),
                session_id: Some("same-ctrl-reconnect".into()),
                lan_addrs: vec![],
                nonce: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut owner1).await.unwrap().unwrap(),
            SignalMsg::PunchCoord {
                takeover: false,
                ..
            }
        ));
        assert!(matches!(
            read_signal_frame(&mut host).await.unwrap().unwrap(),
            SignalMsg::PunchCoord {
                takeover: false,
                peer_hostname: Some(ref h),
                peer_os: Some(ref o),
                ..
            } if h == "owner1-mac" && o == "macos"
        ));
        write_signal_frame(
            &mut owner1,
            &SignalMsg::RelayAlloc {
                target_id: host_id.clone(),
                session_id: Some("same-ctrl-relay".into()),
                takeover: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut owner1).await.unwrap().unwrap(),
            SignalMsg::RelayReady {
                takeover: false,
                ..
            }
        ));
        assert!(matches!(
            read_signal_frame(&mut host).await.unwrap().unwrap(),
            SignalMsg::RelayReady {
                takeover: false,
                ..
            }
        ));

        // E, F & G: cross-account guest MUST be rejected with TARGET_IN_SESSION even with takeover=true!
        let tokens_before_guest = ephemeral.active_token_count();
        for takeover in [false, true] {
            write_signal_frame(
                &mut guest,
                &SignalMsg::ConnectRequest {
                    target_id: host_id.clone(),
                    session_id: Some(format!("guest-blk-{takeover}")),
                    lan_addrs: vec![],
                    nonce: None,
                    nat_type: None,
                    nat_port_delta: None,
                    nat_port_range: None,
                    takeover,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                read_signal_frame(&mut guest).await.unwrap().unwrap(),
                SignalMsg::Error { ref code, .. } if code == err_code::TARGET_IN_SESSION
            ));
        }
        write_signal_frame(
            &mut guest,
            &SignalMsg::RelayAlloc {
                target_id: host_id.clone(),
                session_id: Some("guest-relay-takeover-blk".into()),
                takeover: true,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut guest).await.unwrap().unwrap(),
            SignalMsg::Error { ref code, .. } if code == err_code::TARGET_IN_SESSION
        ));
        assert_eq!(ephemeral.active_token_count(), tokens_before_guest);

        // H & I: same-account owner2 with takeover=true -> ALLOWED and passes takeover=true + peer_hostname/peer_os!
        write_signal_frame(
            &mut owner2,
            &SignalMsg::ConnectRequest {
                target_id: host_id.clone(),
                session_id: Some("owner-tk-punch".into()),
                lan_addrs: vec![],
                nonce: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: true,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut owner2).await.unwrap().unwrap(),
            SignalMsg::PunchCoord {
                takeover: true,
                is_owner_connection: true,
                peer_hostname: Some(ref h),
                peer_os: Some(ref o),
                ..
            } if h == "host-studio" && o == "macos"
        ));
        assert!(matches!(
            read_signal_frame(&mut host).await.unwrap().unwrap(),
            SignalMsg::PunchCoord {
                takeover: true,
                is_owner_connection: true,
                peer_hostname: Some(ref h),
                peer_os: Some(ref o),
                ..
            } if h == "owner2-win" && o == "windows"
        ));

        write_signal_frame(
            &mut owner2,
            &SignalMsg::RelayAlloc {
                target_id: host_id.clone(),
                session_id: Some("owner-tk-relay".into()),
                takeover: true,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut owner2).await.unwrap().unwrap(),
            SignalMsg::RelayReady {
                takeover: true,
                is_owner_connection: true,
                ..
            }
        ));
        assert!(matches!(
            read_signal_frame(&mut host).await.unwrap().unwrap(),
            SignalMsg::RelayReady {
                takeover: true,
                is_owner_connection: true,
                peer_hostname: Some(ref h),
                peer_os: Some(ref o),
                ..
            } if h == "owner2-win" && o == "windows"
        ));

        // J: When host has no active_controllers, guest passing takeover=true is allowed as a normal session
        // with takeover sanitized to false!
        write_signal_frame(
            &mut host,
            &SignalMsg::ControlStateReport {
                active_controllers: vec![],
            },
        )
        .await
        .unwrap();
        let _ = read_signal_frame(&mut owner1).await.unwrap().unwrap();
        let _ = read_signal_frame(&mut owner2).await.unwrap().unwrap();

        write_signal_frame(
            &mut guest,
            &SignalMsg::ConnectRequest {
                target_id: host_id,
                session_id: Some("guest-idle-sanitized".into()),
                lan_addrs: vec![],
                nonce: None,
                nat_type: None,
                nat_port_delta: None,
                nat_port_range: None,
                takeover: true,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_signal_frame(&mut guest).await.unwrap().unwrap(),
            SignalMsg::PunchCoord {
                takeover: false,
                is_owner_connection: false,
                ..
            }
        ));
        assert!(matches!(
            read_signal_frame(&mut host).await.unwrap().unwrap(),
            SignalMsg::PunchCoord {
                takeover: false,
                is_owner_connection: false,
                peer_hostname: Some(ref h),
                peer_os: Some(ref o),
                ..
            } if h == "guest-linux" && o == "linux"
        ));

        drop(host);
        drop(owner1);
        drop(owner2);
        drop(guest);
        hub.shutdown_all().await;
        let _ = server_task.await;
    }
}
