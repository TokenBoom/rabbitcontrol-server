#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use clap::Parser;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use rc_server::api::{self, AdvertisedEndpoints, AppState, AuthRateLimiter};
use rc_server::auth::{ensure_initial_admin, AuthAuthority};
use rc_server::ephemeral::{
    EphemeralStore, MemoryEphemeralStore, RedisEphemeralStore, SettingsCache,
};
use rc_server::pki::PkiAuthority;
use rc_server::relay::{RelayConfig, RelayServer};
use rc_server::signal::{SignalConfig, SignalHub};
use rc_server::store::{AuthStore, DeviceStore, PgDeviceStore, PkiStore};
use rc_server::{bind_tcp_listener, DEFAULT_TCP_LISTEN_BACKLOG};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:21118";
const DEFAULT_SIGNAL_ADDR: &str = "0.0.0.0:21116";
const DEFAULT_RELAY_ADDR: &str = "0.0.0.0:21117";
const DEFAULT_LOG_FILTER: &str = "info,rc_server=info,tower_http=info";
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(
    name = "rc-server",
    version,
    about = "RabbitControl Rust Rendezvous, Mandatory mTLS TCP Relay, and Admin REST API Server"
)]
struct Args {
    /// Axum HTTPS/HTTP Admin, Auth, PKI & Web UI listen address [default: 0.0.0.0:21118]
    #[arg(long, env = "RC_HTTP_ADDR", value_name = "ADDR")]
    http: Option<String>,

    /// Optional separate plain-HTTP listen address for Admin Web UI & Admin REST API (intended behind a TLS reverse proxy, e.g. 127.0.0.1:21119)
    #[arg(long = "web-addr", env = "RC_WEB_ADDR", value_name = "ADDR")]
    web_addr: Option<String>,

    /// Native TLS 1.3 TCP framed signaling + UDP STUN-lite probe listen address [default: 0.0.0.0:21116]
    #[arg(long, env = "RC_SIGNAL_ADDR", value_name = "ADDR")]
    signal: Option<String>,

    /// Mandatory TLS 1.3 mTLS TCP relay listen address (RCR1 binary handshake) [default: 0.0.0.0:21117]
    #[arg(long, env = "RC_RELAY_ADDR", value_name = "ADDR")]
    relay: Option<String>,

    /// PostgreSQL connection URL (required via --database-url, DATABASE_URL, or RC_DATABASE_URL)
    #[arg(long, env = "DATABASE_URL", value_name = "URL")]
    database_url: Option<String>,

    /// Optional Redis URL for distributed ephemeral state (via --redis-url, REDIS_URL, or RC_REDIS_URL)
    #[arg(long, env = "REDIS_URL", value_name = "URL")]
    redis_url: Option<String>,

    /// Optional public hostname or IP advertised to clients (e.g. 172.16.1.2 or relay.example.com)
    #[arg(long, env = "RC_PUBLIC_HOST", value_name = "HOST")]
    public_host: Option<String>,

    /// Extra Subject Alternative Names (DNS or IP) included in the server TLS certificate
    #[arg(long = "tls-san", env = "RC_TLS_SAN", value_delimiter = ',')]
    tls_san: Vec<String>,

    /// Serve plain HTTP instead of HTTPS on --http (intended ONLY behind a TLS-terminating reverse proxy)
    #[arg(
        long,
        env = "RC_PLAIN_HTTP",
        num_args = 0..=1,
        default_missing_value = "true",
        value_name = "BOOL"
    )]
    plain_http: Option<String>,

    /// Optional directory containing built frontend static files (e.g. /app/web or web/dist)
    #[arg(long, env = "RC_WEB_DIR", value_name = "DIR")]
    web_dir: Option<String>,

    /// Optional email for the auto-generated initial administrator on first boot
    #[arg(long, env = "RC_INIT_ADMIN_EMAIL", value_name = "EMAIL")]
    init_admin_email: Option<String>,

    /// Optional legacy static bearer token also accepted on admin REST endpoints
    #[arg(long, env = "RC_ADMIN_TOKEN", value_name = "TOKEN")]
    admin_token: Option<String>,

    /// Allowed CORS origins (comma-separated, e.g. "https://admin.example.com" or "*" for wildcard; omit for same-origin only)
    #[arg(long = "cors-origin", env = "RC_CORS_ORIGIN", value_delimiter = ',')]
    cors_origin: Vec<String>,

    /// TCP listen backlog for HTTP, optional Web Admin, signaling, and relay sockets [default: 4096]
    #[arg(long, env = "RC_LISTEN_BACKLOG", value_name = "BACKLOG")]
    listen_backlog: Option<String>,

    /// Allow rc-server to directly broadcast Wake-on-LAN UDP magic packets when no same-LAN peer is online [default: false]
    #[arg(
        long = "allow-server-wol",
        env = "ALLOW_SERVER_WOL",
        num_args = 0..=1,
        default_missing_value = "true",
        value_name = "BOOL"
    )]
    allow_server_wol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedConfig {
    http: SocketAddr,
    web_addr: Option<SocketAddr>,
    signal: SocketAddr,
    relay: SocketAddr,
    database_url: String,
    redis_url: Option<String>,
    public_host: Option<String>,
    tls_san: Vec<String>,
    plain_http: bool,
    web_dir: Option<PathBuf>,
    init_admin_email: Option<String>,
    admin_token: Option<String>,
    cors_origin: Vec<String>,
    listen_backlog: u32,
    allow_server_wol: bool,
}

fn trim_non_empty(raw: Option<String>) -> Option<String> {
    raw.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn clean_list(items: Vec<String>) -> Vec<String> {
    items
        .into_iter()
        .filter_map(|item| {
            let trimmed = item.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect()
}

fn parse_socket_addr_or_default(
    raw: Option<String>,
    default_addr: &str,
    name: &str,
) -> Result<SocketAddr, String> {
    let val = trim_non_empty(raw).unwrap_or_else(|| default_addr.to_string());
    val.parse::<SocketAddr>()
        .map_err(|err| format!("invalid socket address '{val}' for {name}: {err}"))
}

fn parse_optional_socket_addr(
    raw: Option<String>,
    name: &str,
) -> Result<Option<SocketAddr>, String> {
    let Some(val) = trim_non_empty(raw) else {
        return Ok(None);
    };
    val.parse::<SocketAddr>()
        .map(Some)
        .map_err(|err| format!("invalid socket address '{val}' for {name}: {err}"))
}

fn parse_optional_bool(raw: Option<String>, name: &str) -> Result<bool, String> {
    let Some(val) = trim_non_empty(raw) else {
        return Ok(false);
    };
    match val.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(format!(
            "invalid boolean value '{val}' for {name} (expected true/false/1/0/yes/no/on/off)"
        )),
    }
}

fn parse_listen_backlog(raw: Option<String>) -> Result<u32, String> {
    let Some(val) = trim_non_empty(raw) else {
        return Ok(DEFAULT_TCP_LISTEN_BACKLOG);
    };
    let parsed = val.parse::<u32>().map_err(|err| {
        format!("invalid integer '{val}' for --listen-backlog / RC_LISTEN_BACKLOG: {err}")
    })?;
    if parsed == 0 {
        return Err("--listen-backlog / RC_LISTEN_BACKLOG must be >= 1".to_string());
    }
    Ok(parsed)
}

fn resolve_log_filter(env_lookup: impl Fn(&str) -> Option<String>) -> String {
    trim_non_empty(env_lookup("RUST_LOG"))
        .or_else(|| trim_non_empty(env_lookup("RC_LOG")))
        .unwrap_or_else(|| DEFAULT_LOG_FILTER.to_string())
}

fn addrs_conflict(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() != 0
        && a.port() == b.port()
        && a.is_ipv4() == b.is_ipv4()
        && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

fn resolve_config(
    args: Args,
    env_lookup: impl Fn(&str) -> Option<String>,
) -> Result<ResolvedConfig, String> {
    let http = parse_socket_addr_or_default(args.http, DEFAULT_HTTP_ADDR, "--http / RC_HTTP_ADDR")?;
    let web_addr = parse_optional_socket_addr(args.web_addr, "--web-addr / RC_WEB_ADDR")?;
    let signal = parse_socket_addr_or_default(
        args.signal,
        DEFAULT_SIGNAL_ADDR,
        "--signal / RC_SIGNAL_ADDR",
    )?;
    let relay =
        parse_socket_addr_or_default(args.relay, DEFAULT_RELAY_ADDR, "--relay / RC_RELAY_ADDR")?;

    if let Some(addr) = web_addr {
        if addrs_conflict(addr, http) || addrs_conflict(addr, signal) || addrs_conflict(addr, relay)
        {
            return Err(format!(
                "--web-addr / RC_WEB_ADDR ({addr}) must not conflict with --http ({http}), --signal ({signal}), or --relay ({relay})"
            ));
        }
    }

    let database_url = trim_non_empty(args.database_url)
        .or_else(|| trim_non_empty(env_lookup("RC_DATABASE_URL")))
        .ok_or_else(|| {
            "missing required database URL: pass --database-url or set DATABASE_URL / RC_DATABASE_URL"
                .to_string()
        })?;

    let redis_url =
        trim_non_empty(args.redis_url).or_else(|| trim_non_empty(env_lookup("RC_REDIS_URL")));
    let public_host = trim_non_empty(args.public_host);
    let tls_san = clean_list(args.tls_san);
    let plain_http = parse_optional_bool(args.plain_http, "--plain-http / RC_PLAIN_HTTP")?;
    let web_dir = trim_non_empty(args.web_dir).map(PathBuf::from);
    let init_admin_email = trim_non_empty(args.init_admin_email);
    let admin_token = trim_non_empty(args.admin_token);
    let cors_origin = clean_list(args.cors_origin);
    let listen_backlog = parse_listen_backlog(args.listen_backlog)?;
    let allow_server_wol = parse_optional_bool(
        trim_non_empty(args.allow_server_wol)
            .or_else(|| trim_non_empty(env_lookup("RC_ALLOW_SERVER_WOL"))),
        "--allow-server-wol / ALLOW_SERVER_WOL",
    )?;

    Ok(ResolvedConfig {
        http,
        web_addr,
        signal,
        relay,
        database_url,
        redis_url,
        public_host,
        tls_san,
        plain_http,
        web_dir,
        init_admin_email,
        admin_token,
        cors_origin,
        listen_backlog,
        allow_server_wol,
    })
}

fn format_advertised_addr(public_host: Option<&str>, bind: SocketAddr) -> String {
    if let Some(host) = public_host.map(str::trim).filter(|s| !s.is_empty()) {
        if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{}", bind.port())
        } else {
            format!("{host}:{}", bind.port())
        }
    } else if bind.ip().is_unspecified() {
        if bind.is_ipv6() {
            format!("[::1]:{}", bind.port())
        } else {
            format!("127.0.0.1:{}", bind.port())
        }
    } else {
        bind.to_string()
    }
}

fn build_tls13_server_config(
    cert_der: &[u8],
    key_pkcs8_der: &[u8],
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8_der.to_vec())),
        )?;
    Ok(Arc::new(cfg))
}

async fn wait_for_watch_shutdown(mut rx: watch::Receiver<bool>) {
    if *rx.borrow_and_update() {
        return;
    }
    while rx.changed().await.is_ok() {
        if *rx.borrow_and_update() {
            return;
        }
    }
}

async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            error!(error = %err, "failed to install Ctrl+C handler");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                error!(error = %err, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("received SIGINT (Ctrl+C); initiating graceful shutdown");
        }
        _ = terminate => {
            info!("received SIGTERM; initiating graceful shutdown");
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let log_filter = resolve_log_filter(|k| std::env::var(k).ok());
    let env_filter =
        EnvFilter::try_new(&log_filter).unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let args = Args::parse();
    let cfg = resolve_config(args, |k| std::env::var(k).ok())
        .map_err(|msg| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))?;

    // Validate CORS configuration upfront so malformed origins fail fast.
    let _ = api::build_cors_layer(&cfg.cors_origin)
        .map_err(|msg| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))?;

    let web_dir = cfg.web_dir.as_ref().and_then(|dir| {
        if dir.is_dir() {
            Some(dir.clone())
        } else {
            warn!(path = %dir.display(), "--web-dir does not exist or is not a directory; static web hosting disabled");
            None
        }
    });

    // Shared shutdown signal coordinated across HTTPS, UDP probe, TLS signaling, mTLS relay, and cleanup.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 1. Connect PostgreSQL and run embedded SQL migrations.
    info!("connecting to PostgreSQL and running migrations");
    let pg_store = Arc::new(PgDeviceStore::connect(&cfg.database_url).await?);
    let device_store: Arc<dyn DeviceStore> = pg_store.clone();
    let auth_store: Arc<dyn AuthStore> = pg_store.clone();

    // 2. Ensure initial admin account on first boot.
    if let Some(creds) =
        ensure_initial_admin(pg_store.as_ref(), cfg.init_admin_email.as_deref()).await?
    {
        println!(
            "\n\
            ========================================================================\n\
              RabbitControl Initial Administrator Account Created (First Boot)\n\
              Email    : {email}\n\
              Password : {password}\n\
              Notice   : You MUST change this password on first login!\n\
            ========================================================================",
            email = creds.email,
            password = creds.password,
        );
        info!(
            admin_user_id = %creds.user_id,
            admin_email = %creds.email,
            "initial administrator account created; password change required on first login"
        );
    }

    // 3. Load or initialize persistent Ed25519 AuthAuthority and ECDSA P-256 Root CA.
    let auth_authority = Arc::new(AuthAuthority::load_or_create(pg_store.as_ref()).await?);
    let pki_authority = Arc::new(PkiAuthority::load_or_create(pg_store.as_ref()).await?);
    let server_cert =
        pki_authority.issue_default_server_tls_cert(cfg.public_host.as_deref(), &cfg.tls_san)?;
    let https_tls_config = pki_authority.build_server_tls_config(&server_cert, false)?;
    let signal_tls_config =
        build_tls13_server_config(&server_cert.cert_der, &server_cert.key_pkcs8_der)?;
    let relay_mtls_config = pki_authority.build_server_tls_config(&server_cert, true)?;

    // 4. Initialize EphemeralStore (Redis if configured, otherwise zero-dependency DashMap).
    let mut cleanup_task = None;
    let ephemeral: Arc<dyn EphemeralStore> = match cfg.redis_url.as_deref() {
        Some(redis_url) => {
            info!("connecting to Redis ephemeral backend");
            let redis_store = RedisEphemeralStore::connect(redis_url).await?;
            Arc::new(redis_store)
        }
        None => {
            info!("no REDIS_URL provided; using in-memory DashMap ephemeral backend");
            let mem = Arc::new(MemoryEphemeralStore::new());
            cleanup_task = Some(
                mem.spawn_cleanup_task_with_shutdown(Duration::from_secs(30), shutdown_rx.clone()),
            );
            mem
        }
    };

    // Pre-warm SettingsCache and certificate revocation cache.
    let settings_cache = Arc::new(SettingsCache::new(pg_store.clone(), Arc::clone(&ephemeral)));
    let allow_registration = settings_cache.get_allow_registration().await?;
    let active_revoked = pg_store.list_active_revoked_certs().await?;
    let now = Utc::now();
    for cert in &active_revoked {
        if cert.expires_at > now {
            let ttl = (cert.expires_at - now)
                .to_std()
                .unwrap_or_else(|_| Duration::from_secs(1));
            let _ = ephemeral.revoke_cert_serial(&cert.serial_hex, ttl).await;
        }
    }

    // 5. Bind all network sockets upfront so address conflicts fail fast.
    let signal_listener = bind_tcp_listener(cfg.signal, cfg.listen_backlog)?;
    let signal_local = signal_listener.local_addr()?;
    let udp_socket = Arc::new(UdpSocket::bind(signal_local).await?);
    let udp_local = udp_socket.local_addr()?;
    let relay_listener = bind_tcp_listener(cfg.relay, cfg.listen_backlog)?;
    let relay_local = relay_listener.local_addr()?;
    let http_listener = bind_tcp_listener(cfg.http, cfg.listen_backlog)?;
    let http_local = http_listener.local_addr()?;
    let web_listener = match cfg.web_addr {
        Some(web_bind) => Some(bind_tcp_listener(web_bind, cfg.listen_backlog)?),
        None => None,
    };
    let web_local = web_listener
        .as_ref()
        .map(|listener| listener.local_addr())
        .transpose()?;

    if web_listener.is_some() && web_dir.is_none() {
        warn!("--web-addr / RC_WEB_ADDR is set without a valid --web-dir; only Admin REST APIs will be served on the web listener");
    }

    let advertised_signal = format_advertised_addr(cfg.public_host.as_deref(), signal_local);
    let advertised_udp = format_advertised_addr(cfg.public_host.as_deref(), udp_local);
    let advertised_relay = format_advertised_addr(cfg.public_host.as_deref(), relay_local);

    let signal_hub = Arc::new(SignalHub::with_auth(
        Arc::clone(&auth_store),
        Arc::clone(&ephemeral),
        Arc::clone(&auth_authority),
        SignalConfig {
            public_udp_probe_addr: advertised_udp.clone(),
            public_relay_addr: advertised_relay.clone(),
            allow_server_wol: cfg.allow_server_wol,
            ..SignalConfig::default()
        },
    ));

    let relay_server = Arc::new(RelayServer::new(
        Arc::clone(&device_store),
        Arc::clone(&ephemeral),
        RelayConfig::default(),
    ));

    let tls_enabled = !cfg.plain_http;
    let app_state = AppState {
        device_store,
        auth_store: Arc::clone(&auth_store),
        ephemeral: Arc::clone(&ephemeral),
        auth_authority: Arc::clone(&auth_authority),
        pki_authority: Arc::clone(&pki_authority),
        settings_cache: Arc::clone(&settings_cache),
        signal_hub: Arc::clone(&signal_hub),
        relay_server: Arc::clone(&relay_server),
        endpoints: AdvertisedEndpoints {
            signal_tcp_addr: advertised_signal.clone(),
            udp_probe_addr: advertised_udp.clone(),
            tcp_relay_addr: advertised_relay.clone(),
        },
        started_at: Instant::now(),
        admin_token: cfg.admin_token.clone(),
        cors_origins: cfg.cors_origin.clone(),
        tls_enabled,
        web_dir: web_dir.clone(),
        auth_rate_limiter: Arc::new(AuthRateLimiter::default()),
        allow_unauthenticated_legacy_admin: false,
    };
    let (http_app, web_app) = if web_listener.is_some() {
        (
            api::router_with_mode(app_state.clone(), api::RouterMode::ClientApiOnly),
            Some(api::router_with_mode(
                app_state,
                api::RouterMode::WebAdminOnly,
            )),
        )
    } else {
        (api::router(app_state), None)
    };

    info!(
        http_addr = %http_local,
        https_enabled = tls_enabled,
        web_http_addr = ?web_local,
        split_web_admin = web_local.is_some(),
        signal_tls_addr = %signal_local,
        udp_probe_addr = %udp_local,
        relay_mtls_addr = %relay_local,
        listen_backlog = cfg.listen_backlog,
        advertised_signal = %advertised_signal,
        advertised_udp = %advertised_udp,
        advertised_relay = %advertised_relay,
        ca_fingerprint_sha256 = %pki_authority.ca_fingerprint_sha256(),
        auth_pubkey_hex = %auth_authority.public_key_hex(),
        allow_registration,
        allow_server_wol = cfg.allow_server_wol,
        prewarmed_revoked_certs = active_revoked.len(),
        web_dir = ?web_dir,
        static_admin_token_configured = cfg.admin_token.is_some(),
        ephemeral_backend = ephemeral.backend_name(),
        relay_engine = relay_server.engine(),
        "rc-server started"
    );

    // 6. Spawn all listeners into a tracked JoinSet so any fatal exit triggers coordinated shutdown.
    let mut listeners: JoinSet<(&'static str, std::io::Result<()>)> = JoinSet::new();

    {
        let udp_hub = Arc::clone(&signal_hub);
        let udp_shutdown = shutdown_rx.clone();
        listeners.spawn(async move {
            (
                "udp_probe",
                udp_hub
                    .serve_udp_probe_on_socket_with_shutdown(udp_socket, udp_shutdown)
                    .await,
            )
        });
    }

    {
        let tcp_hub = Arc::clone(&signal_hub);
        let sig_shutdown = shutdown_rx.clone();
        listeners.spawn(async move {
            (
                "tls_signaling",
                tcp_hub
                    .serve_tls_signaling_on_listener_with_shutdown(
                        signal_listener,
                        signal_tls_config,
                        sig_shutdown,
                    )
                    .await,
            )
        });
    }

    {
        let relay_srv = Arc::clone(&relay_server);
        let relay_auth_store = Arc::clone(&auth_store);
        let relay_shutdown = shutdown_rx.clone();
        listeners.spawn(async move {
            (
                "mtls_relay",
                relay_srv
                    .serve_tls_on_listener_with_shutdown(
                        relay_listener,
                        relay_mtls_config,
                        relay_auth_store,
                        relay_shutdown,
                    )
                    .await,
            )
        });
    }

    {
        let http_shutdown = shutdown_rx.clone();
        if cfg.plain_http {
            listeners.spawn(async move {
                (
                    "http_api",
                    axum::serve(
                        http_listener,
                        http_app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(wait_for_watch_shutdown(http_shutdown))
                    .await,
                )
            });
        } else {
            listeners.spawn(async move {
                (
                    "https_api",
                    api::serve_https(http_listener, https_tls_config, http_app, http_shutdown)
                        .await,
                )
            });
        }
    }

    if let (Some(web_listener), Some(web_app)) = (web_listener, web_app) {
        let web_shutdown = shutdown_rx.clone();
        listeners.spawn(async move {
            (
                "web_http",
                axum::serve(
                    web_listener,
                    web_app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .with_graceful_shutdown(wait_for_watch_shutdown(web_shutdown))
                .await,
            )
        });
    }

    let mut fatal_error: Option<String> = None;

    tokio::select! {
        _ = wait_for_shutdown_signal() => {
            let _ = shutdown_tx.send(true);
        }
        Some(joined) = listeners.join_next() => {
            let _ = shutdown_tx.send(true);
            match joined {
                Ok((name, Ok(()))) => {
                    error!(service = name, "listener exited unexpectedly; initiating coordinated shutdown");
                    fatal_error = Some(format!("service '{name}' exited unexpectedly"));
                }
                Ok((name, Err(err))) => {
                    error!(service = name, error = %err, "listener exited with fatal error; initiating coordinated shutdown");
                    fatal_error = Some(format!("service '{name}' failed: {err}"));
                }
                Err(join_err) => {
                    error!(error = %join_err, "listener task panicked or was cancelled; initiating coordinated shutdown");
                    fatal_error = Some(format!("listener task failed: {join_err}"));
                }
            }
        }
    }

    // 7. Coordinated graceful drain with a bounded 5s timeout so active relay sessions
    // flush `record_relay_end` to PostgreSQL and online peers clean up ephemeral state.
    let drain_result = tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, async {
        let drain_listeners = async {
            let mut drain_err: Option<String> = None;
            while let Some(joined) = listeners.join_next().await {
                match joined {
                    Ok((name, Ok(()))) => {
                        info!(service = name, "listener stopped cleanly");
                    }
                    Ok((name, Err(err))) => {
                        error!(service = name, error = %err, "listener exited with error during shutdown");
                        if drain_err.is_none() {
                            drain_err = Some(format!("service '{name}' failed during shutdown: {err}"));
                        }
                    }
                    Err(join_err) => {
                        error!(error = %join_err, "listener task failed during shutdown");
                        if drain_err.is_none() {
                            drain_err = Some(format!("listener task failed during shutdown: {join_err}"));
                        }
                    }
                }
            }
            drain_err
        };

        let drain_cleanup = async {
            if let Some(handle) = cleanup_task.take() {
                let _ = handle.await;
            }
        };

        let ((), (), listener_err, ()) = tokio::join!(
            signal_hub.shutdown_all(),
            relay_server.shutdown_all(),
            drain_listeners,
            drain_cleanup,
        );
        listener_err
    })
    .await;

    match drain_result {
        Ok(listener_err) => {
            if fatal_error.is_none() {
                fatal_error = listener_err;
            }
        }
        Err(_) => {
            warn!(
                timeout_secs = SHUTDOWN_DRAIN_TIMEOUT.as_secs(),
                "graceful shutdown drain timed out; aborting remaining tasks"
            );
            listeners.abort_all();
            if let Some(handle) = cleanup_task.take() {
                handle.abort();
            }
        }
    }

    if let Some(msg) = fatal_error {
        return Err(std::io::Error::other(msg).into());
    }

    info!("rc-server stopped cleanly");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty_args() -> Args {
        Args {
            http: None,
            web_addr: None,
            signal: None,
            relay: None,
            database_url: None,
            redis_url: None,
            public_host: None,
            tls_san: Vec::new(),
            plain_http: None,
            web_dir: None,
            init_admin_email: None,
            admin_token: None,
            cors_origin: Vec::new(),
            listen_backlog: None,
            allow_server_wol: None,
        }
    }

    fn lookup_from<'a>(map: &'a HashMap<&'a str, &'a str>) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| map.get(k).map(|v| (*v).to_string())
    }

    #[test]
    fn resolve_config_handles_empty_env_defaults_and_fallbacks() {
        let mut args = empty_args();
        args.http = Some("  ".into());
        args.web_addr = Some("  ".into());
        args.signal = Some(String::new());
        args.relay = Some("".into());
        args.database_url = Some("   ".into());
        args.redis_url = Some("".into());
        args.public_host = Some("  ".into());
        args.tls_san = vec!["".into(), " relay.example.com ".into(), "  ".into()];
        args.plain_http = Some("  ".into());
        args.web_dir = Some("  ".into());
        args.init_admin_email = Some("".into());
        args.admin_token = Some(" ".into());
        args.cors_origin = vec![" ".into(), "https://admin.example.com".into()];
        args.listen_backlog = Some("".into());

        let env = HashMap::from([
            (
                "RC_DATABASE_URL",
                "postgres://user:pass@postgres:5432/rabbitcontrol",
            ),
            ("RC_REDIS_URL", "redis://redis:6379"),
        ]);

        let cfg = resolve_config(args, lookup_from(&env)).unwrap();
        assert_eq!(cfg.http, DEFAULT_HTTP_ADDR.parse().unwrap());
        assert_eq!(cfg.web_addr, None);
        assert_eq!(cfg.signal, DEFAULT_SIGNAL_ADDR.parse().unwrap());
        assert_eq!(cfg.relay, DEFAULT_RELAY_ADDR.parse().unwrap());
        assert_eq!(
            cfg.database_url,
            "postgres://user:pass@postgres:5432/rabbitcontrol"
        );
        assert_eq!(cfg.redis_url.as_deref(), Some("redis://redis:6379"));
        assert_eq!(cfg.public_host, None);
        assert_eq!(cfg.tls_san, vec!["relay.example.com".to_string()]);
        assert!(!cfg.plain_http);
        assert_eq!(cfg.web_dir, None);
        assert_eq!(cfg.init_admin_email, None);
        assert_eq!(cfg.admin_token, None);
        assert_eq!(
            cfg.cors_origin,
            vec!["https://admin.example.com".to_string()]
        );
        assert_eq!(cfg.listen_backlog, DEFAULT_TCP_LISTEN_BACKLOG);
    }

    #[test]
    fn resolve_config_accepts_bool_variants_and_cli_override() {
        for raw in ["true", "TRUE", "1", "yes", "On"] {
            let mut args = empty_args();
            args.database_url = Some("postgres://u:p@127.0.0.1/rc".into());
            args.plain_http = Some(raw.into());
            let env = HashMap::new();
            let cfg = resolve_config(args, lookup_from(&env)).unwrap();
            assert!(cfg.plain_http, "expected '{raw}' to parse true");
        }
        for raw in ["false", "FALSE", "0", "no", "Off"] {
            let mut args = empty_args();
            args.database_url = Some("postgres://u:p@127.0.0.1/rc".into());
            args.plain_http = Some(raw.into());
            let env = HashMap::new();
            let cfg = resolve_config(args, lookup_from(&env)).unwrap();
            assert!(!cfg.plain_http, "expected '{raw}' to parse false");
        }

        // Clap flag without value sets plain_http=true without swallowing subsequent flags.
        let parsed = Args::try_parse_from([
            "rc-server",
            "--database-url",
            "postgres://cli:p@db/rc",
            "--plain-http",
            "--http",
            "127.0.0.1:29999",
            "--listen-backlog",
            "8192",
        ])
        .unwrap();
        let env = HashMap::from([("RC_DATABASE_URL", "postgres://env/ignored")]);
        let cfg = resolve_config(parsed, lookup_from(&env)).unwrap();
        assert_eq!(cfg.database_url, "postgres://cli:p@db/rc");
        assert!(cfg.plain_http);
        assert_eq!(cfg.http, "127.0.0.1:29999".parse().unwrap());
        assert_eq!(cfg.listen_backlog, 8192);
    }

    #[test]
    fn resolve_config_rejects_invalid_or_missing_values() {
        let env = HashMap::new();

        // Missing database URL
        let err = resolve_config(empty_args(), lookup_from(&env)).unwrap_err();
        assert!(err.contains("missing required database URL"), "{err}");

        // Invalid socket address
        let mut args = empty_args();
        args.database_url = Some("postgres://u:p@127.0.0.1/rc".into());
        args.http = Some("not-an-addr".into());
        assert!(resolve_config(args, lookup_from(&env)).is_err());

        // Invalid boolean
        let mut args = empty_args();
        args.database_url = Some("postgres://u:p@127.0.0.1/rc".into());
        args.plain_http = Some("maybe".into());
        assert!(resolve_config(args, lookup_from(&env)).is_err());

        // Zero listen backlog
        let mut args = empty_args();
        args.database_url = Some("postgres://u:p@127.0.0.1/rc".into());
        args.listen_backlog = Some("0".into());
        assert!(resolve_config(args, lookup_from(&env)).is_err());

        // Invalid web_addr
        let mut args = empty_args();
        args.database_url = Some("postgres://u:p@127.0.0.1/rc".into());
        args.web_addr = Some("not-an-addr".into());
        assert!(resolve_config(args, lookup_from(&env)).is_err());

        // web_addr conflicting with http / signal / relay (exact or wildcard/loopback same port)
        for conflict in [
            "0.0.0.0:21118",
            "127.0.0.1:21118",
            "0.0.0.0:21116",
            "127.0.0.1:21116",
            "0.0.0.0:21117",
        ] {
            let mut args = empty_args();
            args.database_url = Some("postgres://u:p@127.0.0.1/rc".into());
            args.web_addr = Some(conflict.into());
            let err = resolve_config(args, lookup_from(&env)).unwrap_err();
            assert!(err.contains("--web-addr / RC_WEB_ADDR"), "{err}");
        }

        // IPv6 wildcard [::]:21118 conflicts with [::1]:21118
        let mut args = empty_args();
        args.database_url = Some("postgres://u:p@127.0.0.1/rc".into());
        args.http = Some("[::]:21118".into());
        args.web_addr = Some("[::1]:21118".into());
        let err = resolve_config(args, lookup_from(&env)).unwrap_err();
        assert!(err.contains("--web-addr / RC_WEB_ADDR"), "{err}");
    }

    #[test]
    fn resolve_config_parses_valid_web_addr() {
        let env = HashMap::new();
        let parsed = Args::try_parse_from([
            "rc-server",
            "--database-url",
            "postgres://cli:p@db/rc",
            "--web-addr",
            "127.0.0.1:21119",
        ])
        .unwrap();
        let cfg = resolve_config(parsed, lookup_from(&env)).unwrap();
        assert_eq!(cfg.web_addr, Some("127.0.0.1:21119".parse().unwrap()));
    }

    #[test]
    fn resolve_log_filter_prefers_rust_log_then_rc_log_then_default() {
        let empty = HashMap::new();
        assert_eq!(resolve_log_filter(lookup_from(&empty)), DEFAULT_LOG_FILTER);

        let only_rc = HashMap::from([("RUST_LOG", "  "), ("RC_LOG", "debug")]);
        assert_eq!(resolve_log_filter(lookup_from(&only_rc)), "debug");

        let both = HashMap::from([("RUST_LOG", "warn"), ("RC_LOG", "debug")]);
        assert_eq!(resolve_log_filter(lookup_from(&both)), "warn");
    }

    #[test]
    fn resolve_config_parses_allow_server_wol_default_false() {
        let env = HashMap::new();
        let parsed =
            Args::try_parse_from(["rc-server", "--database-url", "postgres://cli:p@db/rc"])
                .unwrap();
        let cfg = resolve_config(parsed, lookup_from(&env)).unwrap();
        assert!(!cfg.allow_server_wol);

        let parsed_true = Args::try_parse_from([
            "rc-server",
            "--database-url",
            "postgres://cli:p@db/rc",
            "--allow-server-wol=true",
        ])
        .unwrap();
        let cfg_true = resolve_config(parsed_true, lookup_from(&env)).unwrap();
        assert!(cfg_true.allow_server_wol);

        let env_fallback = HashMap::from([("RC_ALLOW_SERVER_WOL", "true")]);
        let parsed_env =
            Args::try_parse_from(["rc-server", "--database-url", "postgres://cli:p@db/rc"])
                .unwrap();
        let cfg_env = resolve_config(parsed_env, lookup_from(&env_fallback)).unwrap();
        assert!(cfg_env.allow_server_wol);
    }
}
