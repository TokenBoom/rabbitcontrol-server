#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use rc_server::api::{
    self, AdminSettingsResponse, AdminUserMutationResponse, AdminUsersResponse,
    AdvertisedEndpoints, AppState, AuthConfigResponse, AuthRateLimiter, AuthTokenResponse,
    DeviceBindingResponse, DevicesResponse, ErrorBody, HealthResponse, IssueCertResponse,
    MyDevicesResponse, PkiCaResponse, RefreshTokenResponse,
};
use rc_server::auth::{
    ensure_initial_admin, hash_token_sha256_hex, verify_owner_grant_with_pubkey, AuthAuthority,
};
use rc_server::ephemeral::{EphemeralStore, MemoryEphemeralStore, SettingsCache};
use rc_server::pki::{parse_peer_cert_identity, PkiAuthority};
use rc_server::relay::{
    encode_relay_handshake, RelayConfig, RelayServer, REPLY_ERR, REPLY_OK, ROLE_CLIENT, ROLE_HOST,
};
use rc_server::signal::{
    read_signal_frame, write_signal_frame, SignalConfig, SignalHub, SignalMsg,
};
use rc_server::store::{DeviceStore, MemoryDeviceStore, PkiStore, UserStore};

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

struct SecureTestCluster {
    http_addr: SocketAddr,
    signal_addr: SocketAddr,
    relay_addr: SocketAddr,
    store: Arc<MemoryDeviceStore>,
    ephemeral: Arc<MemoryEphemeralStore>,
    auth_authority: Arc<AuthAuthority>,
    pki_authority: Arc<PkiAuthority>,
    hub: Arc<SignalHub>,
    relay: Arc<RelayServer>,
    client_tls_no_cert: Arc<ClientConfig>,
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl SecureTestCluster {
    async fn start_fresh() -> Self {
        let store = Arc::new(MemoryDeviceStore::new());
        let ephemeral = Arc::new(MemoryEphemeralStore::new());
        Self::start_with_store(store, ephemeral, AuthRateLimiter::default()).await
    }

    async fn start_with_store(
        store: Arc<MemoryDeviceStore>,
        ephemeral: Arc<MemoryEphemeralStore>,
        rate_limiter: AuthRateLimiter,
    ) -> Self {
        ensure_crypto_provider();

        let auth_authority = Arc::new(AuthAuthority::load_or_create(&*store).await.unwrap());
        let pki_authority = Arc::new(PkiAuthority::load_or_create(&*store).await.unwrap());
        let server_cert = pki_authority
            .issue_default_server_tls_cert(Some("127.0.0.1"), &[])
            .unwrap();

        let https_tls = pki_authority
            .build_server_tls_config(&server_cert, false)
            .unwrap();
        let signal_tls = pki_authority
            .build_server_tls_config(&server_cert, false)
            .unwrap();
        let relay_mtls = pki_authority
            .build_server_tls_config(&server_cert, true)
            .unwrap();

        let signal_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let signal_addr = signal_listener.local_addr().unwrap();
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();

        let settings_cache = Arc::new(SettingsCache::new(store.clone(), ephemeral.clone()));

        let hub = Arc::new(SignalHub::with_auth(
            store.clone(),
            ephemeral.clone(),
            auth_authority.clone(),
            SignalConfig {
                public_udp_probe_addr: signal_addr.to_string(),
                public_relay_addr: relay_addr.to_string(),
                require_auth: true,
                ..SignalConfig::default()
            },
        ));

        let relay = Arc::new(RelayServer::new(
            store.clone(),
            ephemeral.clone(),
            RelayConfig {
                handshake_timeout: Duration::from_secs(5),
                pair_timeout: Duration::from_secs(5),
                ..RelayConfig::default()
            },
        ));

        let app = api::router(AppState {
            device_store: store.clone(),
            auth_store: store.clone(),
            ephemeral: ephemeral.clone(),
            auth_authority: auth_authority.clone(),
            pki_authority: pki_authority.clone(),
            settings_cache,
            signal_hub: hub.clone(),
            relay_server: relay.clone(),
            endpoints: AdvertisedEndpoints {
                signal_tcp_addr: signal_addr.to_string(),
                udp_probe_addr: signal_addr.to_string(),
                udp_probe_alt_addr: None,
                tcp_relay_addr: relay_addr.to_string(),
            },
            started_at: Instant::now(),
            admin_token: None,
            cors_origins: Vec::new(),
            tls_enabled: true,
            web_dir: None,
            auth_rate_limiter: Arc::new(rate_limiter),
            allow_unauthenticated_legacy_admin: false,
        });

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let sig_task = tokio::spawn({
            let hub = hub.clone();
            let rx = shutdown_rx.clone();
            async move {
                let _ = hub
                    .serve_tls_signaling_on_listener_with_shutdown(signal_listener, signal_tls, rx)
                    .await;
            }
        });

        let relay_task = tokio::spawn({
            let relay = relay.clone();
            let store = store.clone();
            let rx = shutdown_rx.clone();
            async move {
                let _ = relay
                    .serve_tls_on_listener_with_shutdown(relay_listener, relay_mtls, store, rx)
                    .await;
            }
        });

        let https_task = tokio::spawn({
            let rx = shutdown_rx.clone();
            async move {
                let _ = api::serve_https(http_listener, https_tls, app, rx).await;
            }
        });

        let roots = pki_authority.root_cert_store().unwrap();
        let client_tls_no_cert = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        Self {
            http_addr,
            signal_addr,
            relay_addr,
            store,
            ephemeral,
            auth_authority,
            pki_authority,
            hub,
            relay,
            client_tls_no_cert,
            shutdown_tx,
            tasks: vec![sig_task, relay_task, https_task],
        }
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        self.hub.shutdown_all().await;
        self.relay.shutdown_all().await;
        for t in self.tasks {
            t.abort();
        }
    }
}

async fn send_http_request<S>(
    stream: &mut S,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&Value>,
) -> (u16, String)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let payload = body.map(|b| serde_json::to_vec(b).unwrap());
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: application/json\r\n"
    );
    if let Some(tok) = bearer {
        req.push_str(&format!("Authorization: Bearer {tok}\r\n"));
    }
    if let Some(ref bytes) = payload {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", bytes.len()));
    }
    req.push_str("\r\n");

    stream.write_all(req.as_bytes()).await.unwrap();
    if let Some(ref bytes) = payload {
        stream.write_all(bytes).await.unwrap();
    }
    stream.flush().await.unwrap();

    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw).await;

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP response header terminator");
    let header_str = std::str::from_utf8(&raw[..header_end]).unwrap();
    let status: u16 = header_str
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();

    let is_chunked = header_str.lines().any(|line| {
        line.to_ascii_lowercase().starts_with("transfer-encoding:")
            && line.to_ascii_lowercase().contains("chunked")
    });
    let body_bytes = &raw[header_end + 4..];
    let decoded = if is_chunked {
        decode_chunked(body_bytes)
    } else {
        body_bytes.to_vec()
    };

    (status, String::from_utf8(decoded).unwrap())
}

async fn https_json(
    addr: SocketAddr,
    tls_cfg: &Arc<ClientConfig>,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&Value>,
) -> (u16, String) {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = TlsConnector::from(Arc::clone(tls_cfg));
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    send_http_request(&mut tls, method, path, bearer, body).await
}

async fn http_plain(
    addr: SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&Value>,
) -> (u16, String) {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    send_http_request(&mut tcp, method, path, bearer, body).await
}

fn decode_chunked(mut input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(pos) = input.windows(2).position(|w| w == b"\r\n") {
        let len_str = std::str::from_utf8(&input[..pos])
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .trim();
        let len = usize::from_str_radix(len_str, 16).unwrap();
        input = &input[pos + 2..];
        if len == 0 {
            break;
        }
        out.extend_from_slice(&input[..len]);
        input = &input[len + 2..];
    }
    out
}

async fn connect_tls_signal(
    addr: SocketAddr,
    tls_cfg: &Arc<ClientConfig>,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = TlsConnector::from(Arc::clone(tls_cfg));
    let server_name = ServerName::try_from("localhost").unwrap();
    connector.connect(server_name, tcp).await.unwrap()
}

fn generate_ecdsa_csr_and_key() -> (String, Vec<u8>) {
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "rc-device");
    let csr = params.serialize_request(&kp).unwrap();
    (csr.pem().unwrap(), kp.serialize_der())
}

fn build_mtls_client_config(
    ca_cert_pem: &str,
    leaf_cert_pem: &str,
    leaf_key_pkcs8_der: &[u8],
) -> Arc<ClientConfig> {
    let mut ca_reader = std::io::BufReader::new(ca_cert_pem.as_bytes());
    let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut roots = RootCertStore::empty();
    for c in ca_certs {
        roots.add(c).unwrap();
    }

    let mut leaf_reader = std::io::BufReader::new(leaf_cert_pem.as_bytes());
    let leaf_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut leaf_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_pkcs8_der.to_vec()));

    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(leaf_chain, key)
            .unwrap(),
    )
}

#[tokio::test]
async fn initial_admin_must_change_password_gate_and_settings_toggle() {
    let cluster = SecureTestCluster::start_fresh().await;

    // 1. First boot generates initial admin with must_change_password = true; idempotent on repeat.
    let creds = ensure_initial_admin(&*cluster.store, Some("admin@rc.local"))
        .await
        .unwrap()
        .expect("initial admin must be created");
    assert_eq!(creds.email, "admin@rc.local");
    assert_eq!(creds.password.len(), 16);
    assert!(ensure_initial_admin(&*cluster.store, None)
        .await
        .unwrap()
        .is_none());

    // Health endpoint exposes TLS + CA fingerprint + allow_registration + cache_backend.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "GET",
        "/api/v1/health",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200, "health: {body}");
    let health: HealthResponse = serde_json::from_str(&body).unwrap();
    assert!(health.tls_enabled);
    assert_eq!(
        health.ca_fingerprint_sha256,
        cluster.pki_authority.ca_fingerprint_sha256()
    );
    assert!(health.allow_registration);
    assert_eq!(health.cache_backend, "memory");

    // 2. Login as initial admin -> must_change_password=true, pwd_change_only=true JWT.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&serde_json::json!({
            "email": "admin@rc.local",
            "password": creds.password,
        })),
    )
    .await;
    assert_eq!(status, 200, "login: {body}");
    let login_res: AuthTokenResponse = serde_json::from_str(&body).unwrap();
    assert!(login_res.user.must_change_password);
    let claims = cluster
        .auth_authority
        .verify_access_token(&login_res.access_token)
        .unwrap();
    assert!(claims.pwd_change_only);

    // 3. GET /api/v1/me is allowed while must_change_password=true.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "GET",
        "/api/v1/me",
        Some(&login_res.access_token),
        None,
    )
    .await;
    assert_eq!(status, 200, "/me must work before password change: {body}");

    // 4. All other user/admin routes MUST reject with 403 password_change_required!
    for (method, path, payload) in [
        ("GET", "/api/v1/me/devices", None),
        (
            "POST",
            "/api/v1/me/devices/bind",
            Some(serde_json::json!({ "device_key": "dk-1" })),
        ),
        (
            "POST",
            "/api/v1/certs/issue",
            Some(serde_json::json!({ "device_id": "123456789", "csr_pem": "x" })),
        ),
        ("GET", "/api/v1/admin/users", None),
        ("GET", "/api/v1/admin/settings", None),
        (
            "PATCH",
            "/api/v1/admin/settings",
            Some(serde_json::json!({ "allow_registration": false })),
        ),
        ("GET", "/api/v1/stats", None),
        ("GET", "/api/v1/devices", None),
        ("GET", "/api/v1/sessions", None),
    ] {
        let (status, body) = https_json(
            cluster.http_addr,
            &cluster.client_tls_no_cert,
            method,
            path,
            Some(&login_res.access_token),
            payload.as_ref(),
        )
        .await;
        assert_eq!(status, 403, "{method} {path} must be blocked: {body}");
        let err: ErrorBody = serde_json::from_str(&body).unwrap();
        assert_eq!(err.error, "password_change_required");
    }

    // TLS signaling also rejects pwd_change_only token.
    let mut sig = connect_tls_signal(cluster.signal_addr, &cluster.client_tls_no_cert).await;
    write_signal_frame(
        &mut sig,
        &SignalMsg::Register {
            device_id: None,
            device_key: "ed25519:admin-dev".into(),
            hostname: "admin-box".into(),
            os: "linux".into(),
            app_version: String::new(),
            arch: String::new(),
            device_group: "".into(),
            lan_addrs: vec![],
            access_token: Some(login_res.access_token.clone()),
            device_pubkey: None,
            allow_remote_assist: None,
            allow_remote_control: None,
            mac_addr: None,
            wol_enabled: None,
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_signal_frame(&mut sig).await.unwrap().unwrap(),
        SignalMsg::Error { code, .. } if code == "password_change_required"
    ));

    // 5. Change password -> returns full-privilege tokens and invalidates old token.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/change-password",
        Some(&login_res.access_token),
        Some(&serde_json::json!({
            "current_password": creds.password,
            "new_password": "NewStrongAdminPassword!2026",
        })),
    )
    .await;
    assert_eq!(status, 200, "change-password: {body}");
    let changed: RefreshTokenResponse = serde_json::from_str(&body).unwrap();
    assert!(!changed.user.must_change_password);
    let new_claims = cluster
        .auth_authority
        .verify_access_token(&changed.access_token)
        .unwrap();
    assert!(!new_claims.pwd_change_only);

    // Old token is invalidated by token_version bump.
    let (status, _) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "GET",
        "/api/v1/me",
        Some(&login_res.access_token),
        None,
    )
    .await;
    assert_eq!(status, 401);

    // 6. Admin toggles allow_registration off -> SettingsCache & /auth/config reflect immediately -> register returns 403.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "PATCH",
        "/api/v1/admin/settings",
        Some(&changed.access_token),
        Some(&serde_json::json!({ "allow_registration": false })),
    )
    .await;
    assert_eq!(status, 200, "patch settings: {body}");
    let settings: AdminSettingsResponse = serde_json::from_str(&body).unwrap();
    assert!(!settings.allow_registration);
    assert_eq!(settings.cache_backend, "memory");
    assert_eq!(
        cluster.ephemeral.get_allow_registration().await.unwrap(),
        Some(false)
    );

    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "GET",
        "/api/v1/auth/config",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let cfg: AuthConfigResponse = serde_json::from_str(&body).unwrap();
    assert!(!cfg.allow_registration);

    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/register",
        None,
        Some(&serde_json::json!({
            "email": "blocked@example.com",
            "password": "Password123!",
        })),
    )
    .await;
    assert_eq!(status, 403, "register while disabled: {body}");
    let err: ErrorBody = serde_json::from_str(&body).unwrap();
    assert_eq!(err.error, "registration_disabled");

    // Toggle back to true -> registration succeeds.
    let (status, _) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "PATCH",
        "/api/v1/admin/settings",
        Some(&changed.access_token),
        Some(&serde_json::json!({ "allow_registration": true })),
    )
    .await;
    assert_eq!(status, 200);

    let (status, _) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/register",
        None,
        Some(&serde_json::json!({
            "email": "alice@example.com",
            "password": "Password123!",
            "display_name": "Alice",
        })),
    )
    .await;
    assert_eq!(status, 200);

    cluster.shutdown().await;
}

#[tokio::test]
async fn register_login_bind_cert_issue_refresh_replay_and_restart_persistence() {
    let store = Arc::new(MemoryDeviceStore::new());
    let ephemeral = Arc::new(MemoryEphemeralStore::new());
    let cluster = SecureTestCluster::start_with_store(
        store.clone(),
        ephemeral.clone(),
        AuthRateLimiter::default(),
    )
    .await;

    // 1. Register user with inline device bind over HTTPS.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/register",
        None,
        Some(&serde_json::json!({
            "email": "Bob@Example.COM",
            "password": "StrongPassword!99",
            "display_name": "Bob",
            "device_key": "dk-bob-1",
            "hostname": "bob-mac",
            "os": "macos",
            "device_pubkey": "11".repeat(32),
        })),
    )
    .await;
    assert_eq!(status, 200, "register: {body}");
    let reg: AuthTokenResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(reg.user.email, "bob@example.com");
    let bob_dev = reg.device.expect("inline device bound");
    assert_eq!(bob_dev.owner_user_id, Some(reg.user.id));

    // 2. Pull CA bundle via /api/v1/pki/ca and issue device cert via CSR.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "GET",
        "/api/v1/pki/ca",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let ca_resp: PkiCaResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(
        ca_resp.ca_fingerprint_sha256,
        cluster.pki_authority.ca_fingerprint_sha256()
    );
    assert_eq!(
        ca_resp.auth_pubkey_hex,
        cluster.auth_authority.public_key_hex()
    );

    let (csr_pem, _key_der) = generate_ecdsa_csr_and_key();
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/certs/issue",
        Some(&reg.access_token),
        Some(&serde_json::json!({
            "device_id": bob_dev.device_id,
            "csr_pem": csr_pem,
        })),
    )
    .await;
    assert_eq!(status, 200, "issue cert: {body}");
    let cert_resp: IssueCertResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(cert_resp.user_id, reg.user.id);
    assert_eq!(cert_resp.device_id, bob_dev.device_id);

    // Parse issued cert DER and verify SAN identity.
    let mut reader = std::io::BufReader::new(cert_resp.cert_pem.as_bytes());
    let cert_der = rustls_pemfile::certs(&mut reader).next().unwrap().unwrap();
    let id = parse_peer_cert_identity(cert_der.as_ref()).unwrap();
    assert_eq!(id.user_id, reg.user.id);
    assert_eq!(id.device_id, bob_dev.device_id);

    // 3. Rotate refresh token r1 -> r2.
    let r1 = reg.refresh_token.clone();
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(&serde_json::json!({ "refresh_token": r1 })),
    )
    .await;
    assert_eq!(status, 200, "refresh r1->r2: {body}");
    let rot1: RefreshTokenResponse = serde_json::from_str(&body).unwrap();
    let r2 = rot1.refresh_token.clone();
    assert_ne!(r1, r2);

    // 4. Simulate full server restart reusing the same MemoryDeviceStore!
    // AuthAuthority and PkiAuthority reload persisted keys/CA; old access_token and r2 remain valid!
    let prev_auth_hex = cluster.auth_authority.public_key_hex();
    let prev_ca_fp = cluster.pki_authority.ca_fingerprint_sha256().to_string();
    cluster.shutdown().await;

    let restarted = SecureTestCluster::start_with_store(
        store.clone(),
        ephemeral.clone(),
        AuthRateLimiter::default(),
    )
    .await;
    assert_eq!(restarted.auth_authority.public_key_hex(), prev_auth_hex);
    assert_eq!(restarted.pki_authority.ca_fingerprint_sha256(), prev_ca_fp);

    // Original access token issued BEFORE restart still works on /api/v1/me!
    let (status, body) = https_json(
        restarted.http_addr,
        &restarted.client_tls_no_cert,
        "GET",
        "/api/v1/me",
        Some(&rot1.access_token),
        None,
    )
    .await;
    assert_eq!(
        status, 200,
        "access token must stay valid across server restart: {body}"
    );

    // r2 issued BEFORE restart rotates cleanly to r3 AFTER restart!
    let (status, body) = https_json(
        restarted.http_addr,
        &restarted.client_tls_no_cert,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(&serde_json::json!({ "refresh_token": r2 })),
    )
    .await;
    assert_eq!(
        status, 200,
        "refresh token must stay valid across server restart: {body}"
    );
    let rot2: RefreshTokenResponse = serde_json::from_str(&body).unwrap();
    let r3 = rot2.refresh_token.clone();

    // 5. Simulate expired grace window replay attack: rotate r3 -> r4 with Duration::ZERO grace,
    // then replay r3 via HTTP POST /api/v1/auth/refresh -> must return 401 token_reuse_detected
    // and revoke the entire family (so r4 is also invalidated)!
    let r4_raw = "synthetic_r4_token_after_grace_000000000000";
    let r3_hash = hash_token_sha256_hex(&r3);
    let r4_hash = hash_token_sha256_hex(r4_raw);
    restarted
        .store
        .rotate_refresh_token(
            &r3_hash,
            &r4_hash,
            Utc::now() + chrono::Duration::days(30),
            Duration::ZERO,
        )
        .await
        .unwrap();

    let (status, body) = https_json(
        restarted.http_addr,
        &restarted.client_tls_no_cert,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(&serde_json::json!({ "refresh_token": r3 })),
    )
    .await;
    assert_eq!(status, 401, "replayed token must return 401: {body}");
    let err: ErrorBody = serde_json::from_str(&body).unwrap();
    assert_eq!(err.error, "token_reuse_detected");

    // Victim's r4 in the same family is now revoked too!
    let (status, _) = https_json(
        restarted.http_addr,
        &restarted.client_tls_no_cert,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(&serde_json::json!({ "refresh_token": r4_raw })),
    )
    .await;
    assert_eq!(status, 401, "entire token family must be revoked on replay");

    restarted.shutdown().await;
}

#[tokio::test]
async fn signaling_owner_grant_assist_gate_and_mtls_relay_enforcement() {
    let cluster = SecureTestCluster::start_fresh().await;

    // Register User A (with 2 devices: host_a and client_a) and User B (stranger_b).
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/register",
        None,
        Some(&serde_json::json!({
            "email": "usera@example.com",
            "password": "PasswordA!123",
        })),
    )
    .await;
    assert_eq!(status, 200);
    let user_a: AuthTokenResponse = serde_json::from_str(&body).unwrap();

    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/register",
        None,
        Some(&serde_json::json!({
            "email": "userb@example.com",
            "password": "PasswordB!123",
        })),
    )
    .await;
    assert_eq!(status, 200);
    let user_b: AuthTokenResponse = serde_json::from_str(&body).unwrap();

    // Connect host_a, client_a (same user A), and stranger_b (user B) over TLS 1.3 signaling.
    let mut host_sig = connect_tls_signal(cluster.signal_addr, &cluster.client_tls_no_cert).await;
    write_signal_frame(
        &mut host_sig,
        &SignalMsg::Register {
            device_id: None,
            device_key: "dk-host-a".into(),
            hostname: "host-a".into(),
            os: "macos".into(),
            app_version: String::new(),
            arch: String::new(),
            device_group: "prod".into(),
            lan_addrs: vec!["10.0.0.1:50000".into()],
            access_token: Some(user_a.access_token.clone()),
            device_pubkey: Some("aa".repeat(32)),
            allow_remote_assist: Some(false),
            allow_remote_control: None,
            mac_addr: None,
            wol_enabled: None,
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    let host_id = match read_signal_frame(&mut host_sig).await.unwrap().unwrap() {
        SignalMsg::Registered { device_id, .. } => device_id,
        other => panic!("expected Registered for host_a, got {other:?}"),
    };

    let caller_pk_hex = "bb".repeat(32);
    let mut client_sig = connect_tls_signal(cluster.signal_addr, &cluster.client_tls_no_cert).await;
    write_signal_frame(
        &mut client_sig,
        &SignalMsg::Register {
            device_id: None,
            device_key: "dk-client-a".into(),
            hostname: "client-a".into(),
            os: "linux".into(),
            app_version: String::new(),
            arch: String::new(),
            device_group: "prod".into(),
            lan_addrs: vec!["10.0.0.2:50001".into()],
            access_token: Some(user_a.access_token.clone()),
            device_pubkey: Some(caller_pk_hex.clone()),
            allow_remote_assist: Some(false),
            allow_remote_control: None,
            mac_addr: None,
            wol_enabled: None,
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    let client_id = match read_signal_frame(&mut client_sig).await.unwrap().unwrap() {
        SignalMsg::Registered { device_id, .. } => device_id,
        other => panic!("expected Registered for client_a, got {other:?}"),
    };

    // host_a must receive DeviceStatusChanged(online: true) for same-account client_a!
    let status_evt = read_signal_frame(&mut host_sig).await.unwrap().unwrap();
    assert!(matches!(
        status_evt,
        SignalMsg::DeviceStatusChanged {
            ref device_id,
            online: true,
            allow_remote_assist: false,
            ..
        } if device_id == &client_id
    ));

    let mut stranger_sig =
        connect_tls_signal(cluster.signal_addr, &cluster.client_tls_no_cert).await;
    write_signal_frame(
        &mut stranger_sig,
        &SignalMsg::Register {
            device_id: None,
            device_key: "dk-stranger-b".into(),
            hostname: "stranger-b".into(),
            os: "windows".into(),
            app_version: String::new(),
            arch: String::new(),
            device_group: "".into(),
            lan_addrs: vec![],
            access_token: Some(user_b.access_token.clone()),
            device_pubkey: Some("cc".repeat(32)),
            allow_remote_assist: Some(false),
            allow_remote_control: None,
            mac_addr: None,
            wol_enabled: None,
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    let stranger_id = match read_signal_frame(&mut stranger_sig).await.unwrap().unwrap() {
        SignalMsg::Registered { device_id, .. } => device_id,
        other => panic!("expected Registered for stranger_b, got {other:?}"),
    };

    // 1. Same-account self-control ignores allow_remote_assist=false and issues owner_grant!
    write_signal_frame(
        &mut client_sig,
        &SignalMsg::ConnectRequest {
            target_id: host_id.clone(),
            session_id: Some("sess-owner-1".into()),
            lan_addrs: vec![],
            nonce: Some("n1".into()),
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    let client_punch = read_signal_frame(&mut client_sig).await.unwrap().unwrap();
    let host_punch = read_signal_frame(&mut host_sig).await.unwrap().unwrap();
    let relay_token = match (client_punch, host_punch) {
        (
            SignalMsg::PunchCoord {
                role,
                relay_token: ct,
                owner_grant: Some(ticket),
                is_owner_connection: true,
                ..
            },
            SignalMsg::PunchCoord {
                role: hrole,
                relay_token: ht,
                owner_grant: None,
                is_owner_connection: true,
                ..
            },
        ) => {
            assert_eq!(role, "client");
            assert_eq!(hrole, "host");
            assert_eq!(ct, ht);
            assert_eq!(ticket.user_id, user_a.user.id);
            assert_eq!(ticket.caller_device_id, client_id);
            assert_eq!(ticket.caller_pubkey_hex, caller_pk_hex);
            assert_eq!(ticket.target_device_id, host_id);
            let now_sec = Utc::now().timestamp();
            verify_owner_grant_with_pubkey(
                &ticket,
                cluster.auth_authority.public_key_bytes(),
                now_sec,
            )
            .expect("owner_grant signature must verify");
            ct
        }
        other => panic!("expected owner PunchCoord, got {other:?}"),
    };

    // 2. Different-account connect_request & relay_alloc MUST be rejected with assist_disabled!
    write_signal_frame(
        &mut stranger_sig,
        &SignalMsg::ConnectRequest {
            target_id: host_id.clone(),
            session_id: Some("sess-stranger-blocked".into()),
            lan_addrs: vec![],
            nonce: None,
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_signal_frame(&mut stranger_sig).await.unwrap().unwrap(),
        SignalMsg::Error { code, .. } if code == "assist_disabled"
    ));

    write_signal_frame(
        &mut stranger_sig,
        &SignalMsg::RelayAlloc {
            target_id: host_id.clone(),
            session_id: Some("sess-stranger-relay-blocked".into()),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_signal_frame(&mut stranger_sig).await.unwrap().unwrap(),
        SignalMsg::Error { code, .. } if code == "assist_disabled"
    ));

    // Issue mTLS certs for host_a, client_a, and stranger_b.
    let (h_csr, h_key_der) = generate_ecdsa_csr_and_key();
    let (_, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/certs/issue",
        Some(&user_a.access_token),
        Some(&serde_json::json!({ "device_id": host_id, "csr_pem": h_csr })),
    )
    .await;
    let h_cert: IssueCertResponse = serde_json::from_str(&body).unwrap();

    let (c_csr, c_key_der) = generate_ecdsa_csr_and_key();
    let (_, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/certs/issue",
        Some(&user_a.access_token),
        Some(&serde_json::json!({ "device_id": client_id, "csr_pem": c_csr })),
    )
    .await;
    let c_cert: IssueCertResponse = serde_json::from_str(&body).unwrap();

    let (s_csr, s_key_der) = generate_ecdsa_csr_and_key();
    let (_, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/certs/issue",
        Some(&user_b.access_token),
        Some(&serde_json::json!({ "device_id": stranger_id, "csr_pem": s_csr })),
    )
    .await;
    let s_cert: IssueCertResponse = serde_json::from_str(&body).unwrap();

    let host_mtls_cfg = build_mtls_client_config(&h_cert.ca_cert_pem, &h_cert.cert_pem, &h_key_der);
    let client_mtls_cfg =
        build_mtls_client_config(&c_cert.ca_cert_pem, &c_cert.cert_pem, &c_key_der);
    let stranger_mtls_cfg =
        build_mtls_client_config(&s_cert.ca_cert_pem, &s_cert.cert_pem, &s_key_der);

    // 3. mTLS Relay rejects client without certificate at TLS handshake!
    {
        let tcp = TcpStream::connect(cluster.relay_addr).await.unwrap();
        let connector = TlsConnector::from(Arc::clone(&cluster.client_tls_no_cert));
        let mut tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        // TLS 1.3 post-handshake or handshake rejects missing client cert when reading/writing.
        let _ = tls
            .write_all(&encode_relay_handshake(ROLE_HOST, &relay_token).unwrap())
            .await;
        let mut buf = [0u8; 1];
        let res = tls.read_exact(&mut buf).await;
        assert!(res.is_err(), "relay must reject peer without client cert");
    }

    // 4. mTLS Relay rejects mismatched device cert ("串号证书"): stranger_b's cert cannot claim client_a's token!
    {
        let tcp = TcpStream::connect(cluster.relay_addr).await.unwrap();
        let mut tls = TlsConnector::from(Arc::clone(&stranger_mtls_cfg))
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        // Also allocate a dedicated token for this mismatch test so relay_token stays unused.
        write_signal_frame(
            &mut client_sig,
            &SignalMsg::RelayAlloc {
                target_id: host_id.clone(),
                session_id: Some("sess-mismatch-test".into()),
            },
        )
        .await
        .unwrap();
        let mismatch_tok = match read_signal_frame(&mut client_sig).await.unwrap().unwrap() {
            SignalMsg::RelayReady { relay_token, .. } => relay_token,
            other => panic!("expected RelayReady, got {other:?}"),
        };
        let _ = read_signal_frame(&mut host_sig).await.unwrap().unwrap();

        tls.write_all(&encode_relay_handshake(ROLE_CLIENT, &mismatch_tok).unwrap())
            .await
            .unwrap();
        let mut reply = [0u8; 1];
        tls.read_exact(&mut reply).await.unwrap();
        assert_eq!(
            reply[0], REPLY_ERR,
            "wrong device cert must receive REPLY_ERR"
        );
    }

    // 5. Legitimate dual mTLS certs pair and transfer 512 KiB with SHA-256 match!
    {
        let h_tcp = TcpStream::connect(cluster.relay_addr).await.unwrap();
        let mut h_tls = TlsConnector::from(Arc::clone(&host_mtls_cfg))
            .connect(ServerName::try_from("localhost").unwrap(), h_tcp)
            .await
            .unwrap();
        let c_tcp = TcpStream::connect(cluster.relay_addr).await.unwrap();
        let mut c_tls = TlsConnector::from(Arc::clone(&client_mtls_cfg))
            .connect(ServerName::try_from("localhost").unwrap(), c_tcp)
            .await
            .unwrap();

        h_tls
            .write_all(&encode_relay_handshake(ROLE_HOST, &relay_token).unwrap())
            .await
            .unwrap();
        c_tls
            .write_all(&encode_relay_handshake(ROLE_CLIENT, &relay_token).unwrap())
            .await
            .unwrap();

        let mut h_ack = [0u8; 1];
        let mut c_ack = [0u8; 1];
        h_tls.read_exact(&mut h_ack).await.unwrap();
        c_tls.read_exact(&mut c_ack).await.unwrap();
        assert_eq!(h_ack[0], REPLY_OK);
        assert_eq!(c_ack[0], REPLY_OK);

        let payload: Vec<u8> = (0..(512 * 1024)).map(|i| (i % 251) as u8).collect();
        let expected_sha = Sha256::digest(&payload);

        let (mut hr, mut hw) = tokio::io::split(h_tls);
        let (mut cr, mut cw) = tokio::io::split(c_tls);

        let send_task = tokio::spawn({
            let data = payload.clone();
            async move {
                hw.write_all(&data).await.unwrap();
                hw.shutdown().await.unwrap();
            }
        });
        let recv_task = tokio::spawn(async move {
            let mut got = Vec::new();
            cr.read_to_end(&mut got).await.unwrap();
            got
        });
        let _ = cw.shutdown().await;
        let mut back = Vec::new();
        let _ = hr.read_to_end(&mut back).await;

        send_task.await.unwrap();
        let got = recv_task.await.unwrap();
        assert_eq!(Sha256::digest(&got), expected_sha);
    }

    // 6. Revoked cert is rejected immediately by mTLS relay!
    {
        cluster
            .store
            .revoke_cert_by_serial(&h_cert.serial_hex, Some("test_revoke"))
            .await
            .unwrap();
        cluster
            .ephemeral
            .revoke_cert_serial(&h_cert.serial_hex, Duration::from_secs(60))
            .await
            .unwrap();

        write_signal_frame(
            &mut client_sig,
            &SignalMsg::RelayAlloc {
                target_id: host_id.clone(),
                session_id: Some("sess-revoked".into()),
            },
        )
        .await
        .unwrap();
        let rev_tok = match read_signal_frame(&mut client_sig).await.unwrap().unwrap() {
            SignalMsg::RelayReady { relay_token, .. } => relay_token,
            other => panic!("expected RelayReady, got {other:?}"),
        };
        let _ = read_signal_frame(&mut host_sig).await.unwrap().unwrap();

        let h_tcp = TcpStream::connect(cluster.relay_addr).await.unwrap();
        let mut h_tls = TlsConnector::from(Arc::clone(&host_mtls_cfg))
            .connect(ServerName::try_from("localhost").unwrap(), h_tcp)
            .await
            .unwrap();
        let _ = h_tls
            .write_all(&encode_relay_handshake(ROLE_HOST, &rev_tok).unwrap())
            .await;
        let mut reply = [0u8; 1];
        let res = h_tls.read_exact(&mut reply).await;
        assert!(
            res.is_err(),
            "revoked cert must be rejected without REPLY_OK"
        );
    }

    // 7. host_a toggles UpdateAssistState(true) -> client_a sees DeviceStatusChanged -> stranger_b succeeds!
    write_signal_frame(
        &mut host_sig,
        &SignalMsg::UpdateAssistState {
            allow_remote_assist: Some(true),
            allow_remote_control: None,
            mac_addr: None,
            wol_enabled: None,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_signal_frame(&mut client_sig).await.unwrap().unwrap(),
        SignalMsg::DeviceStatusChanged {
            ref device_id,
            online: true,
            allow_remote_assist: true,
            ..
        } if device_id == &host_id
    ));

    write_signal_frame(
        &mut stranger_sig,
        &SignalMsg::ConnectRequest {
            target_id: host_id.clone(),
            session_id: Some("sess-stranger-allowed".into()),
            lan_addrs: vec![],
            nonce: None,
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_signal_frame(&mut stranger_sig).await.unwrap().unwrap(),
        SignalMsg::PunchCoord {
            is_owner_connection: false,
            owner_grant: None,
            ..
        }
    ));
    assert!(matches!(
        read_signal_frame(&mut host_sig).await.unwrap().unwrap(),
        SignalMsg::PunchCoord {
            is_owner_connection: false,
            owner_grant: None,
            ..
        }
    ));

    cluster.shutdown().await;
}

#[tokio::test]
async fn admin_disable_and_delete_user_kicks_signal_relay_and_protects_last_admin() {
    let cluster = SecureTestCluster::start_fresh().await;

    // Bootstrap & activate initial admin.
    let creds = ensure_initial_admin(&*cluster.store, Some("root@rc.local"))
        .await
        .unwrap()
        .unwrap();
    let (_, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&serde_json::json!({
            "email": "root@rc.local",
            "password": creds.password,
        })),
    )
    .await;
    let init_login: AuthTokenResponse = serde_json::from_str(&body).unwrap();
    let (_, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/change-password",
        Some(&init_login.access_token),
        Some(&serde_json::json!({
            "current_password": creds.password,
            "new_password": "RootPassword!999",
        })),
    )
    .await;
    let admin: RefreshTokenResponse = serde_json::from_str(&body).unwrap();

    // Cannot delete last active admin!
    let (status, _) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "DELETE",
        &format!("/api/v1/admin/users/{}", admin.user.id),
        Some(&admin.access_token),
        None,
    )
    .await;
    assert_eq!(status, 403);

    // Admin creates user C.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/admin/users",
        Some(&admin.access_token),
        Some(&serde_json::json!({
            "email": "charlie@rc.local",
            "display_name": "Charlie",
            "password": "CharliePassword!1",
            "role": "user",
            "must_change_password": false,
        })),
    )
    .await;
    assert_eq!(status, 200, "create user: {body}");
    let created: AdminUserMutationResponse = serde_json::from_str(&body).unwrap();
    let charlie_id = created.user.id;

    // Charlie logs in with device & connects signaling + issues cert.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&serde_json::json!({
            "email": "charlie@rc.local",
            "password": "CharliePassword!1",
            "device_key": "dk-charlie-1",
            "hostname": "charlie-box",
            "os": "linux",
        })),
    )
    .await;
    assert_eq!(status, 200);
    let charlie_login: AuthTokenResponse = serde_json::from_str(&body).unwrap();
    let charlie_dev = charlie_login.device.unwrap();

    let (csr, _) = generate_ecdsa_csr_and_key();
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/certs/issue",
        Some(&charlie_login.access_token),
        Some(&serde_json::json!({
            "device_id": charlie_dev.device_id,
            "csr_pem": csr,
        })),
    )
    .await;
    assert_eq!(status, 200);
    let charlie_cert: IssueCertResponse = serde_json::from_str(&body).unwrap();

    // Admin GET /api/v1/devices includes owner_email.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "GET",
        "/api/v1/devices",
        Some(&admin.access_token),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let devs: DevicesResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(
        devs.devices[0].owner_email.as_deref(),
        Some("charlie@rc.local")
    );

    let mut sig = connect_tls_signal(cluster.signal_addr, &cluster.client_tls_no_cert).await;
    write_signal_frame(
        &mut sig,
        &SignalMsg::Register {
            device_id: Some(charlie_dev.device_id.clone()),
            device_key: "dk-charlie-1".into(),
            hostname: "charlie-box".into(),
            os: "linux".into(),
            app_version: String::new(),
            arch: String::new(),
            device_group: "".into(),
            lan_addrs: vec![],
            access_token: Some(charlie_login.access_token.clone()),
            device_pubkey: None,
            allow_remote_assist: None,
            allow_remote_control: None,
            mac_addr: None,
            wol_enabled: None,
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_signal_frame(&mut sig).await.unwrap().unwrap(),
        SignalMsg::Registered { .. }
    ));

    // Admin disables Charlie -> immediate Kicked + cert revoked + refresh rejected!
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "PATCH",
        &format!("/api/v1/admin/users/{charlie_id}"),
        Some(&admin.access_token),
        Some(&serde_json::json!({ "status": "disabled" })),
    )
    .await;
    assert_eq!(status, 200, "disable charlie: {body}");

    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), read_signal_frame(&mut sig))
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        SignalMsg::Kicked { reason } if reason == "account_updated"
    ));
    assert!(cluster
        .ephemeral
        .is_cert_revoked(&charlie_cert.serial_hex)
        .await
        .unwrap());
    let (status, _) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(&serde_json::json!({ "refresh_token": charlie_login.refresh_token })),
    )
    .await;
    assert_eq!(status, 401);

    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&serde_json::json!({
            "email": "charlie@rc.local",
            "password": "CharliePassword!1",
        })),
    )
    .await;
    assert_eq!(status, 403, "disabled user login must return 403: {body}");

    // Admin lists users -> sees root + charlie.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "GET",
        "/api/v1/admin/users",
        Some(&admin.access_token),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let users_resp: AdminUsersResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(users_resp.total, 2);

    // Admin deletes Charlie -> device unbound & user removed.
    let (status, _) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "DELETE",
        &format!("/api/v1/admin/users/{charlie_id}"),
        Some(&admin.access_token),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(cluster
        .store
        .get_by_id(&charlie_dev.device_id)
        .await
        .unwrap()
        .unwrap()
        .owner_user_id
        .is_none());

    cluster.shutdown().await;
}

#[tokio::test]
async fn auth_rate_limiter_blocks_burst_login_and_register() {
    let store = Arc::new(MemoryDeviceStore::new());
    let ephemeral = Arc::new(MemoryEphemeralStore::new());
    let cluster = SecureTestCluster::start_with_store(
        store,
        ephemeral,
        AuthRateLimiter::new(100, 2, Duration::from_secs(60)),
    )
    .await;

    for i in 0..2 {
        let (status, _) = https_json(
            cluster.http_addr,
            &cluster.client_tls_no_cert,
            "POST",
            "/api/v1/auth/login",
            None,
            Some(&serde_json::json!({
                "email": "bruteforce@example.com",
                "password": format!("wrong-{i}"),
            })),
        )
        .await;
        assert_eq!(status, 401);
    }

    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&serde_json::json!({
            "email": "bruteforce@example.com",
            "password": "wrong-3",
        })),
    )
    .await;
    assert_eq!(status, 429, "expected rate_limited: {body}");
    let err: ErrorBody = serde_json::from_str(&body).unwrap();
    assert_eq!(err.error, "rate_limited");

    cluster.shutdown().await;
}

#[tokio::test]
async fn logout_ownership_refresh_fallback_and_admin_disable_device_revokes_sessions() {
    let cluster = SecureTestCluster::start_fresh().await;

    // Register User A with device A and User B with device B.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/register",
        None,
        Some(&serde_json::json!({
            "email": "owner-a@example.com",
            "password": "PasswordA!123",
            "device_key": "dk-owner-a",
            "hostname": "host-a",
            "os": "macos",
        })),
    )
    .await;
    assert_eq!(status, 200);
    let user_a: AuthTokenResponse = serde_json::from_str(&body).unwrap();
    let dev_a = user_a.device.as_ref().unwrap().device_id.clone();

    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/register",
        None,
        Some(&serde_json::json!({
            "email": "owner-b@example.com",
            "password": "PasswordB!123",
            "device_key": "dk-owner-b",
            "hostname": "host-b",
            "os": "linux",
        })),
    )
    .await;
    assert_eq!(status, 200);
    let user_b: AuthTokenResponse = serde_json::from_str(&body).unwrap();
    let dev_b = user_b.device.as_ref().unwrap().device_id.clone();

    // User A cannot kick User B's device via /api/v1/auth/logout.
    let (status, _) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/logout",
        Some(&user_a.access_token),
        Some(&serde_json::json!({ "device_id": dev_b })),
    )
    .await;
    assert_eq!(status, 403, "cross-user device kick via logout must fail");

    // User A cannot kick User B's device via /api/v1/auth/logout, and refresh_token logout must
    // validate device ownership BEFORE revoking User A's refresh session.
    let (status, _) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/logout",
        None,
        Some(&serde_json::json!({
            "refresh_token": user_a.refresh_token,
            "device_id": dev_b,
        })),
    )
    .await;
    assert_eq!(
        status, 403,
        "cross-user device kick via refresh_token logout must fail"
    );

    // User A logs out with refresh_token only (simulating expired access_token) -> session still existed and now revokes cleanly.
    let (status, _) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/logout",
        Some("invalid.expired.bearer"),
        Some(&serde_json::json!({ "refresh_token": user_a.refresh_token })),
    )
    .await;
    assert_eq!(status, 200);

    let (status, _) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(&serde_json::json!({ "refresh_token": user_a.refresh_token })),
    )
    .await;
    assert_eq!(status, 401, "refresh must fail after refresh_token logout");

    // Replaying an already-revoked refresh_token to /api/v1/auth/logout must fail (401)
    // and must NOT kick a fresh active session of User A on the same device.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&serde_json::json!({
            "email": "owner-a@example.com",
            "password": "PasswordA!123",
            "device_key": "dk-owner-a",
        })),
    )
    .await;
    assert_eq!(status, 200);
    let user_a2: AuthTokenResponse = serde_json::from_str(&body).unwrap();

    let (status, _) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/logout",
        None,
        Some(&serde_json::json!({ "refresh_token": user_a.refresh_token })),
    )
    .await;
    assert_eq!(
        status, 401,
        "replaying already-revoked refresh_token to logout must fail"
    );

    let (status, _) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "GET",
        "/api/v1/me",
        Some(&user_a2.access_token),
        None,
    )
    .await;
    assert_eq!(status, 200, "fresh session must survive old refresh replay");

    // Admin logs in & changes initial password, then disables User B's device -> session revoked!
    let creds = ensure_initial_admin(&*cluster.store, Some("root@rc.local"))
        .await
        .unwrap()
        .unwrap();
    let (_, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&serde_json::json!({ "email": creds.email, "password": creds.password })),
    )
    .await;
    let init_login: AuthTokenResponse = serde_json::from_str(&body).unwrap();
    let (_, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/change-password",
        Some(&init_login.access_token),
        Some(&serde_json::json!({
            "current_password": creds.password,
            "new_password": "AdminPassword!999",
        })),
    )
    .await;
    let admin: RefreshTokenResponse = serde_json::from_str(&body).unwrap();

    // Search devices by owner email + check total_count.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "GET",
        "/api/v1/devices?q=owner-b@example.com&limit=1&offset=0",
        Some(&admin.access_token),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let dev_resp: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(dev_resp["total"], 1);
    assert_eq!(dev_resp["total_count"], 1);
    assert_eq!(dev_resp["devices"][0]["device_id"], dev_b);
    let _ = dev_a;

    // Disable device B via admin route -> revokes device B's refresh session too.
    let (status, _) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "DELETE",
        &format!("/api/v1/devices/{dev_b}"),
        Some(&admin.access_token),
        None,
    )
    .await;
    assert_eq!(status, 200);

    let (status, _) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(&serde_json::json!({ "refresh_token": user_b.refresh_token })),
    )
    .await;
    assert_eq!(
        status, 401,
        "refresh must fail after admin DELETE /api/v1/devices/{{id}}"
    );

    cluster.shutdown().await;
}

#[tokio::test]
async fn split_web_admin_and_client_api_ports_isolate_routes_and_static_ui() {
    ensure_crypto_provider();

    let store = Arc::new(MemoryDeviceStore::new());
    let ephemeral = Arc::new(MemoryEphemeralStore::new());
    let auth_authority = Arc::new(AuthAuthority::load_or_create(&*store).await.unwrap());
    let pki_authority = Arc::new(PkiAuthority::load_or_create(&*store).await.unwrap());
    let server_cert = pki_authority
        .issue_default_server_tls_cert(Some("127.0.0.1"), &[])
        .unwrap();
    let https_tls = pki_authority
        .build_server_tls_config(&server_cert, false)
        .unwrap();

    let temp_web_dir = std::env::temp_dir().join(format!(
        "rc-server-split-web-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&temp_web_dir).unwrap();
    let marker_html = "<!doctype html><html><body>RC_SPLIT_ADMIN_SPA_OK</body></html>";
    std::fs::write(temp_web_dir.join("index.html"), marker_html).unwrap();

    let signal_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signal_addr = signal_listener.local_addr().unwrap();
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    let client_https_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_https_addr = client_https_listener.local_addr().unwrap();
    let web_http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let web_http_addr = web_http_listener.local_addr().unwrap();

    let settings_cache = Arc::new(SettingsCache::new(store.clone(), ephemeral.clone()));
    let hub = Arc::new(SignalHub::with_auth(
        store.clone(),
        ephemeral.clone(),
        auth_authority.clone(),
        SignalConfig {
            public_udp_probe_addr: signal_addr.to_string(),
            public_relay_addr: relay_addr.to_string(),
            require_auth: true,
            ..SignalConfig::default()
        },
    ));
    let relay = Arc::new(RelayServer::new(
        store.clone(),
        ephemeral.clone(),
        RelayConfig::default(),
    ));

    let app_state = AppState {
        device_store: store.clone(),
        auth_store: store.clone(),
        ephemeral: ephemeral.clone(),
        auth_authority: auth_authority.clone(),
        pki_authority: pki_authority.clone(),
        settings_cache,
        signal_hub: hub.clone(),
        relay_server: relay.clone(),
        endpoints: AdvertisedEndpoints {
            signal_tcp_addr: signal_addr.to_string(),
            udp_probe_addr: signal_addr.to_string(),
            udp_probe_alt_addr: None,
            tcp_relay_addr: relay_addr.to_string(),
        },
        started_at: Instant::now(),
        admin_token: None,
        cors_origins: Vec::new(),
        tls_enabled: true,
        web_dir: Some(temp_web_dir.clone()),
        auth_rate_limiter: Arc::new(AuthRateLimiter::default()),
        allow_unauthenticated_legacy_admin: false,
    };

    let client_app = api::router_with_mode(app_state.clone(), api::RouterMode::ClientApiOnly);
    let web_app = api::router_with_mode(app_state, api::RouterMode::WebAdminOnly);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let https_task = tokio::spawn({
        let rx = shutdown_rx.clone();
        async move {
            let _ = api::serve_https(client_https_listener, https_tls, client_app, rx).await;
        }
    });
    let web_task = tokio::spawn({
        let mut rx = shutdown_rx.clone();
        async move {
            let _ = axum::serve(
                web_http_listener,
                web_app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                while !*rx.borrow_and_update() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await;
        }
    });

    let roots = pki_authority.root_cert_store().unwrap();
    let client_tls = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    // Bootstrap initial admin and login on WebAdminOnly plain HTTP port.
    let creds = ensure_initial_admin(&*store, Some("admin@split.test"))
        .await
        .unwrap()
        .unwrap();
    let (status, body) = http_plain(
        web_http_addr,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&serde_json::json!({ "email": creds.email, "password": creds.password })),
    )
    .await;
    assert_eq!(status, 200, "admin login on web port: {body}");
    let init_login: AuthTokenResponse = serde_json::from_str(&body).unwrap();

    let (status, body) = http_plain(
        web_http_addr,
        "POST",
        "/api/v1/auth/change-password",
        Some(&init_login.access_token),
        Some(&serde_json::json!({
            "current_password": creds.password,
            "new_password": "AdminSplitPassword!123",
        })),
    )
    .await;
    assert_eq!(status, 200, "admin change-password on web port: {body}");
    let admin: RefreshTokenResponse = serde_json::from_str(&body).unwrap();

    // 1. WebAdminOnly port assertions: SPA static & admin APIs work; client-only APIs return 404.
    let (status, body) = http_plain(web_http_addr, "GET", "/", None, None).await;
    assert_eq!(status, 200);
    assert!(body.contains("RC_SPLIT_ADMIN_SPA_OK"), "{body}");

    let (status, body) = http_plain(web_http_addr, "GET", "/settings", None, None).await;
    assert_eq!(status, 200);
    assert!(body.contains("RC_SPLIT_ADMIN_SPA_OK"), "{body}");

    let (status, body) = http_plain(web_http_addr, "GET", "/api/v1/health", None, None).await;
    assert_eq!(status, 200);
    let health: HealthResponse = serde_json::from_str(&body).unwrap();
    assert!(health.tls_enabled);

    let (status, _) = http_plain(web_http_addr, "GET", "/api/v1/pki/ca", None, None).await;
    assert_eq!(status, 200);

    let (status, _) = http_plain(
        web_http_addr,
        "GET",
        "/api/v1/me",
        Some(&admin.access_token),
        None,
    )
    .await;
    assert_eq!(status, 200);

    let (status, body) = http_plain(
        web_http_addr,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(&serde_json::json!({ "refresh_token": admin.refresh_token })),
    )
    .await;
    assert_eq!(status, 200, "refresh on web port: {body}");
    let admin_refreshed: RefreshTokenResponse = serde_json::from_str(&body).unwrap();

    for admin_path in [
        "/api/v1/admin/settings",
        "/api/v1/admin/users",
        "/api/v1/stats",
        "/api/v1/devices",
        "/api/v1/sessions",
    ] {
        let (status, resp) = http_plain(
            web_http_addr,
            "GET",
            admin_path,
            Some(&admin_refreshed.access_token),
            None,
        )
        .await;
        assert_eq!(
            status, 200,
            "expected 200 for {admin_path} on web port: {resp}"
        );
    }

    let (status, _) = http_plain(
        web_http_addr,
        "PATCH",
        "/api/v1/admin/settings",
        Some(&admin_refreshed.access_token),
        Some(&serde_json::json!({ "allow_registration": true })),
    )
    .await;
    assert_eq!(status, 200);

    for (method, client_only_path) in [
        ("GET", "/api/v1/auth/config"),
        ("POST", "/api/v1/auth/register"),
        ("POST", "/api/v1/devices/register"),
        ("GET", "/api/v1/me/devices"),
        ("POST", "/api/v1/certs/issue"),
    ] {
        let (status, resp) = http_plain(
            web_http_addr,
            method,
            client_only_path,
            Some(&admin_refreshed.access_token),
            None,
        )
        .await;
        assert_eq!(
            status, 404,
            "expected 404 for {method} {client_only_path} on web port: {resp}"
        );
        let err: ErrorBody = serde_json::from_str(&resp).unwrap();
        assert_eq!(err.error, "not_found");
    }

    // 2. ClientApiOnly HTTPS port assertions: client APIs work; static UI & admin APIs return 404.
    let (status, body) = https_json(
        client_https_addr,
        &client_tls,
        "GET",
        "/api/v1/health",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let health: HealthResponse = serde_json::from_str(&body).unwrap();
    assert!(health.tls_enabled);

    let (status, _) = https_json(
        client_https_addr,
        &client_tls,
        "GET",
        "/api/v1/pki/ca",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);

    let (status, body) = https_json(
        client_https_addr,
        &client_tls,
        "GET",
        "/api/v1/auth/config",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let auth_cfg: AuthConfigResponse = serde_json::from_str(&body).unwrap();
    assert!(auth_cfg.allow_registration);

    let (status, body) = https_json(
        client_https_addr,
        &client_tls,
        "POST",
        "/api/v1/auth/register",
        None,
        Some(&serde_json::json!({
            "email": "client@split.test",
            "password": "ClientPassword!123",
            "display_name": "Split Client",
        })),
    )
    .await;
    assert_eq!(status, 200, "client register on client port: {body}");
    let client_user: AuthTokenResponse = serde_json::from_str(&body).unwrap();

    let (status, _) = https_json(
        client_https_addr,
        &client_tls,
        "GET",
        "/api/v1/me",
        Some(&client_user.access_token),
        None,
    )
    .await;
    assert_eq!(status, 200);

    let (status, _) = https_json(
        client_https_addr,
        &client_tls,
        "GET",
        "/api/v1/me/devices",
        Some(&client_user.access_token),
        None,
    )
    .await;
    assert_eq!(status, 200);

    // Static SPA is NOT served on ClientApiOnly port.
    let (status, _) = https_json(client_https_addr, &client_tls, "GET", "/", None, None).await;
    assert_eq!(status, 404);

    // Admin routes are NOT mounted on ClientApiOnly port (even with valid admin token).
    for admin_path in [
        "/api/v1/admin/settings",
        "/api/v1/admin/users",
        "/api/v1/stats",
        "/api/v1/devices",
        "/api/v1/sessions",
    ] {
        let (status, resp) = https_json(
            client_https_addr,
            &client_tls,
            "GET",
            admin_path,
            Some(&admin_refreshed.access_token),
            None,
        )
        .await;
        assert_eq!(
            status, 404,
            "expected 404 for {admin_path} on client port: {resp}"
        );
        let err: ErrorBody = serde_json::from_str(&resp).unwrap();
        assert_eq!(err.error, "not_found");
    }

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), https_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), web_task).await;
    drop(signal_listener);
    drop(relay_listener);
    let _ = std::fs::remove_dir_all(&temp_web_dir);
}

#[tokio::test]
async fn two_layer_remote_control_policy_gates_android_self_control_assist_and_rest_patch() {
    let cluster = SecureTestCluster::start_fresh().await;

    // 1. Register User A (owns desktop controller + Android phone) and User B (stranger).
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/register",
        None,
        Some(&serde_json::json!({
            "email": "mobile-owner@example.com",
            "password": "OwnerPassword!2026",
            "display_name": "Mobile Owner",
        })),
    )
    .await;
    assert_eq!(status, 200, "register user A: {body}");
    let user_a: AuthTokenResponse = serde_json::from_str(&body).unwrap();

    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/register",
        None,
        Some(&serde_json::json!({
            "email": "mobile-stranger@example.com",
            "password": "StrangerPassword!2026",
            "display_name": "Stranger",
        })),
    )
    .await;
    assert_eq!(status, 200, "register user B: {body}");
    let user_b: AuthTokenResponse = serde_json::from_str(&body).unwrap();

    // Also bootstrap an active admin to verify GET /api/v1/devices exposes allow_remote_control.
    let creds = ensure_initial_admin(&*cluster.store, Some("rc-policy-admin@rc.local"))
        .await
        .unwrap()
        .unwrap();
    let (_, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&serde_json::json!({
            "email": "rc-policy-admin@rc.local",
            "password": creds.password,
        })),
    )
    .await;
    let init_admin: AuthTokenResponse = serde_json::from_str(&body).unwrap();
    let (_, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/change-password",
        Some(&init_admin.access_token),
        Some(&serde_json::json!({
            "current_password": creds.password,
            "new_password": "AdminStrongPassword!2026",
        })),
    )
    .await;
    let admin: RefreshTokenResponse = serde_json::from_str(&body).unwrap();

    // 2. Register desktop controller (macOS) via legacy raw JSON without `allow_remote_control`
    // -> defaults to allow_remote_control = true.
    let controller_pk_hex = "11".repeat(32);
    let mut desktop_sig =
        connect_tls_signal(cluster.signal_addr, &cluster.client_tls_no_cert).await;
    let legacy_desktop_payload = serde_json::json!({
        "type": "register",
        "device_key": "dk-desktop-mac-rc",
        "hostname": "MacBook-Controller",
        "os": "macos",
        "access_token": user_a.access_token,
        "device_pubkey": controller_pk_hex,
        "allow_remote_assist": false
    })
    .to_string()
    .into_bytes();
    desktop_sig
        .write_all(&(legacy_desktop_payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    desktop_sig
        .write_all(&legacy_desktop_payload)
        .await
        .unwrap();
    desktop_sig.flush().await.unwrap();
    let desktop_id = match read_signal_frame(&mut desktop_sig).await.unwrap().unwrap() {
        SignalMsg::Registered { device_id, .. } => device_id,
        other => panic!("expected Registered for desktop, got {other:?}"),
    };
    let desktop_rec = cluster.store.get_by_id(&desktop_id).await.unwrap().unwrap();
    assert!(
        desktop_rec.allow_remote_control,
        "desktop device must default allow_remote_control = true"
    );
    assert!(!desktop_rec.allow_remote_assist);

    // 3. Register Android host WITHOUT explicit `allow_remote_control` (simulating legacy/default client)
    // -> defaults to allow_remote_control = false!
    let mut android_sig =
        connect_tls_signal(cluster.signal_addr, &cluster.client_tls_no_cert).await;
    write_signal_frame(
        &mut android_sig,
        &SignalMsg::Register {
            device_id: None,
            device_key: "dk-android-phone-rc".into(),
            hostname: "Pixel-9-Pro".into(),
            os: "Android 15".into(),
            app_version: "0.1.12".into(),
            arch: "arm64".into(),
            device_group: "mobile".into(),
            lan_addrs: vec!["192.168.1.55:50000".into()],
            access_token: Some(user_a.access_token.clone()),
            device_pubkey: Some("22".repeat(32)),
            allow_remote_assist: Some(false),
            allow_remote_control: None,
            mac_addr: None,
            wol_enabled: None,
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    let android_id = match read_signal_frame(&mut android_sig).await.unwrap().unwrap() {
        SignalMsg::Registered { device_id, .. } => device_id,
        other => panic!("expected Registered for android, got {other:?}"),
    };
    let android_rec = cluster.store.get_by_id(&android_id).await.unwrap().unwrap();
    assert!(
        !android_rec.allow_remote_control,
        "Android device must default allow_remote_control = false"
    );

    // Same-account desktop must receive DeviceStatusChanged with allow_remote_control = false.
    let online_evt = read_signal_frame(&mut desktop_sig).await.unwrap().unwrap();
    assert!(matches!(
        online_evt,
        SignalMsg::DeviceStatusChanged {
            ref device_id,
            online: true,
            allow_remote_assist: false,
            allow_remote_control: false,
            ..
        } if device_id == &android_id
    ));

    // Register User B's stranger device.
    let mut stranger_sig =
        connect_tls_signal(cluster.signal_addr, &cluster.client_tls_no_cert).await;
    write_signal_frame(
        &mut stranger_sig,
        &SignalMsg::Register {
            device_id: None,
            device_key: "dk-stranger-rc".into(),
            hostname: "Stranger-PC".into(),
            os: "windows".into(),
            app_version: String::new(),
            arch: String::new(),
            device_group: String::new(),
            lan_addrs: vec![],
            access_token: Some(user_b.access_token.clone()),
            device_pubkey: Some("33".repeat(32)),
            allow_remote_assist: Some(false),
            allow_remote_control: None,
            mac_addr: None,
            wol_enabled: None,
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_signal_frame(&mut stranger_sig).await.unwrap().unwrap(),
        SignalMsg::Registered { .. }
    ));

    // 4. While Android has allow_remote_control == false:
    //    4a. Same-account ConnectRequest MUST be rejected with remote_control_disabled
    //        and MUST NOT push punch_coord to Android or allocate any relay token!
    write_signal_frame(
        &mut desktop_sig,
        &SignalMsg::ConnectRequest {
            target_id: android_id.clone(),
            session_id: Some("sess-android-blocked-punch".into()),
            lan_addrs: vec![],
            nonce: Some("n1".into()),
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_signal_frame(&mut desktop_sig).await.unwrap().unwrap(),
        SignalMsg::Error { ref code, .. } if code == "remote_control_disabled"
    ));
    assert_eq!(
        cluster.ephemeral.active_token_count(),
        0,
        "rejected ConnectRequest must not allocate any relay token"
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(80),
            read_signal_frame(&mut android_sig)
        )
        .await
        .is_err(),
        "Android host must not receive punch_coord when allow_remote_control == false"
    );

    //    4b. Same-account RelayAlloc MUST ALSO be rejected with remote_control_disabled
    //        and MUST NOT push relay_ready or allocate any relay token!
    write_signal_frame(
        &mut desktop_sig,
        &SignalMsg::RelayAlloc {
            target_id: android_id.clone(),
            session_id: Some("sess-android-blocked-relay".into()),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_signal_frame(&mut desktop_sig).await.unwrap().unwrap(),
        SignalMsg::Error { ref code, .. } if code == "remote_control_disabled"
    ));
    assert_eq!(
        cluster.ephemeral.active_token_count(),
        0,
        "rejected RelayAlloc must not allocate any relay token"
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(80),
            read_signal_frame(&mut android_sig)
        )
        .await
        .is_err(),
        "Android host must not receive relay_ready when allow_remote_control == false"
    );

    //    4c. Legacy UpdateAssistState without allow_remote_control field keeps allow_remote_control == false!
    let legacy_upd_payload = br#"{"type":"update_assist_state","allow_remote_assist":true}"#;
    android_sig
        .write_all(&(legacy_upd_payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    android_sig.write_all(legacy_upd_payload).await.unwrap();
    android_sig.flush().await.unwrap();
    assert!(matches!(
        read_signal_frame(&mut desktop_sig).await.unwrap().unwrap(),
        SignalMsg::DeviceStatusChanged {
            ref device_id,
            online: true,
            allow_remote_assist: true,
            allow_remote_control: false,
            ..
        } if device_id == &android_id
    ));
    // Even with allow_remote_assist=true, allow_remote_control=false still blocks stranger & owner!
    write_signal_frame(
        &mut stranger_sig,
        &SignalMsg::ConnectRequest {
            target_id: android_id.clone(),
            session_id: Some("sess-stranger-blocked-layer1".into()),
            lan_addrs: vec![],
            nonce: None,
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_signal_frame(&mut stranger_sig).await.unwrap().unwrap(),
        SignalMsg::Error { ref code, .. } if code == "remote_control_disabled"
    ));

    // 5. Android explicitly enables allow_remote_control=Some(true) with allow_remote_assist=Some(false).
    write_signal_frame(
        &mut android_sig,
        &SignalMsg::UpdateAssistState {
            allow_remote_assist: Some(false),
            allow_remote_control: Some(true),
            mac_addr: None,
            wol_enabled: None,
        },
    )
    .await
    .unwrap();
    // Same-account desktop receives real-time DeviceStatusChanged { allow_remote_control: true, allow_remote_assist: false }.
    assert!(matches!(
        read_signal_frame(&mut desktop_sig).await.unwrap().unwrap(),
        SignalMsg::DeviceStatusChanged {
            ref device_id,
            online: true,
            allow_remote_assist: false,
            allow_remote_control: true,
            ..
        } if device_id == &android_id
    ));

    //    5a. Same-account ConnectRequest now succeeds and issues valid OwnerGrantTicket!
    write_signal_frame(
        &mut desktop_sig,
        &SignalMsg::ConnectRequest {
            target_id: android_id.clone(),
            session_id: Some("sess-android-owner-ok".into()),
            lan_addrs: vec![],
            nonce: Some("n2".into()),
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    match read_signal_frame(&mut desktop_sig).await.unwrap().unwrap() {
        SignalMsg::PunchCoord {
            is_owner_connection,
            owner_grant,
            session_id,
            ..
        } => {
            assert!(is_owner_connection);
            let grant = owner_grant.expect("same-account connection must receive OwnerGrantTicket");
            assert_eq!(grant.user_id, user_a.user.id);
            assert_eq!(grant.caller_device_id, desktop_id);
            assert_eq!(grant.caller_pubkey_hex, controller_pk_hex);
            assert_eq!(grant.target_device_id, android_id);
            assert_eq!(grant.session_id, session_id);
            verify_owner_grant_with_pubkey(
                &grant,
                cluster.auth_authority.public_key_bytes(),
                Utc::now().timestamp(),
            )
            .expect("OwnerGrantTicket signature and bindings must verify");
        }
        other => panic!("expected PunchCoord for same-account desktop, got {other:?}"),
    }
    assert!(matches!(
        read_signal_frame(&mut android_sig).await.unwrap().unwrap(),
        SignalMsg::PunchCoord {
            is_owner_connection: true,
            owner_grant: None,
            ..
        }
    ));

    //    5b. Non-owner (stranger) ConnectRequest is STILL rejected with assist_disabled!
    write_signal_frame(
        &mut stranger_sig,
        &SignalMsg::ConnectRequest {
            target_id: android_id.clone(),
            session_id: Some("sess-stranger-assist-disabled".into()),
            lan_addrs: vec![],
            nonce: None,
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_signal_frame(&mut stranger_sig).await.unwrap().unwrap(),
        SignalMsg::Error { ref code, .. } if code == "assist_disabled"
    ));

    // 6. REST PATCH /api/v1/me/devices/{id} toggles allow_remote_control = false ->
    //    persisted in GET /api/v1/me/devices & Admin GET /api/v1/devices, broadcasts DeviceStatusChanged,
    //    and immediately blocks subsequent same-account ConnectRequest!
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "PATCH",
        &format!("/api/v1/me/devices/{android_id}"),
        Some(&user_a.access_token),
        Some(&serde_json::json!({ "allow_remote_control": false })),
    )
    .await;
    assert_eq!(status, 200, "PATCH allow_remote_control=false: {body}");
    let patched: DeviceBindingResponse = serde_json::from_str(&body).unwrap();
    assert!(!patched.device.allow_remote_control);

    // Real-time DeviceStatusChanged broadcast triggered by REST PATCH reaches BOTH
    // same-account other peers (desktop_sig) AND the target online device itself (android_sig)!
    assert!(matches!(
        read_signal_frame(&mut desktop_sig).await.unwrap().unwrap(),
        SignalMsg::DeviceStatusChanged {
            ref device_id,
            online: true,
            allow_remote_assist: false,
            allow_remote_control: false,
            ..
        } if device_id == &android_id
    ));
    assert!(matches!(
        read_signal_frame(&mut android_sig).await.unwrap().unwrap(),
        SignalMsg::DeviceStatusChanged {
            ref device_id,
            online: true,
            allow_remote_assist: false,
            allow_remote_control: false,
            ..
        } if device_id == &android_id
    ));

    // GET /api/v1/me/devices reflects desktop=true, android=false.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "GET",
        "/api/v1/me/devices",
        Some(&user_a.access_token),
        None,
    )
    .await;
    assert_eq!(status, 200, "GET /api/v1/me/devices: {body}");
    let my_devs: MyDevicesResponse = serde_json::from_str(&body).unwrap();
    let my_android = my_devs
        .devices
        .iter()
        .find(|d| d.device_id == android_id)
        .unwrap();
    let my_desktop = my_devs
        .devices
        .iter()
        .find(|d| d.device_id == desktop_id)
        .unwrap();
    assert!(!my_android.allow_remote_control);
    assert!(my_desktop.allow_remote_control);

    // Admin GET /api/v1/devices also exposes allow_remote_control.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "GET",
        "/api/v1/devices",
        Some(&admin.access_token),
        None,
    )
    .await;
    assert_eq!(status, 200, "GET /api/v1/devices: {body}");
    let admin_devs: DevicesResponse = serde_json::from_str(&body).unwrap();
    let admin_android = admin_devs
        .devices
        .iter()
        .find(|d| d.device_id == android_id)
        .unwrap();
    assert!(!admin_android.allow_remote_control);

    // Same-account ConnectRequest is blocked again immediately after PATCH false.
    write_signal_frame(
        &mut desktop_sig,
        &SignalMsg::ConnectRequest {
            target_id: android_id.clone(),
            session_id: Some("sess-after-patch-false".into()),
            lan_addrs: vec![],
            nonce: None,
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_signal_frame(&mut desktop_sig).await.unwrap().unwrap(),
        SignalMsg::Error { ref code, .. } if code == "remote_control_disabled"
    ));

    // PATCH back to true -> GET /api/v1/me/devices returns true + broadcasts DeviceStatusChanged.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "PATCH",
        &format!("/api/v1/me/devices/{android_id}"),
        Some(&user_a.access_token),
        Some(&serde_json::json!({ "allow_remote_control": true })),
    )
    .await;
    assert_eq!(status, 200, "PATCH allow_remote_control=true: {body}");
    assert!(matches!(
        read_signal_frame(&mut desktop_sig).await.unwrap().unwrap(),
        SignalMsg::DeviceStatusChanged {
            ref device_id,
            online: true,
            allow_remote_control: true,
            ..
        } if device_id == &android_id
    ));
    assert!(matches!(
        read_signal_frame(&mut android_sig).await.unwrap().unwrap(),
        SignalMsg::DeviceStatusChanged {
            ref device_id,
            online: true,
            allow_remote_control: true,
            ..
        } if device_id == &android_id
    ));
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "GET",
        "/api/v1/me/devices",
        Some(&user_a.access_token),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let my_devs_after: MyDevicesResponse = serde_json::from_str(&body).unwrap();
    assert!(
        my_devs_after
            .devices
            .iter()
            .find(|d| d.device_id == android_id)
            .unwrap()
            .allow_remote_control
    );

    cluster.shutdown().await;
}

#[tokio::test]
async fn my_devices_orders_online_before_offline_even_when_offline_seen_later() {
    let cluster = SecureTestCluster::start_fresh().await;

    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "POST",
        "/api/v1/auth/register",
        None,
        Some(&serde_json::json!({
            "email": "sort-owner@example.com",
            "password": "SortPassword!2026",
            "display_name": "Sort Owner",
        })),
    )
    .await;
    assert_eq!(status, 200, "register user: {body}");
    let user: AuthTokenResponse = serde_json::from_str(&body).unwrap();

    // 1. Register online device FIRST (older last_seen_at) and keep it connected.
    let mut online_sig = connect_tls_signal(cluster.signal_addr, &cluster.client_tls_no_cert).await;
    write_signal_frame(
        &mut online_sig,
        &SignalMsg::Register {
            device_id: None,
            device_key: "dk-sort-online-older".into(),
            hostname: "Online-Mac".into(),
            os: "macos".into(),
            app_version: "0.1.12".into(),
            arch: "arm64".into(),
            device_group: "default".into(),
            lan_addrs: vec![],
            access_token: Some(user.access_token.clone()),
            device_pubkey: None,
            allow_remote_assist: Some(false),
            allow_remote_control: Some(true),
            mac_addr: None,
            wol_enabled: None,
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    let online_id = match read_signal_frame(&mut online_sig).await.unwrap().unwrap() {
        SignalMsg::Registered { device_id, .. } => device_id,
        other => panic!("expected Registered for online device, got {other:?}"),
    };

    // Wait briefly so the second device gets a strictly newer `last_seen_at`.
    tokio::time::sleep(Duration::from_millis(15)).await;

    // 2. Register second device LATER (newer last_seen_at), then disconnect it so it becomes offline.
    let mut offline_sig =
        connect_tls_signal(cluster.signal_addr, &cluster.client_tls_no_cert).await;
    write_signal_frame(
        &mut offline_sig,
        &SignalMsg::Register {
            device_id: None,
            device_key: "dk-sort-offline-newer".into(),
            hostname: "Offline-Mac".into(),
            os: "macos".into(),
            app_version: "0.1.12".into(),
            arch: "arm64".into(),
            device_group: "default".into(),
            lan_addrs: vec![],
            access_token: Some(user.access_token.clone()),
            device_pubkey: None,
            allow_remote_assist: Some(false),
            allow_remote_control: Some(true),
            mac_addr: None,
            wol_enabled: None,
            nat_type: None,
            nat_port_delta: None,
        },
    )
    .await
    .unwrap();
    let offline_id = match read_signal_frame(&mut offline_sig).await.unwrap().unwrap() {
        SignalMsg::Registered { device_id, .. } => device_id,
        other => panic!("expected Registered for offline device, got {other:?}"),
    };
    // Drain the online broadcast on `online_sig`.
    let _ = read_signal_frame(&mut online_sig).await.unwrap().unwrap();

    // Disconnect the newer device and wait for its offline broadcast on `online_sig`.
    drop(offline_sig);
    assert!(matches!(
        read_signal_frame(&mut online_sig).await.unwrap().unwrap(),
        SignalMsg::DeviceStatusChanged {
            ref device_id,
            online: false,
            ..
        } if device_id == &offline_id
    ));

    // 3. GET /api/v1/me/devices MUST return the online device first and the offline device last,
    //    even though the offline device has a newer `last_seen_at`.
    let (status, body) = https_json(
        cluster.http_addr,
        &cluster.client_tls_no_cert,
        "GET",
        "/api/v1/me/devices",
        Some(&user.access_token),
        None,
    )
    .await;
    assert_eq!(status, 200, "GET /api/v1/me/devices: {body}");
    let my_devs: MyDevicesResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(my_devs.devices.len(), 2);
    assert_eq!(my_devs.devices[0].device_id, online_id);
    assert!(my_devs.devices[0].online);
    assert_eq!(my_devs.devices[1].device_id, offline_id);
    assert!(!my_devs.devices[1].online);
    assert!(
        my_devs.devices[1].last_seen_at >= my_devs.devices[0].last_seen_at,
        "sanity check: offline device had newer last_seen_at yet must still sort after online"
    );

    drop(online_sig);
    cluster.shutdown().await;
}
