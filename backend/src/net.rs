use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpSocket};

/// Default TCP listen backlog (breaks std/mio's hardcoded 128 cap so burst
/// connection spikes are absorbed cleanly without SYN retransmission stalls;
/// clamped by kernel `somaxconn`).
pub const DEFAULT_TCP_LISTEN_BACKLOG: u32 = 4096;

/// Bind a TCP listener on `addr` with an explicit kernel listen `backlog`.
pub fn bind_tcp_listener(addr: SocketAddr, backlog: u32) -> io::Result<TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    #[cfg(not(windows))]
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(backlog)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn bind_tcp_listener_accepts_ipv4_connection() {
        let listener =
            bind_tcp_listener("127.0.0.1:0".parse().unwrap(), DEFAULT_TCP_LISTEN_BACKLOG).unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await });
        let _client = TcpStream::connect(addr).await.unwrap();
        assert!(accept.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn bind_tcp_listener_accepts_ipv6_loopback_if_available() {
        let Ok(listener) =
            bind_tcp_listener("[::1]:0".parse().unwrap(), DEFAULT_TCP_LISTEN_BACKLOG)
        else {
            return;
        };
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await });
        let Ok(_client) = TcpStream::connect(addr).await else {
            return;
        };
        assert!(accept.await.unwrap().is_ok());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bind_tcp_listener_applies_high_backlog_capped_by_somaxconn() {
        let Ok(raw) = std::fs::read_to_string("/proc/sys/net/core/somaxconn") else {
            eprintln!("cannot read /proc/sys/net/core/somaxconn, skipping test");
            return;
        };
        let Ok(somaxconn) = raw.trim().parse::<u32>() else {
            eprintln!("non-numeric somaxconn: {raw:?}, skipping test");
            return;
        };
        let listener =
            bind_tcp_listener("127.0.0.1:0".parse().unwrap(), DEFAULT_TCP_LISTEN_BACKLOG).unwrap();
        let port = listener.local_addr().unwrap().port();
        let Ok(out) = std::process::Command::new("ss")
            .args(["-ltnH", &format!("sport = :{port}")])
            .output()
        else {
            eprintln!("ss command unavailable, skipping test");
            return;
        };
        if !out.status.success() {
            eprintln!("ss exited with {}, skipping test", out.status);
            return;
        }
        let line = String::from_utf8_lossy(&out.stdout);
        let Some(send_q) = line
            .lines()
            .next()
            .and_then(|row| row.split_whitespace().nth(2))
            .and_then(|q| q.parse::<u32>().ok())
        else {
            eprintln!("could not parse Send-Q from ss output: {line:?}, skipping test");
            return;
        };
        let expected_min = DEFAULT_TCP_LISTEN_BACKLOG.min(somaxconn);
        assert!(
            send_q >= expected_min,
            "expected Send-Q >= min({DEFAULT_TCP_LISTEN_BACKLOG}, somaxconn={somaxconn})={expected_min}, got {send_q}"
        );
        drop(listener);
    }
}
