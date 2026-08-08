//! mqvpn-rs step 0b — seamless failover via TWO endpoints (active-active).
//!
//! noq can't pin one Endpoint to two interfaces (single UDP socket, IP_PKTINFO
//! is only a hint). So we run TWO independent QUIC connections, each on an
//! Endpoint bound to one interface's source IP:
//!     connA bound to en17 (wired), connB bound to en0 (wifi)
//! Client sends every ping on BOTH conns; server echoes each; client dedups by
//! seq. Pull the wired cable -> connA's packets blackhole, connB (wifi) keeps
//! delivering. The echo gap at the pull is the true failover cost.
//!
//!   mqvpn-rs server 0.0.0.0:9000
//!   mqvpn-rs client <server-ip>:9000 <wired-src-ip> <wifi-src-ip>

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use noq::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig};
use noq_proto::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio_stream::StreamExt;

const PING_INTERVAL: Duration = Duration::from_millis(50);
static START: LazyLock<Instant> = LazyLock::new(Instant::now);
fn now() -> String { format!("{:>8.3}s", START.elapsed().as_secs_f64()) }

/// datagram = [seq u64][send-stamp u64 micros]; echoed verbatim. Dedup by seq.
fn encode(seq: u64) -> bytes::Bytes {
    let stamp = START.elapsed().as_micros() as u64;
    let mut b = Vec::with_capacity(16);
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(&stamp.to_be_bytes());
    b.into()
}
fn decode(d: &[u8]) -> Option<(u64, Duration)> {
    if d.len() < 16 { return None; }
    let seq = u64::from_be_bytes(d[0..8].try_into().ok()?);
    let stamp = u64::from_be_bytes(d[8..16].try_into().ok()?);
    Some((seq, START.elapsed().saturating_sub(Duration::from_micros(stamp))))
}

fn transport() -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    tc.max_concurrent_multipath_paths(2);
    tc.keep_alive_interval(Some(Duration::from_millis(200)));
    Arc::new(tc)
}

fn server_config() -> ServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["mqvpn-rs".into()]).unwrap();
    let der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut cfg = ServerConfig::with_single_cert(vec![der], key.into()).unwrap();
    cfg.transport_config(transport());
    cfg
}

#[derive(Debug)]
struct SkipVerify(Arc<rustls::crypto::CryptoProvider>);
impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> { self.0.signature_verification_algorithms.supported_schemes() }
}
fn client_config() -> ClientConfig {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let tls = rustls::ClientConfig::builder_with_provider(provider.clone().into())
        .with_safe_default_protocol_versions().unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify(provider.into())))
        .with_no_client_auth();
    let mut cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
    cfg.transport_config(transport());
    cfg
}

async fn run_server(bind: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = Endpoint::server(server_config(), bind)?;
    println!("[{}] server on {} (echo, dual-conn)", now(), server.local_addr()?);
    while let Some(incoming) = server.accept().await {
        tokio::spawn(async move {
            let conn = match incoming.await { Ok(c) => c, Err(_) => return };
            let remote = conn.path(noq_proto::PathId::ZERO).and_then(|p| p.remote_address().ok());
            println!("[{}] [srv] conn from {:?}", now(), remote);
            loop {
                match conn.read_datagram().await {
                    Ok(d) => { if conn.send_datagram(d).is_err() { break; } }
                    Err(_) => break,
                }
            }
        });
    }
    Ok(())
}

/// Open one connection on an endpoint bound to `src_ip`, label it.
async fn dial(server: SocketAddr, src_ip: IpAddr, label: &str) -> Result<Connection, Box<dyn std::error::Error + Send + Sync>> {
    let ep = Endpoint::client(SocketAddr::new(src_ip, 0))?;
    ep.set_default_client_config(client_config());
    let conn = ep.connect(server, "mqvpn-rs")?.await?;
    let local = conn.path(noq_proto::PathId::ZERO).and_then(|p| p.network_path().ok());
    println!("[{}] conn{} up  src_ip={} 4-tuple={:?}", now(), label, src_ip, local);
    Ok(conn)
}

async fn run_client(server: SocketAddr, ip_a: IpAddr, ip_b: IpAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn_a = dial(server, ip_a, "A(wired)").await?;
    let conn_b = dial(server, ip_b, "B(wifi)").await?;

    // echo readers, tagged by conn, all feeding one channel
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(&'static str, u64, Duration)>(8192);
    for (conn, tag) in [(conn_a.clone(), "A"), (conn_b.clone(), "B")] {
        let tx = tx.clone();
        tokio::spawn(async move {
            loop {
                match conn.read_datagram().await {
                    Ok(d) => { if let Some((seq, rtt)) = decode(&d) { let _ = tx.try_send((tag, seq, rtt)); } }
                    Err(e) => { println!("[{}] conn{} read end: {}", now(), tag, e); break; }
                }
            }
        });
    }

    let run_for = Duration::from_secs(std::env::var("PING_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(90));
    println!("[{}] --- active-active ping start ({}ms, {}s). UNPLUG wired now ---", now(), PING_INTERVAL.as_millis(), run_for.as_secs());

    let mut ticker = tokio::time::interval(PING_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let deadline = Instant::now() + run_for;
    let mut sent = 0u64;
    let mut seen: HashSet<u64> = HashSet::new();
    let mut per_conn: std::collections::HashMap<&'static str, u64> = Default::default();
    let mut rtts = Vec::new();
    let mut max_gap = Duration::ZERO;
    let mut last_echo = Instant::now();
    let mut last_report = Instant::now();

    while Instant::now() < deadline {
        tokio::select! {
            _ = ticker.tick() => {
                sent += 1;
                let d = encode(sent);
                let _ = conn_a.send_datagram(d.clone());
                let _ = conn_b.send_datagram(d);
            }
            Some((tag, seq, rtt)) = rx.recv() => {
                *per_conn.entry(tag).or_insert(0) += 1;
                if seen.insert(seq) {
                    // first copy of this seq => the echo that "arrived"
                    rtts.push(rtt);
                    let gap = last_echo.elapsed();
                    if gap > max_gap { max_gap = gap; }
                    last_echo = Instant::now();
                }
                if last_report.elapsed() >= Duration::from_secs(1) {
                    last_report = Instant::now();
                    println!("[{}] echo seq={} via={} rtt={:.2}ms (delivered={}/{})", now(), seq, tag, rtt.as_secs_f64()*1e3, seen.len(), sent);
                }
            }
        }
    }

    let delivered = seen.len() as u64;
    let lost = sent.saturating_sub(delivered);
    let avg = if rtts.is_empty() { Duration::ZERO } else { rtts.iter().sum::<Duration>() / rtts.len() as u32 };
    println!("[{}] === RESULT ===", now());
    println!("  sent={} delivered(unique)={} lost={} ({:.1}%)", sent, delivered, lost, 100.0*lost as f64/sent.max(1) as f64);
    println!("  avg_rtt={:.2}ms  max_echo_gap={:.2}ms", avg.as_secs_f64()*1e3, max_gap.as_secs_f64()*1e3);
    for (k, v) in &per_conn { println!("  echoes via conn{}: {}", k, v); }
    println!("  VERDICT: max_echo_gap small through the unplug => seamless active-active");
    std::process::exit(0);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    LazyLock::force(&START);
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "mqvpn_rs=info,noq=warn".parse().unwrap()))
        .init();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("server") => run_server(args.get(2).expect("server <bind:port>").parse()?).await,
        Some("client") => {
            let server: SocketAddr = args.get(2).expect("client <server:port> <wired-ip> <wifi-ip>").parse()?;
            let ip_a: IpAddr = args.get(3).expect("wired ip").parse()?;
            let ip_b: IpAddr = args.get(4).expect("wifi ip").parse()?;
            run_client(server, ip_a, ip_b).await
        }
        _ => { eprintln!("usage:\n  mqvpn-rs server <bind:port>\n  mqvpn-rs client <server:port> <wired-src-ip> <wifi-src-ip>"); std::process::exit(2); }
    }
}
