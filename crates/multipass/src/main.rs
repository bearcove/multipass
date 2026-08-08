//! multipass step-0 failover test — a thin CLI wrapper over the transport lib.
//!
//! Proves the active-active dual-connection core: two QUIC connections, one
//! per interface, every ping sent on BOTH, receiver dedups by seq. Pulling one
//! interface blackholes one connection's packets while the other keeps
//! delivering; the echo gap at the pull is the true failover cost.
//!
//!   multipass server 0.0.0.0:9000
//!   multipass client <server-ip>:9000 <wired-src-ip> <wifi-src-ip>

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use bytes::Bytes;
use multipass::{dial, server_config};
use noq::Endpoint;

const PING_INTERVAL: Duration = Duration::from_millis(50);
static START: LazyLock<Instant> = LazyLock::new(Instant::now);
fn now() -> String {
    format!("{:>8.3}s", START.elapsed().as_secs_f64())
}

/// datagram = [seq u64][send-stamp u64 micros]; echoed verbatim. Dedup by seq.
fn encode(seq: u64) -> Bytes {
    let stamp = START.elapsed().as_micros() as u64;
    let mut b = Vec::with_capacity(16);
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(&stamp.to_be_bytes());
    b.into()
}
fn decode(d: &[u8]) -> Option<(u64, Duration)> {
    if d.len() < 16 {
        return None;
    }
    let seq = u64::from_be_bytes(d[0..8].try_into().ok()?);
    let stamp = u64::from_be_bytes(d[8..16].try_into().ok()?);
    Some((
        seq,
        START.elapsed().saturating_sub(Duration::from_micros(stamp)),
    ))
}

async fn run_server(bind: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = Endpoint::server(server_config(), bind)?;
    println!(
        "[{}] server on {} (echo, dual-conn)",
        now(),
        server.local_addr()?
    );
    while let Some(incoming) = server.accept().await {
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(_) => return,
            };
            let remote = conn
                .path(noq_proto::PathId::ZERO)
                .and_then(|p| p.remote_address().ok());
            println!("[{}] [srv] conn from {:?}", now(), remote);
            while let Ok(d) = conn.read_datagram().await {
                if conn.send_datagram(d).is_err() {
                    break;
                }
            }
        });
    }
    Ok(())
}

async fn run_client(
    server: SocketAddr,
    ip_a: IpAddr,
    ip_b: IpAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn_a = dial(server, ip_a, "A(wired)").await?;
    let conn_b = dial(server, ip_b, "B(wifi)").await?;

    // echo readers, tagged by conn, all feeding one channel
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(&'static str, u64, Duration)>(8192);
    for (conn, tag) in [(conn_a.clone(), "A"), (conn_b.clone(), "B")] {
        let tx = tx.clone();
        tokio::spawn(async move {
            loop {
                match conn.read_datagram().await {
                    Ok(d) => {
                        if let Some((seq, rtt)) = decode(&d) {
                            let _ = tx.try_send((tag, seq, rtt));
                        }
                    }
                    Err(e) => {
                        println!("[{}] conn{} read end: {}", now(), tag, e);
                        break;
                    }
                }
            }
        });
    }

    let run_for = Duration::from_secs(
        std::env::var("PING_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(90),
    );
    println!(
        "[{}] --- active-active ping start ({}ms, {}s). UNPLUG wired now ---",
        now(),
        PING_INTERVAL.as_millis(),
        run_for.as_secs()
    );

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
    let avg = if rtts.is_empty() {
        Duration::ZERO
    } else {
        rtts.iter().sum::<Duration>() / rtts.len() as u32
    };
    println!("[{}] === RESULT ===", now());
    println!(
        "  sent={} delivered(unique)={} lost={} ({:.1}%)",
        sent,
        delivered,
        lost,
        100.0 * lost as f64 / sent.max(1) as f64
    );
    println!(
        "  avg_rtt={:.2}ms  max_echo_gap={:.2}ms",
        avg.as_secs_f64() * 1e3,
        max_gap.as_secs_f64() * 1e3
    );
    for (k, v) in &per_conn {
        println!("  echoes via conn{}: {}", k, v);
    }
    println!("  VERDICT: max_echo_gap small through the unplug => seamless active-active");
    std::process::exit(0);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    LazyLock::force(&START);
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "multipass=info,noq=warn".parse().unwrap()),
        )
        .init();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("server") => run_server(args.get(2).expect("server <bind:port>").parse()?).await,
        Some("client") => {
            let server: SocketAddr = args
                .get(2)
                .expect("client <server:port> <wired-ip> <wifi-ip>")
                .parse()?;
            let ip_a: IpAddr = args.get(3).expect("wired ip").parse()?;
            let ip_b: IpAddr = args.get(4).expect("wifi ip").parse()?;
            run_client(server, ip_a, ip_b).await
        }
        _ => {
            eprintln!(
                "usage:\n  multipass server <bind:port>\n  multipass client <server:port> <wired-src-ip> <wifi-src-ip>"
            );
            std::process::exit(2);
        }
    }
}
