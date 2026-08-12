//! End-to-end aggregation test: real client `Transport` against an in-process
//! SACK-capable server over loopback. Verifies that striping + SACK retire the
//! client's send window (no unbounded growth) and that every packet is
//! delivered exactly once.

use bytes::Bytes;
use multipass::{PathId, Transport, UplinkDial, UplinkId};
use multipass_proto::{Dedup, Frame, SackScoreboard};
use noq::Endpoint;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc;

fn test_dials(count: u16) -> Vec<UplinkDial> {
    (1..=count)
        .map(|id| UplinkDial {
            path_id: PathId::new(id),
            uplink_id: UplinkId::new(format!("path-{id}")).unwrap(),
            source: "127.0.0.1".parse().unwrap(),
        })
        .collect()
}

/// Spawn a server that dedups inbound Data and periodically SACKs back its
/// receive state. Returns the server address and a count of unique packets
/// the server accepted.
async fn spawn_sack_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let server =
        Endpoint::server(multipass::server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_task = accepted.clone();

    tokio::spawn(async move {
        // Single logical session across both client connections.
        let dedup = Arc::new(std::sync::Mutex::new(Dedup::new()));
        let scoreboard = Arc::new(std::sync::Mutex::new(SackScoreboard::new()));
        let (conn_tx, mut conn_rx) = mpsc::channel::<noq::Connection>(8);

        // Accept loop: each new connection spawns a reader sharing the session.
        let accept = {
            let conn_tx = conn_tx.clone();
            async move {
                while let Some(incoming) = server.accept().await {
                    if let Ok(conn) = incoming.await {
                        let _ = conn_tx.send(conn).await;
                    }
                }
            }
        };
        tokio::spawn(accept);
        drop(conn_tx);

        // SACK broadcast task.
        let mut sack_conns: Vec<noq::Connection> = Vec::new();
        let (sack_tx, mut sack_rx) = mpsc::channel::<noq::Connection>(8);
        let sack_scoreboard = scoreboard.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(10));
            loop {
                ticker.tick().await;
                while let Ok(c) = sack_rx.try_recv() {
                    sack_conns.push(c);
                }
                let sack = sack_scoreboard.lock().unwrap().generate_sack();
                let enc = multipass_proto::encode(&sack);
                for c in &sack_conns {
                    let _ = c.send_datagram(enc.clone());
                }
            }
        });

        // Reader per connection.
        while let Some(conn) = conn_rx.recv().await {
            let _ = sack_tx.send(conn.clone()).await;
            let dedup = dedup.clone();
            let scoreboard = scoreboard.clone();
            let accepted = accepted_task.clone();
            tokio::spawn(async move {
                while let Ok(d) = conn.read_datagram().await {
                    if let Some(Frame::Data { seq, .. }) = multipass_proto::decode(&d) {
                        scoreboard.lock().unwrap().insert(seq);
                        if dedup.lock().unwrap().insert(seq) {
                            accepted.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
    });

    (addr, accepted)
}

#[tokio::test]
async fn aggregation_delivers_all_and_retires_window() {
    let (addr, accepted) = spawn_sack_server().await;
    let t = Transport::connect(addr, test_dials(2))
    .await
    .unwrap();
    for path_id in t.path_ids() {
        assert!(t.mark_ready(path_id));
    }

    const N: u64 = 200;
    for seq in 1..=N {
        assert!(t.send_data(seq, Bytes::from(vec![0u8; 100])));
        // Drain pending SACKs (drives window retirement) without blocking.
        // The daemon's pump selects over recv_control continuously; we mirror
        // it by racing a short timeout against the control channel each iter.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(2), t.recv_control()).await;
    }

    // Let SACKs flush and the window retire, draining any stragglers.
    for _ in 0..50 {
        let _ = tokio::time::timeout(std::time::Duration::from_millis(10), t.recv_control()).await;
        if t.send_window_len() == 0 {
            break;
        }
    }

    // Every packet reached the server exactly once (dedup absorbs retransmit).
    assert_eq!(accepted.load(Ordering::Relaxed), N as usize);

    // The send window must have retired nearly everything via SACK; it must
    // not have grown unboundedly. Allow a small tail of in-flight packets.
    let remaining = t.send_window_len();
    assert!(
        remaining < N as usize / 2,
        "send window should retire via SACK, {remaining} still retained"
    );
}
