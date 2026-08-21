//! End-to-end aggregation test: real client `Transport` against an in-process
//! SACK-capable server over loopback. Verifies that striping + SACK retire the
//! client's send window (no unbounded growth) and that every packet is
//! delivered exactly once.

use bytes::Bytes;
use multipass::{PathId, RegistryError, Transport, UplinkConnection, UplinkDial, UplinkId};
use multipass_proto::{
    ClientId, Dedup, Frame, SackScoreboard, TUNNEL_CLIENT, TUNNEL_MTU, TUNNEL_PREFIX,
};
use noq::{ClientConfig, Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use tokio::sync::{mpsc, oneshot};

struct TestQuicConfig {
    client: ClientConfig,
    server: ServerConfig,
}

fn test_quic_config() -> &'static TestQuicConfig {
    use multipass::identity::{ClientIdentity, client_config, public_key_from_spki};
    use noq_proto::crypto::rustls::QuicServerConfig;
    use rcgen::PublicKeyData as _;
    use rustls::DistinguishedName;
    use rustls::crypto::{CryptoProvider, verify_tls13_signature_with_raw_key};
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer, UnixTime,
    };
    use rustls::server::AlwaysResolvesServerRawPublicKeys;
    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
    use rustls::sign::CertifiedKey;

    #[derive(Debug)]
    struct PinnedTestClient {
        pinned: multipass::identity::PublicKey,
        provider: Arc<CryptoProvider>,
    }

    impl ClientCertVerifier for PinnedTestClient {
        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            &[]
        }

        fn verify_client_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, rustls::Error> {
            if !intermediates.is_empty()
                || public_key_from_spki(end_entity.as_ref()).map_err(|_| {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
                })? != self.pinned
            {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer,
                ));
            }
            Ok(ClientCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("TLS 1.2 is disabled".into()))
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature_with_raw_key(
                message,
                &SubjectPublicKeyInfoDer::from(cert.as_ref()),
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![rustls::SignatureScheme::ED25519]
        }

        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }

    static CONFIG: LazyLock<TestQuicConfig> = LazyLock::new(|| {
        let client_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let client_identity =
            ClientIdentity::from_secure_bytes(client_key.serialize_der()).unwrap();
        let server_public = public_key_from_spki(&server_key.subject_public_key_info()).unwrap();
        let client = client_config(
            &client_identity,
            server_public,
            multipass::transport_config(),
        )
        .unwrap();

        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                server_key.serialize_der(),
            )))
            .unwrap();
        let public_spki = signing_key.public_key().unwrap();
        let certified_key = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(public_spki.as_ref().to_vec())],
            signing_key,
        ));
        let verifier = Arc::new(PinnedTestClient {
            pinned: client_identity.public_key(),
            provider: provider.clone().into(),
        });
        let mut tls = rustls::ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
                certified_key,
            )));
        tls.alpn_protocols = vec![multipass::ALPN.to_vec()];
        let crypto = QuicServerConfig::try_from(tls).unwrap();
        let mut server = ServerConfig::with_crypto(Arc::new(crypto));
        server.transport_config(multipass::transport_config());
        TestQuicConfig { client, server }
    });
    &CONFIG
}

fn test_dials(count: u16) -> Vec<UplinkDial> {
    (1..=count)
        .map(|id| UplinkDial {
            path_id: PathId::new(id),
            uplink_id: UplinkId::new(format!("path-{id}")).unwrap(),
            source: "127.0.0.1".parse().unwrap(),
        })
        .collect()
}

async fn dial_test_connection(addr: SocketAddr, path_id: u16, uplink_id: &str) -> UplinkConnection {
    UplinkConnection {
        path_id: PathId::new(path_id),
        uplink_id: UplinkId::new(uplink_id).unwrap(),
        connection: multipass::dial(
            addr,
            "127.0.0.1".parse().unwrap(),
            uplink_id,
            test_quic_config().client.clone(),
        )
        .await
        .unwrap(),
    }
}

/// Spawn a server that dedups inbound Data and periodically SACKs back its
/// receive state. Returns the server address and a count of unique packets
/// the server accepted.
async fn spawn_sack_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let server = Endpoint::server(
        test_quic_config().server.clone(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
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

async fn spawn_late_registry_server() -> (
    SocketAddr,
    oneshot::Receiver<(u64, Bytes)>,
    oneshot::Receiver<u64>,
) {
    let server = Endpoint::server(
        test_quic_config().server.clone(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let (data_tx, data_rx) = oneshot::channel();
    let (probe_tx, probe_rx) = oneshot::channel();
    tokio::spawn(async move {
        let Some(incoming) = server.accept().await else {
            return;
        };
        let Ok(conn) = incoming.await else { return };
        let mut data_tx = Some(data_tx);
        let mut probe_tx = Some(probe_tx);
        let mut scoreboard = SackScoreboard::new();
        while let Ok(datagram) = conn.read_datagram().await {
            match multipass_proto::decode(&datagram) {
                Some(Frame::Hello { .. }) => {
                    let assign = Frame::Assign {
                        ipv4: Some((TUNNEL_CLIENT, TUNNEL_PREFIX)),
                        ipv6: None,
                        mtu: TUNNEL_MTU,
                        dns: vec![],
                        server_version: "late-registry-test".into(),
                    };
                    let _ = conn.send_datagram(multipass_proto::encode(&assign));
                }
                Some(Frame::Data { seq, packet }) => {
                    scoreboard.insert(seq);
                    if let Some(tx) = data_tx.take() {
                        let _ = tx.send((seq, packet));
                    }
                    let _ =
                        conn.send_datagram(multipass_proto::encode(&scoreboard.generate_sack()));
                }
                Some(Frame::Ping { nonce }) => {
                    if let Some(tx) = probe_tx.take() {
                        let _ = tx.send(nonce);
                    }
                    let _ = conn.send_datagram(multipass_proto::encode(&Frame::Pong { nonce }));
                }
                _ => {}
            }
        }
    });
    (addr, data_rx, probe_rx)
}

async fn spawn_registry_server() -> SocketAddr {
    let server = Endpoint::server(
        test_quic_config().server.clone(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                while let Ok(datagram) = conn.read_datagram().await {
                    if let Some(Frame::Ping { nonce }) = multipass_proto::decode(&datagram) {
                        let _ = conn.send_datagram(multipass_proto::encode(&Frame::Pong { nonce }));
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn zero_to_one_late_path_completes_handshake_data_sack_and_probe() {
    let (addr, data_rx, probe_rx) = spawn_late_registry_server().await;
    let transport = Arc::new(Transport::from_connections(vec![]).unwrap());
    assert_eq!(transport.path_ids().count(), 0);
    assert!(!transport.send_data(1, Bytes::from_static(b"before-registration")));
    assert_eq!(
        transport.register_uplink(dial_test_connection(addr, 7, "late-uplink").await),
        Ok(0),
    );

    let path_id = PathId::new(7);
    assert!(transport.send_frame_on(
        path_id,
        &Frame::Hello {
            client_id: ClientId::new("late-client").unwrap(),
            client_epoch: 41,
            uplink_id: UplinkId::new("late-uplink").unwrap(),
            path_id,
            connection_generation: 0,
        },
    ));
    let (assigned_path, assign) =
        tokio::time::timeout(std::time::Duration::from_secs(1), transport.recv_control())
            .await
            .expect("late path must receive Assign")
            .unwrap();
    assert_eq!(assigned_path, path_id);
    assert!(matches!(assign, Frame::Assign { .. }));
    assert!(transport.mark_ready(path_id));
    assert!(transport.send_data(1, Bytes::from_static(b"late-data")));
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), data_rx)
            .await
            .expect("server must receive late-path Data")
            .unwrap(),
        (1, Bytes::from_static(b"late-data")),
    );
    let control_transport = transport.clone();
    let control_driver = tokio::spawn(async move {
        let _ = control_transport.recv_control().await;
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while transport.send_window_len() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("server SACK must retire the session send window");
    control_driver.abort();
    tokio::time::timeout(std::time::Duration::from_secs(1), probe_rx)
        .await
        .expect("probe task must discover the late path")
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while transport.path_status(path_id).unwrap().rtt.is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("late path probe RTT must be visible in status");
}

#[tokio::test]
async fn initial_registry_rejects_duplicate_ids_without_panicking() {
    let addr = spawn_registry_server().await;
    let first = dial_test_connection(addr, 8, "initial-alpha").await;
    let duplicate = UplinkConnection {
        path_id: PathId::new(8),
        uplink_id: UplinkId::new("initial-beta").unwrap(),
        connection: first.connection.clone(),
    };
    let error = match Transport::try_from_connections(vec![first, duplicate]) {
        Ok(_) => panic!("duplicate initial path ID must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error, RegistryError::DuplicatePathId(PathId::new(8)));
}
#[tokio::test]
async fn registry_rejects_duplicate_ids_and_stale_mutations() {
    let addr = spawn_registry_server().await;
    let transport = Transport::from_connections(vec![]).unwrap();
    assert_eq!(
        transport.register_uplink(dial_test_connection(addr, 1, "alpha").await),
        Ok(0),
    );
    assert_eq!(
        transport.register_uplink(dial_test_connection(addr, 1, "beta").await),
        Err(RegistryError::DuplicatePathId(PathId::new(1))),
    );
    assert_eq!(
        transport.register_uplink(dial_test_connection(addr, 2, "alpha").await),
        Err(RegistryError::DuplicateUplinkId(
            UplinkId::new("alpha").unwrap()
        )),
    );
    let replacement = dial_test_connection(addr, 1, "alpha-replacement").await;
    assert_eq!(
        transport.replace_uplink(PathId::new(1), 1, replacement.connection),
        Err(RegistryError::StaleGeneration {
            path_id: PathId::new(1),
            current: 0,
            expected: 1,
        }),
    );
    assert_eq!(
        transport.remove_uplink(PathId::new(1), 1),
        Err(RegistryError::StaleGeneration {
            path_id: PathId::new(1),
            current: 0,
            expected: 1,
        }),
    );
}

#[tokio::test]
async fn replacement_preserves_path_counters_and_session_send_window() {
    let addr = spawn_registry_server().await;
    let transport = Transport::from_connections(vec![]).unwrap();
    let path_id = PathId::new(3);
    assert_eq!(
        transport.register_uplink(dial_test_connection(addr, 3, "replaceable").await),
        Ok(0),
    );
    assert!(transport.mark_ready(path_id));
    assert!(transport.send_data(10, Bytes::from_static(b"retained")));
    let before = transport.path_status(path_id).unwrap();
    let replacement = dial_test_connection(addr, 3, "replacement-connection").await;
    assert_eq!(
        transport.replace_uplink(path_id, 0, replacement.connection),
        Ok(1),
    );
    let after = transport.path_status(path_id).unwrap();
    assert_eq!(after.generation, 1);
    assert_eq!(after.transmitted, before.transmitted);
    assert_eq!(transport.send_window_len(), 1);
    assert!(!after.ready);
    assert_eq!(transport.remove_uplink(path_id, 1), Ok(()));
    assert!(transport.path_status(path_id).is_none());
    assert!(!transport.send_data(11, Bytes::from_static(b"removed")));
    assert_eq!(transport.send_window_len(), 1);
}

#[tokio::test]
async fn aggregation_delivers_all_and_retires_window() {
    let (addr, accepted) = spawn_sack_server().await;
    let t = Transport::connect_with_client_config(
        addr,
        test_dials(2),
        test_quic_config().client.clone(),
    )
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
