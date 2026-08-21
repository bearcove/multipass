#![cfg(target_os = "macos")]

mod dialer;
mod ipc;
mod routes;
mod state;
mod underlay;
mod utun;

use std::collections::HashSet;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use multipass::config::{ClientConfigFile, UplinkConfig};
use multipass::{PathId, Transport, UplinkId};
use multipass_proto::TUNNEL_MTU;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use crate::dialer::{
    Assignment, CandidateRace, QuicCandidateDialer, pinned_client_config,
    race_authenticated_candidates, transport_uplink,
};
use crate::state::{Shared, UplinkState};
use crate::underlay::{
    MacOsRouteBackend, MacOsUnderlayRouteResolver, RouteLease, RouteLeaseManager,
    UnderlayRouteResolver,
};

const CONTROLLER_TICK: Duration = Duration::from_millis(500);

struct Opts {
    config: PathBuf,
}

fn parse_args_from(args: &[String]) -> Result<Opts, String> {
    match args {
        [_, flag, path] if flag == "--config" => Ok(Opts {
            config: PathBuf::from(path),
        }),
        _ => Err("usage: multipassd --config <path>".into()),
    }
}

fn parse_args() -> Result<Opts, String> {
    parse_args_from(&std::env::args().collect::<Vec<_>>())
}

struct ActivationRequest {
    assignment: Assignment,
    reply: tokio::sync::oneshot::Sender<bool>,
}

struct InstalledPath {
    generation: u64,
    _lease: RouteLease<MacOsRouteBackend>,
}

struct UplinkController {
    path_id: PathId,
    uplink: UplinkConfig,
    client_epoch: u64,
    client_id: multipass::ClientId,
    endpoints: Vec<multipass::config::GatewayEndpoint>,
    client_config: noq::ClientConfig,
    resolver: Arc<MacOsUnderlayRouteResolver>,
    lease_manager: Arc<RouteLeaseManager<MacOsRouteBackend>>,
    target_generation_rx: watch::Receiver<u64>,
    ready_generation_rx: watch::Receiver<u64>,
    generation_ack_tx: mpsc::Sender<(PathId, u64)>,
    transport: Arc<Transport>,
    shared: Arc<Shared>,
    activation_tx: mpsc::Sender<ActivationRequest>,
    shutdown_rx: watch::Receiver<bool>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "multipassd=info,noq=warn".parse().unwrap()),
        )
        .init();

    let opts = parse_args()?;
    let runtime = ClientConfigFile::load_validated_runtime(&opts.config)?;
    let ipc_server = ipc::bind(runtime.config.ipc_socket.to_string_lossy().as_ref())?;

    let utun_raw = utun::Utun::open()?;
    let utun_name = utun_raw.name();
    let utun = Arc::new(AsyncFd::new(utun_raw)?);
    let shared = Shared::new(&runtime.config, utun_name.clone());
    let transport = Arc::new(Transport::from_connections(Vec::new())?);
    let resolver = Arc::new(MacOsUnderlayRouteResolver::new()?);
    let client_config =
        pinned_client_config(&runtime.identity, runtime.config.gateway.server_public_key)?;
    let initial_network_generation = resolver.snapshot().generation;
    let lease_manager = Arc::new(RouteLeaseManager::new(
        MacOsRouteBackend,
        initial_network_generation,
    ));

    info!(config = %opts.config.display(), uplinks = runtime.config.uplinks.len(), %utun_name, "multipassd starting");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let ipc_shutdown_tx = shutdown_tx.clone();
    let ipc_shared = shared.clone();
    let ipc_task = tokio::spawn(async move {
        let result = ipc::serve(ipc_server, ipc_shared).await;
        let _ = ipc_shutdown_tx.send(true);
        result
    });

    let (activation_tx, mut activation_rx) =
        mpsc::channel::<ActivationRequest>(runtime.config.uplinks.len().max(1));
    let client_epoch = new_client_epoch();
    let (target_generation_tx, target_generation_rx) = watch::channel(initial_network_generation);
    let (ready_generation_tx, ready_generation_rx) = watch::channel(initial_network_generation);
    let (generation_ack_tx, generation_ack_rx) = mpsc::channel(runtime.config.uplinks.len().max(1));
    let generation_task = tokio::spawn(coordinate_network_generations(
        resolver.clone(),
        lease_manager.clone(),
        (1..=runtime.config.uplinks.len())
            .map(|index| PathId::new(u16::try_from(index).expect("uplink count validated")))
            .collect(),
        target_generation_tx,
        ready_generation_tx,
        generation_ack_rx,
        shutdown_rx.clone(),
    ));
    let mut controllers = tokio::task::JoinSet::new();
    for (index, uplink) in runtime.config.uplinks.iter().cloned().enumerate() {
        let path_id =
            PathId::new(u16::try_from(index + 1).map_err(|_| "too many configured uplinks")?);
        controllers.spawn(run_uplink_controller(UplinkController {
            path_id,
            uplink,
            client_epoch,
            client_id: runtime.config.client.id.clone(),
            endpoints: runtime.config.gateway.endpoints.clone(),
            client_config: client_config.clone(),
            resolver: resolver.clone(),
            lease_manager: lease_manager.clone(),
            target_generation_rx: target_generation_rx.clone(),
            ready_generation_rx: ready_generation_rx.clone(),
            generation_ack_tx: generation_ack_tx.clone(),
            transport: transport.clone(),
            shared: shared.clone(),
            activation_tx: activation_tx.clone(),
            shutdown_rx: shutdown_rx.clone(),
        }));
    }
    drop(activation_tx);
    drop(generation_ack_tx);

    let (tx_q, mut rx_q) = mpsc::channel::<Bytes>(256);
    spawn_utun_reader(utun.clone(), tx_q);
    let lifecycle = run_lifecycle(
        utun,
        transport,
        shared.clone(),
        &mut rx_q,
        &mut activation_rx,
        shutdown_rx,
    )
    .await;

    shared.disconnect();
    let _ = shutdown_tx.send(true);
    while let Some(joined) = controllers.join_next().await {
        if let Err(error) = joined {
            warn!(%error, "uplink controller task failed");
        }
    }
    let _ = generation_task.await;

    ipc_task.abort();
    lifecycle
}

#[allow(clippy::too_many_arguments)]
async fn coordinate_network_generations(
    resolver: Arc<MacOsUnderlayRouteResolver>,
    lease_manager: Arc<RouteLeaseManager<MacOsRouteBackend>>,
    controller_paths: HashSet<PathId>,
    target_generation_tx: watch::Sender<u64>,
    ready_generation_tx: watch::Sender<u64>,
    mut generation_ack_rx: mpsc::Receiver<(PathId, u64)>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut ready_generation = *ready_generation_tx.borrow();
    let mut tick = tokio::time::interval(CONTROLLER_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    return;
                }
            }
            _ = tick.tick() => {}
        }
        let target_generation = resolver.snapshot().generation;
        if target_generation == ready_generation {
            continue;
        }
        if target_generation_tx.send(target_generation).is_err() {
            return;
        }
        let mut acknowledgements = HashSet::with_capacity(controller_paths.len());
        while acknowledgements != controller_paths {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        return;
                    }
                }
                acknowledgement = generation_ack_rx.recv() => {
                    match acknowledgement {
                        Some((path_id, generation))
                            if generation == target_generation
                                && controller_paths.contains(&path_id) => {
                            acknowledgements.insert(path_id);
                        }
                        Some(_) => {}
                        None => return,
                    }
                }
            }
        }
        lease_manager.advance_generation(target_generation);
        ready_generation = lease_manager.generation();
        if ready_generation_tx.send(ready_generation).is_err() {
            return;
        }
    }
}

async fn run_uplink_controller(controller: UplinkController) {
    let UplinkController {
        path_id,
        uplink,
        client_epoch,
        client_id,
        endpoints,
        client_config,
        resolver,
        lease_manager,
        target_generation_rx,
        ready_generation_rx,
        generation_ack_tx,
        transport,
        shared,
        activation_tx,
        mut shutdown_rx,
    } = controller;
    let mut installed: Option<InstalledPath> = None;
    let mut acknowledged_generation = *ready_generation_rx.borrow();
    let mut next_connection_generation = 0u64;
    let mut tick = tokio::time::interval(CONTROLLER_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            _ = tick.tick() => {}
        }

        let target_generation = *target_generation_rx.borrow();
        let ready_generation = *ready_generation_rx.borrow();
        if target_generation != ready_generation {
            remove_installed(&transport, path_id, &mut installed);
            if installed.is_some() {
                continue;
            }
            if acknowledged_generation != target_generation {
                if generation_ack_tx
                    .send((path_id, target_generation))
                    .await
                    .is_err()
                {
                    break;
                }
                acknowledged_generation = target_generation;
            }
            let _ = shared.update_uplink(&uplink.id, |status| status.clear_runtime(true));
            continue;
        }

        let enabled = shared.enabled.load(Ordering::Relaxed) && uplink.enabled;
        if !enabled {
            remove_installed(&transport, path_id, &mut installed);
            let _ = shared.update_uplink(&uplink.id, |snapshot| snapshot.clear_runtime(false));
            continue;
        }

        let snapshot = resolver.snapshot();
        if snapshot.generation != ready_generation {
            continue;
        }

        if installed.is_some() && transport.is_alive(path_id) {
            publish_transport_status(&transport, &shared, path_id, &uplink.id);
            continue;
        }
        let has_source = dialer::sources_for_interface(&snapshot, &uplink.interface)
            .into_iter()
            .next()
            .is_some();
        if !has_source {
            let _ = shared.update_uplink(&uplink.id, |status| {
                status.clear_runtime(true);
                status.state = UplinkState::WaitingForAddress;
            });
            continue;
        }

        let _ = shared.update_uplink(&uplink.id, |status| {
            status.state = UplinkState::RacingEndpoints;
            status.last_error = None;
        });
        let connection_generation = next_connection_generation;
        next_connection_generation = next_connection_generation.saturating_add(1);
        let candidate = race_authenticated_candidates(CandidateRace {
            resolver: resolver.as_ref(),
            lease_manager: &lease_manager,
            dialer: Arc::new(QuicCandidateDialer),
            snapshot,
            uplink: &uplink,
            endpoints: &endpoints,
            client_id: &client_id,
            client_epoch,
            path_id,
            connection_generation,
            client_config: &client_config,
        })
        .await;

        let candidate = match candidate {
            Ok(candidate) => candidate,
            Err(message) => {
                let _ = shared.update_uplink(&uplink.id, |status| {
                    status.state = UplinkState::Backoff;
                    status.ready = false;
                    status.set_last_error(message);
                });
                continue;
            }
        };

        if !shared.enabled.load(Ordering::Relaxed) {
            continue;
        }

        let dialer::AuthenticatedCandidate {
            connection,
            source,
            endpoint,
            assignment,
            lease,
        } = candidate;
        let install_result = if let Some(current) = installed.as_ref() {
            transport.replace_uplink(path_id, current.generation, connection)
        } else {
            transport.register_uplink(transport_uplink(path_id, uplink.id.clone(), connection))
        };
        let new_generation = match install_result {
            Ok(generation) => generation,
            Err(error) => {
                let _ = shared.update_uplink(&uplink.id, |status| {
                    status.state = UplinkState::Backoff;
                    status.set_last_error(error.to_string());
                });
                continue;
            }
        };

        // Replace ownership only after the transport accepted the new generation.
        // Dropping the old InstalledPath now releases its route after the old
        // connection has been replaced; the new lease remains controller-owned.
        installed = Some(InstalledPath {
            generation: new_generation,
            _lease: lease,
        });
        let _ = shared.update_uplink(&uplink.id, |status| {
            status.state = UplinkState::Authenticating;
            status.ready = false;
            status.source_address = Some(source);
            status.gateway_endpoint = Some(endpoint);
            status.last_error = None;
        });
        let (reply, activation) = tokio::sync::oneshot::channel();
        if activation_tx
            .send(ActivationRequest { assignment, reply })
            .await
            .is_err()
            || !activation.await.unwrap_or(false)
        {
            remove_installed(&transport, path_id, &mut installed);
            let _ = shared.update_uplink(&uplink.id, |status| {
                status.state = UplinkState::Error;
                status.ready = false;
                status.set_last_error("tunnel activation rejected");
            });
            continue;
        }
        transport.mark_ready(path_id);
        let _ = shared.update_uplink(&uplink.id, |status| {
            status.state = UplinkState::Ready;
            status.ready = true;
        });
    }

    remove_installed(&transport, path_id, &mut installed);
    let _ = shared.update_uplink(&uplink.id, |status| status.clear_runtime(false));
}

fn remove_installed(transport: &Transport, path_id: PathId, installed: &mut Option<InstalledPath>) {
    let Some(current) = installed.take() else {
        return;
    };
    match transport.remove_uplink(path_id, current.generation) {
        Ok(()) | Err(multipass::RegistryError::UnknownPath(_)) => {
            drop(current);
        }
        Err(error) => {
            warn!(path_id = path_id.get(), %error, "could not remove installed uplink; retaining route lease");
            *installed = Some(current);
        }
    }
}

async fn run_lifecycle(
    utun: Arc<AsyncFd<utun::Utun>>,
    transport: Arc<Transport>,
    shared: Arc<Shared>,
    rx_q: &mut mpsc::Receiver<Bytes>,
    activation_rx: &mut mpsc::Receiver<ActivationRequest>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut routes_active = false;
    let mut ipv6_active = false;
    let mut assignment: Option<Assignment> = None;
    let mut seq = new_epoch_sequence();
    let mut write_buf = vec![0u8; TUNNEL_MTU as usize + 4];
    let mut status_tick = tokio::time::interval(Duration::from_millis(250));
    status_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sack_tick = tokio::time::interval(Duration::from_millis(10));
    sack_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            request = activation_rx.recv() => {
                let Some(request) = request else { break };
                let accepted = if let Some(active) = assignment.as_ref() {
                    active == &request.assignment
                } else if activate_tunnel(&shared, &request.assignment) {
                    routes_active = true;
                    ipv6_active = request.assignment.ipv6.is_some();
                    assignment = Some(request.assignment.clone());
                    true
                } else {
                    false
                };
                let _ = request.reply.send(accepted);
            }
            _ = sack_tick.tick() => transport.broadcast_sack(),
            Some(packet) = rx_q.recv() => {
                if routes_active && shared.enabled.load(Ordering::Relaxed) {
                    seq += 1;
                    if transport.send_data(seq, packet.clone()) {
                        shared.tx_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
                    }
                }
            }
            data = transport.recv_data() => {
                let Some(data) = data else { continue };
                if let Some(status) = transport.path_status(data.path) {
                    shared.set_active(Some(status.uplink_id));
                }
                shared.rx_bytes.fetch_add(data.packet.len() as u64, Ordering::Relaxed);
                let family = match data.packet.first().map(|byte| byte >> 4) {
                    Some(4) => utun::AddressFamily::Inet,
                    Some(6) => utun::AddressFamily::Inet6,
                    _ => continue,
                };
                if routes_active && let Err(error) = utun.get_ref().write_packet(&mut write_buf, family, &data.packet) {
                    warn!(%error, "utun write error");
                }
            }
            dead = transport.recv_dead() => {
                warn!(path_id = dead.get(), "uplink declared dead");
                if let Some(status) = transport.path_status(dead) {
                    let _ = shared.update_uplink(&status.uplink_id, |uplink| {
                        uplink.ready = false;
                        uplink.state = UplinkState::Backoff;
                        uplink.set_last_error("connection liveness timeout");
                    });
                }
            }
            _ = status_tick.tick() => {
                publish_all_transport_status(&transport, &shared);
                if routes_active
                    && (!shared.enabled.load(Ordering::Relaxed)
                        || !transport
                            .status()
                            .uplinks
                            .iter()
                            .any(|uplink| uplink.ready && uplink.alive))
                {
                    teardown_tunnel(&shared, ipv6_active);
                    routes_active = false;
                    ipv6_active = false;
                    assignment = None;
                }
            }
        }
    }

    if routes_active {
        teardown_tunnel(&shared, ipv6_active);
    }
    Ok(())
}

fn activate_tunnel(shared: &Shared, assignment: &Assignment) -> bool {
    let Some((ipv4, prefix)) = assignment.ipv4 else {
        error!("server omitted required IPv4 tunnel assignment");
        return false;
    };
    if !routes::configure(&shared.utun_name, ipv4, prefix, assignment.mtu) {
        return false;
    }
    let ipv6_server = if let Some((ipv6, prefix)) = assignment.ipv6 {
        if !routes::configure_v6(&shared.utun_name, ipv6, prefix) {
            return false;
        }
        Some(ipv6_server_address(ipv6))
    } else {
        None
    };
    let server = shared
        .config
        .gateway
        .endpoints
        .first()
        .expect("validated config has an endpoint")
        .address
        .ip();
    if !routes::setup(&shared.utun_name, server, &[]) {
        return false;
    }
    if ipv6_server.is_some() && !routes::setup_v6(&shared.utun_name) {
        routes::teardown(&shared.utun_name, server, &[]);
        return false;
    }
    shared.activate(assignment.server_version.clone(), ipv6_server);
    true
}

fn teardown_tunnel(shared: &Shared, ipv6_active: bool) {
    if ipv6_active {
        routes::teardown_v6(&shared.utun_name);
    }
    let server = shared
        .config
        .gateway
        .endpoints
        .first()
        .expect("validated config has an endpoint")
        .address
        .ip();
    routes::teardown(&shared.utun_name, server, &[]);
    shared.deactivate();
}

fn publish_transport_status(
    transport: &Transport,
    shared: &Shared,
    path_id: PathId,
    uplink_id: &UplinkId,
) {
    let Some(status) = transport.path_status(path_id) else {
        return;
    };
    let _ = shared.update_uplink(uplink_id, |uplink| {
        uplink.ready = status.ready && status.alive;
        uplink.state = if uplink.ready {
            UplinkState::Ready
        } else {
            UplinkState::Backoff
        };
        uplink.rtt_ms = status.rtt.map(|rtt| rtt.as_secs_f64() * 1000.0);
        uplink.tx = status.transmitted_bytes;
        uplink.rx = status.received_bytes;
    });
}

fn publish_all_transport_status(transport: &Transport, shared: &Shared) {
    for status in transport.status().uplinks {
        publish_transport_status(transport, shared, status.path_id, &status.uplink_id);
    }
}

fn spawn_utun_reader(utun: Arc<AsyncFd<utun::Utun>>, tx_q: mpsc::Sender<Bytes>) {
    tokio::spawn(async move {
        let mut buffer = vec![0u8; TUNNEL_MTU as usize + 4];
        loop {
            let mut guard = match utun.readable().await {
                Ok(guard) => guard,
                Err(error) => {
                    error!(%error, "utun readiness error");
                    return;
                }
            };
            match guard.get_inner().read_packet(&mut buffer) {
                Ok(Some((_family, len))) => {
                    guard.clear_ready();
                    if tx_q
                        .send(Bytes::copy_from_slice(&buffer[..len]))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Ok(None) => guard.clear_ready(),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
                Err(error) => {
                    error!(%error, "utun read error");
                    return;
                }
            }
        }
    });
}

fn new_client_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
        ^ u64::from(std::process::id())
}

fn new_epoch_sequence() -> u64 {
    0
}

fn ipv6_server_address(client: std::net::Ipv6Addr) -> std::net::Ipv6Addr {
    std::net::Ipv6Addr::from((u128::from(client) & !(u64::MAX as u128)) | 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_config_argument() {
        let args = vec![
            "multipassd".into(),
            "--config".into(),
            "/tmp/config.json".into(),
        ];
        assert_eq!(
            parse_args_from(&args).unwrap().config,
            PathBuf::from("/tmp/config.json")
        );
        assert!(parse_args_from(&["multipassd".into()]).is_err());
        assert!(
            parse_args_from(&["multipassd".into(), "server:1".into(), "1.2.3.4".into()]).is_err()
        );
    }

    #[test]
    fn each_transport_epoch_starts_with_sequence_zero() {
        let mut first = new_epoch_sequence();
        first += 42;
        assert_eq!(first, 42);
        assert_eq!(new_epoch_sequence(), 0);
    }

    #[test]
    fn ipv6_server_is_first_host_of_assigned_prefix() {
        let client = "2001:db8:1234:5678::2".parse().unwrap();
        assert_eq!(
            ipv6_server_address(client),
            "2001:db8:1234:5678::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
        );
    }
}
