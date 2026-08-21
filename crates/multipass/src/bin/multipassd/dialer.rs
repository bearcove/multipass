use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use multipass::config::{GatewayEndpoint, UplinkConfig};
use multipass::identity::client_config;
use multipass::{ClientId, PathId, UplinkConnection, UplinkId, dial, transport_config};
use multipass_proto::{Frame, TUNNEL_CLIENT, TUNNEL_MTU, TUNNEL_PREFIX};
use noq::{ClientConfig, Connection};
use tokio::task::JoinSet;

use crate::underlay::{
    MacOsRouteBackend, NativeNetworkSnapshot, RouteLease, RouteLeaseManager, UnderlayRouteResolver,
};

const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

pub type DialFuture = Pin<Box<dyn Future<Output = Result<Connection, String>> + Send>>;

pub trait CandidateDialer: Send + Sync + 'static {
    fn dial(
        &self,
        endpoint: SocketAddr,
        source: IpAddr,
        uplink_id: UplinkId,
        client_config: ClientConfig,
    ) -> DialFuture;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct QuicCandidateDialer;

impl CandidateDialer for QuicCandidateDialer {
    fn dial(
        &self,
        endpoint: SocketAddr,
        source: IpAddr,
        uplink_id: UplinkId,
        client_config: ClientConfig,
    ) -> DialFuture {
        Box::pin(async move {
            dial(endpoint, source, uplink_id.as_str(), client_config)
                .await
                .map_err(|error| error.to_string())
        })
    }
}

pub struct AuthenticatedCandidate {
    pub connection: Connection,
    pub source: IpAddr,
    pub endpoint: SocketAddr,
    pub assignment: Assignment,
    pub lease: RouteLease<MacOsRouteBackend>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assignment {
    pub ipv4: Option<(std::net::Ipv4Addr, u8)>,
    pub ipv6: Option<(std::net::Ipv6Addr, u8)>,
    pub mtu: u16,
    pub server_version: String,
}

pub struct CandidateRace<'a, R, D> {
    pub resolver: &'a R,
    pub lease_manager: &'a RouteLeaseManager<MacOsRouteBackend>,
    pub dialer: Arc<D>,
    pub snapshot: Arc<NativeNetworkSnapshot>,
    pub uplink: &'a UplinkConfig,
    pub endpoints: &'a [GatewayEndpoint],
    pub client_id: &'a ClientId,
    pub client_epoch: u64,
    pub path_id: PathId,
    pub connection_generation: u64,
    pub client_config: &'a ClientConfig,
}

pub async fn race_authenticated_candidates<R, D>(
    race: CandidateRace<'_, R, D>,
) -> Result<AuthenticatedCandidate, String>
where
    R: UnderlayRouteResolver,
    D: CandidateDialer,
{
    let CandidateRace {
        resolver,
        lease_manager,
        dialer,
        snapshot,
        uplink,
        endpoints,
        client_id,
        client_epoch,
        path_id,
        connection_generation,
        client_config,
    } = race;
    if resolver.snapshot().generation != snapshot.generation {
        return Err("network generation changed before endpoint race".into());
    }
    lease_manager.advance_generation(snapshot.generation);
    let sources = sources_for_interface(&snapshot, &uplink.interface);
    if sources.is_empty() {
        return Err(format!(
            "interface {} has no eligible native address",
            uplink.interface
        ));
    }

    let mut tasks = JoinSet::new();
    let mut candidate_count = 0usize;
    for source in sources {
        for endpoint in endpoints {
            if !same_family(source, endpoint.address.ip()) {
                continue;
            }
            let route =
                match resolver.resolve(&snapshot, &uplink.interface, source, endpoint.address.ip())
                {
                    Ok(route) => route,
                    Err(_) => continue,
                };
            let lease = match lease_manager.acquire(route) {
                Ok(lease) => lease,
                Err(_) => continue,
            };
            candidate_count += 1;
            let dialer = dialer.clone();
            let endpoint = endpoint.address;
            let uplink_id = uplink.id.clone();
            let client_id = client_id.clone();
            let client_config = client_config.clone();
            tasks.spawn(async move {
                let connection = dialer
                    .dial(endpoint, source, uplink_id.clone(), client_config)
                    .await?;
                let assignment = authenticate_candidate(
                    &connection,
                    client_id,
                    client_epoch,
                    uplink_id,
                    path_id,
                    connection_generation,
                )
                .await?;
                Ok::<_, String>(AuthenticatedCandidate {
                    connection,
                    source,
                    endpoint,
                    assignment,
                    lease,
                })
            });
        }
    }

    if candidate_count == 0 {
        return Err("no compatible source and gateway endpoint candidates".into());
    }

    let mut last_error = None;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(candidate)) => {
                if resolver.snapshot().generation != snapshot.generation {
                    candidate
                        .connection
                        .close(0u32.into(), b"stale network generation");
                    return Err("network generation changed during endpoint race".into());
                }
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                return Ok(candidate);
            }
            Ok(Err(error)) => last_error = Some(error),
            Err(error) if !error.is_cancelled() => last_error = Some(error.to_string()),
            Err(_) => {}
        }
    }
    Err(last_error.unwrap_or_else(|| "all endpoint candidates failed".into()))
}

async fn authenticate_candidate(
    connection: &Connection,
    client_id: ClientId,
    client_epoch: u64,
    uplink_id: UplinkId,
    path_id: PathId,
    connection_generation: u64,
) -> Result<Assignment, String> {
    let hello = Frame::Hello {
        client_id,
        client_epoch,
        uplink_id,
        path_id,
        connection_generation,
    };
    let deadline = tokio::time::Instant::now() + AUTH_TIMEOUT;
    loop {
        connection
            .send_datagram(multipass_proto::encode(&hello))
            .map_err(|error| format!("send authenticated Hello: {error}"))?;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("timed out waiting for authenticated assignment".into());
        }
        match tokio::time::timeout(
            remaining.min(Duration::from_millis(250)),
            connection.read_datagram(),
        )
        .await
        {
            Ok(Ok(datagram)) => match multipass_proto::decode(&datagram) {
                Some(Frame::Assign {
                    ipv4,
                    ipv6,
                    mtu,
                    server_version,
                    ..
                }) => {
                    if ipv4 != Some((TUNNEL_CLIENT, TUNNEL_PREFIX)) || mtu != TUNNEL_MTU {
                        return Err("server assignment does not match tunnel contract".into());
                    }
                    if server_version.is_empty() {
                        return Err("server assignment omitted build identity".into());
                    }
                    return Ok(Assignment {
                        ipv4,
                        ipv6,
                        mtu,
                        server_version,
                    });
                }
                Some(Frame::Ping { nonce }) => {
                    let _ =
                        connection.send_datagram(multipass_proto::encode(&Frame::Pong { nonce }));
                }
                _ => {}
            },
            Ok(Err(error)) => {
                return Err(format!("candidate closed before assignment: {error}"));
            }
            Err(_) => {}
        }
    }
}

pub fn sources_for_interface(snapshot: &NativeNetworkSnapshot, interface: &str) -> Vec<IpAddr> {
    snapshot
        .services
        .iter()
        .filter(|service| {
            service.interface == interface && service.interface_up && !service.is_tunnel
        })
        .flat_map(|service| service.addresses.iter().map(|address| address.address))
        .collect()
}

fn same_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

pub fn pinned_client_config(
    identity: &multipass::identity::ClientIdentity,
    server_public_key: multipass::identity::PublicKey,
) -> Result<ClientConfig, multipass::identity::IdentityError> {
    client_config(identity, server_public_key, transport_config())
}

pub fn transport_uplink(
    path_id: PathId,
    uplink_id: UplinkId,
    connection: Connection,
) -> UplinkConnection {
    UplinkConnection {
        path_id,
        uplink_id,
        connection,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::UplinkState;
    use crate::underlay::{NativeAddress, NativeService};

    fn snapshot(addresses: Vec<IpAddr>) -> NativeNetworkSnapshot {
        NativeNetworkSnapshot::new(
            7,
            vec![NativeService {
                service_id: "service".into(),
                interface: "en0".into(),
                interface_up: true,
                is_tunnel: false,
                addresses: addresses
                    .into_iter()
                    .map(|address| NativeAddress {
                        prefix_len: if address.is_ipv4() { 24 } else { 64 },
                        address,
                    })
                    .collect(),
                ipv4_router: None,
                ipv6_router: None,
                ipv6_router_scope: None,
            }],
        )
    }

    #[test]
    fn canonical_lifecycle_state_strings_match_status_contract() {
        assert_eq!(UplinkState::Disabled.as_str(), "disabled");
        assert_eq!(
            UplinkState::WaitingForAddress.as_str(),
            "waiting_for_address"
        );
        assert_eq!(UplinkState::RacingEndpoints.as_str(), "racing_endpoints");
        assert_eq!(UplinkState::Authenticating.as_str(), "authenticating");
        assert_eq!(UplinkState::Ready.as_str(), "ready");
        assert_eq!(UplinkState::Backoff.as_str(), "backoff");
        assert_eq!(UplinkState::Error.as_str(), "error");
    }

    #[test]
    fn source_collection_preserves_native_service_order() {
        let first: IpAddr = "192.0.2.4".parse().unwrap();
        let second: IpAddr = "2001:db8::4".parse().unwrap();
        assert_eq!(
            sources_for_interface(&snapshot(vec![first, second]), "en0"),
            vec![first, second]
        );
    }
}
