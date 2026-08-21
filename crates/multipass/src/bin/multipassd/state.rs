use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use multipass::UplinkId;
use multipass::config::{ClientConfig, UplinkConfig};

pub const MAX_LAST_ERROR_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UplinkState {
    Disabled,
    WaitingForAddress,
    RacingEndpoints,
    Authenticating,
    Ready,
    Backoff,
    Error,
}

impl UplinkState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::WaitingForAddress => "waiting_for_address",
            Self::RacingEndpoints => "racing_endpoints",
            Self::Authenticating => "authenticating",
            Self::Ready => "ready",
            Self::Backoff => "backoff",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug)]
pub struct UplinkSnapshot {
    pub id: UplinkId,
    pub display_name: String,
    pub interface: String,
    pub configured_enabled: bool,
    pub state: UplinkState,
    pub ready: bool,
    pub source_address: Option<IpAddr>,
    pub gateway_endpoint: Option<SocketAddr>,
    pub rtt_ms: Option<f64>,
    pub tx: u64,
    pub rx: u64,
    pub last_error: Option<String>,
}

impl UplinkSnapshot {
    pub fn configured(config: &UplinkConfig, daemon_enabled: bool) -> Self {
        Self {
            id: config.id.clone(),
            display_name: config.display_name.clone(),
            interface: config.interface.clone(),
            configured_enabled: config.enabled,
            state: if config.enabled && daemon_enabled {
                UplinkState::WaitingForAddress
            } else {
                UplinkState::Disabled
            },
            ready: false,
            source_address: None,
            gateway_endpoint: None,
            rtt_ms: None,
            tx: 0,
            rx: 0,
            last_error: None,
        }
    }

    pub fn clear_runtime(&mut self, daemon_enabled: bool) {
        self.state = if self.configured_enabled && daemon_enabled {
            UplinkState::WaitingForAddress
        } else {
            UplinkState::Disabled
        };
        self.ready = false;
        self.source_address = None;
        self.gateway_endpoint = None;
        self.rtt_ms = None;
        self.last_error = None;
    }

    pub fn set_last_error(&mut self, error: impl Into<String>) {
        let mut error = error.into();
        if error.len() > MAX_LAST_ERROR_BYTES {
            let mut end = MAX_LAST_ERROR_BYTES;
            while !error.is_char_boundary(end) {
                end -= 1;
            }
            error.truncate(end);
        }
        self.last_error = Some(error);
    }
}

#[derive(Clone, Debug)]
pub struct DaemonSnapshot {
    pub enabled: bool,
    pub connected: bool,
    pub active_uplink_id: Option<UplinkId>,
    pub tx: u64,
    pub rx: u64,
    pub uplinks: Vec<UplinkSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownUplink(pub UplinkId);

impl fmt::Display for UnknownUplink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown uplink {}", self.0)
    }
}

impl std::error::Error for UnknownUplink {}

pub struct Shared {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub enabled: AtomicBool,
    pub config: ClientConfig,
    pub utun_name: String,
    uplinks: RwLock<Vec<UplinkSnapshot>>,
    active_uplink_id: RwLock<Option<UplinkId>>,
    server_version: RwLock<Option<String>>,
    tunnel_ipv6_server: RwLock<Option<Ipv6Addr>>,
}

impl Shared {
    pub fn new(config: &ClientConfig, utun_name: String) -> Arc<Self> {
        Arc::new(Self {
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
            config: config.clone(),
            utun_name,
            uplinks: RwLock::new(
                config
                    .uplinks
                    .iter()
                    .map(|uplink| UplinkSnapshot::configured(uplink, false))
                    .collect(),
            ),
            active_uplink_id: RwLock::new(None),
            server_version: RwLock::new(None),
            tunnel_ipv6_server: RwLock::new(None),
        })
    }

    pub fn connect(&self) {
        self.enabled.store(true, Ordering::Relaxed);
        for uplink in self.uplinks.write().unwrap().iter_mut() {
            uplink.clear_runtime(true);
        }
    }

    pub fn disconnect(&self) {
        self.enabled.store(false, Ordering::Relaxed);
        self.deactivate();
        for uplink in self.uplinks.write().unwrap().iter_mut() {
            uplink.clear_runtime(false);
        }
    }

    pub fn update_uplink(
        &self,
        id: &UplinkId,
        update: impl FnOnce(&mut UplinkSnapshot),
    ) -> Result<(), UnknownUplink> {
        let mut uplinks = self.uplinks.write().unwrap();
        let uplink = uplinks
            .iter_mut()
            .find(|uplink| &uplink.id == id)
            .ok_or_else(|| UnknownUplink(id.clone()))?;
        update(uplink);
        Ok(())
    }

    pub fn activate(&self, server_version: String, tunnel_ipv6_server: Option<Ipv6Addr>) {
        *self.server_version.write().unwrap() = Some(server_version);
        *self.tunnel_ipv6_server.write().unwrap() = tunnel_ipv6_server;
    }

    pub fn deactivate(&self) {
        *self.active_uplink_id.write().unwrap() = None;
        *self.server_version.write().unwrap() = None;
        *self.tunnel_ipv6_server.write().unwrap() = None;
    }

    pub fn set_active(&self, uplink_id: Option<UplinkId>) {
        *self.active_uplink_id.write().unwrap() = uplink_id;
    }

    pub fn snapshot(&self) -> DaemonSnapshot {
        let enabled = self.enabled.load(Ordering::Relaxed);
        let uplinks = self.uplinks.read().unwrap().clone();
        let active_uplink_id = self.active_uplink_id.read().unwrap().clone();
        let active_tunnel = self.server_version.read().unwrap().is_some();
        DaemonSnapshot {
            enabled,
            connected: enabled && active_tunnel && uplinks.iter().any(|uplink| uplink.ready),
            active_uplink_id,
            tx: self.tx_bytes.load(Ordering::Relaxed),
            rx: self.rx_bytes.load(Ordering::Relaxed),
            uplinks,
        }
    }

    pub fn authenticated_server_version(&self) -> String {
        self.server_version
            .read()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "unknown".into())
    }

    pub fn tunnel_ipv6_server(&self) -> Option<Ipv6Addr> {
        *self.tunnel_ipv6_server.read().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;

    use multipass::config::{
        ClientConfig, ClientIdentityConfig, GatewayConfig, GatewayEndpoint, UplinkConfig,
    };
    use multipass::identity::PublicKey;
    use multipass::{ClientId, UplinkId};

    use super::{Shared, UplinkSnapshot, UplinkState};

    fn config() -> ClientConfig {
        ClientConfig {
            gateway: GatewayConfig {
                id: "jax".into(),
                server_public_key: PublicKey::parse(
                    "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .unwrap(),
                endpoints: vec![GatewayEndpoint {
                    address: "10.10.10.1:51823".parse().unwrap(),
                    display_name: Some("Home LAN".into()),
                }],
            },
            client: ClientIdentityConfig {
                id: ClientId::new("scooter").unwrap(),
                private_key_file: "/var/db/multipass/client.key".into(),
            },
            uplinks: vec![
                UplinkConfig {
                    id: UplinkId::new("desk-ethernet").unwrap(),
                    display_name: "Desk Ethernet".into(),
                    interface: "en17".into(),
                    enabled: true,
                },
                UplinkConfig {
                    id: UplinkId::new("wifi").unwrap(),
                    display_name: "Wi-Fi".into(),
                    interface: "en0".into(),
                    enabled: false,
                },
            ],
            ipc_socket: "/var/run/multipassd.sock".into(),
        }
    }

    #[test]
    fn configured_order_and_enabled_state_are_preserved() {
        let shared = Shared::new(&config(), "utun3".into());
        let snapshot = shared.snapshot();

        assert!(!snapshot.enabled);
        assert!(!snapshot.connected);
        assert_eq!(
            snapshot
                .uplinks
                .iter()
                .map(|uplink| uplink.id.as_str())
                .collect::<Vec<_>>(),
            ["desk-ethernet", "wifi"]
        );
        assert_eq!(snapshot.uplinks[0].state, UplinkState::Disabled);
        assert!(snapshot.uplinks[0].configured_enabled);
        assert!(!snapshot.uplinks[1].configured_enabled);
    }

    #[test]
    fn enabling_waits_without_claiming_connectivity() {
        let shared = Shared::new(&config(), "utun3".into());
        shared.connect();
        let snapshot = shared.snapshot();

        assert!(snapshot.enabled);
        assert!(!snapshot.connected);
        assert_eq!(snapshot.uplinks[0].state, UplinkState::WaitingForAddress);
        assert_eq!(snapshot.uplinks[1].state, UplinkState::Disabled);
    }

    #[test]
    fn per_uplink_replacement_preserves_order_and_other_runtime() {
        let shared = Shared::new(&config(), "utun3".into());
        shared.connect();
        let wifi = UplinkId::new("wifi").unwrap();
        let ethernet = UplinkId::new("desk-ethernet").unwrap();
        shared
            .update_uplink(&wifi, |uplink| uplink.tx = 41)
            .unwrap();
        shared
            .update_uplink(&ethernet, |uplink| {
                uplink.state = UplinkState::Ready;
                uplink.ready = true;
                uplink.source_address = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
                uplink.gateway_endpoint = Some("10.10.10.1:51823".parse().unwrap());
                uplink.tx = 99;
            })
            .unwrap();
        shared.activate("server-build".into(), None);
        shared.set_active(Some(ethernet.clone()));

        let snapshot = shared.snapshot();
        assert!(snapshot.connected);
        assert_eq!(snapshot.active_uplink_id, Some(ethernet));
        assert_eq!(snapshot.uplinks[0].tx, 99);
        assert_eq!(snapshot.uplinks[1].tx, 41);
    }

    #[test]
    fn disconnect_clears_runtime_but_preserves_counters_and_configuration() {
        let shared = Shared::new(&config(), "utun3".into());
        shared.connect();
        let ethernet = UplinkId::new("desk-ethernet").unwrap();
        shared
            .update_uplink(&ethernet, |uplink| {
                uplink.state = UplinkState::Ready;
                uplink.ready = true;
                uplink.tx = 123;
                uplink.rx = 456;
                uplink.last_error = Some("prior error".into());
            })
            .unwrap();
        shared.activate("server-build".into(), None);
        shared.set_active(Some(ethernet));

        shared.disconnect();
        let snapshot = shared.snapshot();
        assert!(!shared.enabled.load(Ordering::Relaxed));
        assert!(!snapshot.enabled);
        assert!(!snapshot.connected);
        assert_eq!(snapshot.active_uplink_id, None);
        assert_eq!(snapshot.uplinks[0].state, UplinkState::Disabled);
        assert!(!snapshot.uplinks[0].ready);
        assert_eq!(snapshot.uplinks[0].tx, 123);
        assert_eq!(snapshot.uplinks[0].rx, 456);
        assert_eq!(snapshot.uplinks[0].last_error, None);
    }

    #[test]
    fn last_error_is_utf8_safe_and_bounded() {
        let mut snapshot = UplinkSnapshot::configured(&config().uplinks[0], true);
        snapshot.set_last_error("é".repeat(400));
        let error = snapshot.last_error.unwrap();
        assert!(error.len() <= super::MAX_LAST_ERROR_BYTES);
        assert!(error.is_char_boundary(error.len()));
    }
}
