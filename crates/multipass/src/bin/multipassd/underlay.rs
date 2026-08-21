//! Native underlay discovery and endpoint route leases for macOS.
//!
//! Resolution is deliberately based on immutable SystemConfiguration service
//! snapshots. It never asks the routing table for a default route, because the
//! utun half-defaults are already authoritative by the time a roaming uplink
//! may appear.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Weak};

use parking_lot::Mutex;

/// Address family recorded in a resolved underlay route.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

/// One address assigned by a native network service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAddress {
    pub address: IpAddr,
    pub prefix_len: u8,
}

/// Native state for one configured macOS network service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeService {
    pub service_id: String,
    pub interface: String,
    pub interface_up: bool,
    pub is_tunnel: bool,
    pub addresses: Vec<NativeAddress>,
    pub ipv4_router: Option<Ipv4Addr>,
    pub ipv6_router: Option<Ipv6Addr>,
    pub ipv6_router_scope: Option<String>,
}

/// Immutable native network state. Every refresh gets a strictly newer
/// generation, including a refresh after the SystemConfiguration daemon
/// restarts and delivers an empty notification key list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeNetworkSnapshot {
    pub generation: u64,
    pub services: Arc<[NativeService]>,
}

impl NativeNetworkSnapshot {
    pub fn new(generation: u64, services: Vec<NativeService>) -> Self {
        Self {
            generation,
            services: services.into(),
        }
    }
}

/// A native route independent of the utun-owned defaults.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UnderlayRoute {
    pub endpoint: IpAddr,
    pub interface: String,
    pub source: IpAddr,
    pub next_hop: Option<IpAddr>,
    pub family: AddressFamily,
    pub interface_scope: Option<String>,
    pub network_generation: u64,
}

impl UnderlayRoute {
    fn key(&self) -> RouteKey {
        RouteKey {
            endpoint: self.endpoint,
            interface: self.interface.clone(),
            source: self.source,
            next_hop: self.next_hop,
            interface_scope: self.interface_scope.clone(),
        }
    }
}

/// Why a source/endpoint pair cannot use the native service route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteError {
    FamilyMismatch,
    InterfaceUnavailable(String),
    SourceUnavailable(IpAddr),
    SourceIneligible(IpAddr),
    EndpointIneligible(IpAddr),
    NativeRouteUnavailable { interface: String, endpoint: IpAddr },
    SnapshotStale { requested: u64, current: u64 },
    InstallFailed(RouteKey),
    NativeSnapshot(String),
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FamilyMismatch => write!(f, "source and endpoint address families differ"),
            Self::InterfaceUnavailable(interface) => {
                write!(f, "native interface {interface} is unavailable")
            }
            Self::SourceUnavailable(source) => {
                write!(
                    f,
                    "source address {source} is not assigned to the interface"
                )
            }
            Self::SourceIneligible(source) => write!(f, "source address {source} is ineligible"),
            Self::EndpointIneligible(endpoint) => {
                write!(f, "endpoint address {endpoint} is ineligible")
            }
            Self::NativeRouteUnavailable {
                interface,
                endpoint,
            } => write!(
                f,
                "service for {interface} has no native route to {endpoint}"
            ),
            Self::SnapshotStale { requested, current } => write!(
                f,
                "network snapshot generation {requested} is stale; current generation is {current}"
            ),
            Self::InstallFailed(key) => write!(f, "could not install route {key:?}"),
            Self::NativeSnapshot(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for RouteError {}

/// Resolve sources against immutable native network state.
pub trait UnderlayRouteResolver {
    fn snapshot(&self) -> Arc<NativeNetworkSnapshot>;

    fn resolve(
        &self,
        snapshot: &NativeNetworkSnapshot,
        interface: &str,
        source: IpAddr,
        endpoint: IpAddr,
    ) -> Result<UnderlayRoute, RouteError>;
}

/// Deterministic resolver shared by the native backend and tests.
#[derive(Clone)]
pub struct SnapshotRouteResolver {
    current: Arc<Mutex<Arc<NativeNetworkSnapshot>>>,
}

impl SnapshotRouteResolver {
    pub fn new(snapshot: NativeNetworkSnapshot) -> Self {
        Self {
            current: Arc::new(Mutex::new(Arc::new(snapshot))),
        }
    }

    /// Publishes a new immutable state. Older generations cannot replace a
    /// newer one, so delayed native refresh work cannot roll state backward.
    pub fn publish(&self, snapshot: NativeNetworkSnapshot) -> bool {
        let mut current = self.current.lock();
        if snapshot.generation <= current.generation {
            return false;
        }
        *current = Arc::new(snapshot);
        true
    }
}

impl UnderlayRouteResolver for SnapshotRouteResolver {
    fn snapshot(&self) -> Arc<NativeNetworkSnapshot> {
        Arc::clone(&self.current.lock())
    }

    fn resolve(
        &self,
        snapshot: &NativeNetworkSnapshot,
        interface: &str,
        source: IpAddr,
        endpoint: IpAddr,
    ) -> Result<UnderlayRoute, RouteError> {
        let current_generation = self.snapshot().generation;
        if snapshot.generation != current_generation {
            return Err(RouteError::SnapshotStale {
                requested: snapshot.generation,
                current: current_generation,
            });
        }
        resolve_snapshot(snapshot, interface, source, endpoint)
    }
}

fn resolve_snapshot(
    snapshot: &NativeNetworkSnapshot,
    interface: &str,
    source: IpAddr,
    endpoint: IpAddr,
) -> Result<UnderlayRoute, RouteError> {
    let family = match (source, endpoint) {
        (IpAddr::V4(_), IpAddr::V4(_)) => AddressFamily::Ipv4,
        (IpAddr::V6(_), IpAddr::V6(_)) => AddressFamily::Ipv6,
        _ => return Err(RouteError::FamilyMismatch),
    };

    if !eligible_source(source) {
        return Err(RouteError::SourceIneligible(source));
    }
    if !eligible_endpoint(endpoint) {
        return Err(RouteError::EndpointIneligible(endpoint));
    }

    let interface_services: Vec<&NativeService> = snapshot
        .services
        .iter()
        .filter(|service| service.interface == interface)
        .collect();
    if interface_services.is_empty()
        || interface_services
            .iter()
            .all(|service| !service.interface_up || service.is_tunnel)
    {
        return Err(RouteError::InterfaceUnavailable(interface.to_owned()));
    }

    let Some((service, native_address)) = interface_services.into_iter().find_map(|service| {
        if !service.interface_up || service.is_tunnel {
            return None;
        }
        service
            .addresses
            .iter()
            .find(|address| address.address == source && valid_prefix(address))
            .map(|address| (service, address))
    }) else {
        return Err(RouteError::SourceUnavailable(source));
    };

    let next_hop = match (source, endpoint) {
        (IpAddr::V4(source), IpAddr::V4(endpoint)) => {
            if same_ipv4_network(source, endpoint, native_address.prefix_len) {
                None
            } else {
                Some(service.ipv4_router.map(IpAddr::V4).ok_or_else(|| {
                    RouteError::NativeRouteUnavailable {
                        interface: interface.to_owned(),
                        endpoint: IpAddr::V4(endpoint),
                    }
                })?)
            }
        }
        (IpAddr::V6(source), IpAddr::V6(endpoint)) => {
            if same_ipv6_network(source, endpoint, native_address.prefix_len) {
                None
            } else {
                Some(service.ipv6_router.map(IpAddr::V6).ok_or_else(|| {
                    RouteError::NativeRouteUnavailable {
                        interface: interface.to_owned(),
                        endpoint: IpAddr::V6(endpoint),
                    }
                })?)
            }
        }
        _ => unreachable!("family checked above"),
    };

    Ok(UnderlayRoute {
        endpoint,
        interface: interface.to_owned(),
        source,
        next_hop,
        family,
        interface_scope: (family == AddressFamily::Ipv6).then(|| {
            service
                .ipv6_router_scope
                .clone()
                .unwrap_or_else(|| interface.to_owned())
        }),
        network_generation: snapshot.generation,
    })
}

fn eligible_source(source: IpAddr) -> bool {
    match source {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_multicast()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_unicast_link_local()
                && !address.is_multicast()
        }
    }
}

fn eligible_endpoint(endpoint: IpAddr) -> bool {
    eligible_source(endpoint)
}

fn valid_prefix(address: &NativeAddress) -> bool {
    match address.address {
        IpAddr::V4(_) => address.prefix_len <= 32,
        IpAddr::V6(_) => address.prefix_len <= 128,
    }
}

fn same_ipv4_network(left: Ipv4Addr, right: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len > 32 {
        return false;
    }
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    (u32::from(left) & mask) == (u32::from(right) & mask)
}

fn same_ipv6_network(left: Ipv6Addr, right: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len > 128 {
        return false;
    }
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    (u128::from(left) & mask) == (u128::from(right) & mask)
}

/// Identity of one endpoint-specific scoped host route.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RouteKey {
    pub endpoint: IpAddr,
    pub interface: String,
    pub source: IpAddr,
    pub next_hop: Option<IpAddr>,
    pub interface_scope: Option<String>,
}

/// Boundary around native route installation/removal.
pub trait RouteBackend: Send + Sync + 'static {
    fn install(&self, route: &UnderlayRoute) -> bool;
    fn remove(&self, route: &UnderlayRoute) -> bool;
}

struct LeaseEntry {
    route: UnderlayRoute,
    owners: usize,
}

struct LeaseState<B> {
    backend: B,
    generation: u64,
    entries: HashMap<RouteKey, LeaseEntry>,
}

/// Reference-counted endpoint route manager fenced by network generation.
/// Backend mutations share the ownership critical section, preventing
/// duplicate installs and remove/install races.
pub struct RouteLeaseManager<B> {
    state: Arc<Mutex<LeaseState<B>>>,
}
impl<B: RouteBackend> RouteLeaseManager<B> {
    pub fn new(backend: B, generation: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(LeaseState {
                backend,
                generation,
                entries: HashMap::new(),
            })),
        }
    }

    pub fn generation(&self) -> u64 {
        self.state.lock().generation
    }
    /// Advances the generation and removes routes that belong only to older
    /// snapshots. Existing lease objects become inert after the advance.
    pub fn advance_generation(&self, generation: u64) -> bool {
        let mut state = self.state.lock();
        if generation <= state.generation {
            return false;
        }
        state.generation = generation;
        let stale = std::mem::take(&mut state.entries);
        for entry in stale.into_values() {
            if !state.backend.remove(&entry.route) {
                tracing::warn!(route = ?entry.route, "failed to remove stale underlay route");
            }
        }
        true
    }
    pub fn acquire(&self, route: UnderlayRoute) -> Result<RouteLease<B>, RouteError> {
        let key = route.key();
        let mut state = self.state.lock();
        if route.network_generation != state.generation {
            return Err(RouteError::SnapshotStale {
                requested: route.network_generation,
                current: state.generation,
            });
        }
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.owners += 1;
        } else {
            if !state.backend.install(&route) {
                return Err(RouteError::InstallFailed(key));
            }
            state
                .entries
                .insert(key.clone(), LeaseEntry { route, owners: 1 });
        }
        Ok(RouteLease {
            key: Some(key),
            generation: state.generation,
            manager: Arc::downgrade(&self.state),
        })
    }

    #[cfg(test)]
    fn owner_count(&self, key: &RouteKey) -> usize {
        self.state
            .lock()
            .entries
            .get(key)
            .map_or(0, |entry| entry.owners)
    }
}

pub struct RouteLease<B: RouteBackend> {
    key: Option<RouteKey>,
    generation: u64,
    manager: Weak<Mutex<LeaseState<B>>>,
}

impl<B: RouteBackend> RouteLease<B> {
    #[cfg(test)]
    pub fn key(&self) -> &RouteKey {
        self.key.as_ref().expect("released route lease")
    }

    fn release_inner(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        let Some(manager) = self.manager.upgrade() else {
            return;
        };
        let mut state = manager.lock();
        if state.generation != self.generation {
            return;
        }
        let Some(entry) = state.entries.get_mut(&key) else {
            return;
        };
        entry.owners -= 1;
        if entry.owners != 0 {
            return;
        }
        let entry = state.entries.remove(&key).expect("lease entry disappeared");
        if !state.backend.remove(&entry.route) {
            tracing::warn!(route = ?entry.route, "failed to remove underlay route");
        }
    }
}

impl<B: RouteBackend> Drop for RouteLease<B> {
    fn drop(&mut self) {
        self.release_inner();
    }
}

/// The real scoped-route backend. Route discovery stays native; route mutation
/// uses the macOS route utility's stable scoped-host interface, shared with the
/// daemon's tunnel/default-route owner in `routes.rs`.
#[derive(Clone, Copy, Debug, Default)]
pub struct MacOsRouteBackend;

impl RouteBackend for MacOsRouteBackend {
    fn install(&self, route: &UnderlayRoute) -> bool {
        crate::routes::install_underlay_route(route)
    }

    fn remove(&self, route: &UnderlayRoute) -> bool {
        crate::routes::remove_underlay_route(route)
    }
}

#[cfg(target_os = "macos")]
mod native {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, TCFType, ToVoid};
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::propertylist::CFPropertyList;
    use core_foundation::runloop::{CFRunLoop, kCFRunLoopCommonModes};
    use core_foundation::string::CFString;
    use system_configuration::dynamic_store::{
        SCDynamicStore, SCDynamicStoreBuilder, SCDynamicStoreCallBackContext,
    };
    use system_configuration::network_configuration::SCNetworkService;
    use system_configuration::preferences::SCPreferences;
    use system_configuration::sys::schema_definitions::{
        kSCPropNetIPv4Addresses, kSCPropNetIPv4Router, kSCPropNetIPv4SubnetMasks,
        kSCPropNetIPv6Addresses, kSCPropNetIPv6PrefixLength, kSCPropNetIPv6Router,
    };

    use super::*;

    /// SystemConfiguration-backed resolver. The notification worker publishes
    /// complete immutable snapshots when native network state changes.
    pub struct MacOsUnderlayRouteResolver {
        resolver: SnapshotRouteResolver,
    }

    impl MacOsUnderlayRouteResolver {
        pub fn new() -> Result<Self, RouteError> {
            let initial = read_snapshot(1)?;
            let resolver = SnapshotRouteResolver::new(initial);
            let worker_resolver = resolver.clone();
            thread::Builder::new()
                .name("multipass-underlay-state".to_owned())
                .spawn(move || notification_worker(worker_resolver))
                .map_err(|error| RouteError::NativeSnapshot(error.to_string()))?;
            Ok(Self { resolver })
        }
    }

    impl UnderlayRouteResolver for MacOsUnderlayRouteResolver {
        fn snapshot(&self) -> Arc<NativeNetworkSnapshot> {
            self.resolver.snapshot()
        }

        fn resolve(
            &self,
            snapshot: &NativeNetworkSnapshot,
            interface: &str,
            source: IpAddr,
            endpoint: IpAddr,
        ) -> Result<UnderlayRoute, RouteError> {
            self.resolver.resolve(snapshot, interface, source, endpoint)
        }
    }

    fn notification_worker(resolver: SnapshotRouteResolver) {
        static NOTIFICATION_GENERATION: AtomicU64 = AtomicU64::new(1);
        struct CallbackState {
            resolver: SnapshotRouteResolver,
        }
        fn changed(_store: SCDynamicStore, _keys: CFArray<CFString>, state: &mut CallbackState) {
            let generation = NOTIFICATION_GENERATION.fetch_add(1, Ordering::Relaxed) + 1;
            match read_snapshot(generation) {
                Ok(snapshot) => {
                    state.resolver.publish(snapshot);
                }
                Err(error) => tracing::warn!(%error, "native underlay refresh failed"),
            }
        }

        let callback = SCDynamicStoreCallBackContext {
            callout: changed,
            info: CallbackState {
                resolver: resolver.clone(),
            },
        };
        let Some(store) = SCDynamicStoreBuilder::new("multipassd underlay routes")
            .callback_context(callback)
            .build()
        else {
            tracing::error!("could not create SystemConfiguration dynamic store");
            return;
        };
        let keys = CFArray::<CFString>::from_CFTypes(&[]);
        let patterns = CFArray::from_CFTypes(&[
            CFString::from("State:/Network/Service/.*/(IPv4|IPv6|Interface|Link)"),
            CFString::from("Setup:/Network/Service/.*/Interface"),
        ]);
        if !store.set_notification_keys(&keys, &patterns) {
            tracing::error!("could not subscribe to native network changes");
            return;
        }
        let Some(source) = store.create_run_loop_source() else {
            tracing::error!("could not create native network run-loop source");
            return;
        };
        let run_loop = CFRunLoop::get_current();
        run_loop.add_source(&source, unsafe { kCFRunLoopCommonModes });

        loop {
            CFRunLoop::run_in_mode(
                unsafe { kCFRunLoopCommonModes },
                Duration::from_millis(250),
                true,
            );
        }
    }

    fn read_snapshot(generation: u64) -> Result<NativeNetworkSnapshot, RouteError> {
        let store = SCDynamicStoreBuilder::new("multipassd underlay snapshot")
            .build()
            .ok_or_else(|| RouteError::NativeSnapshot("could not open dynamic store".to_owned()))?;
        let preferences = SCPreferences::default(&CFString::new("multipassd underlay snapshot"));
        let mut services = Vec::new();

        for configured in SCNetworkService::get_services(&preferences).iter() {
            // The 0.7.0 high-level wrapper inverts this SDK Boolean.
            if unsafe {
                system_configuration::sys::network_configuration::SCNetworkServiceGetEnabled(
                    configured.as_concrete_TypeRef(),
                )
            } == 0
            {
                continue;
            }
            let Some(interface) = configured.network_interface() else {
                continue;
            };
            let Some(interface_name) = interface.bsd_name().map(|name| name.to_string()) else {
                continue;
            };
            let Some(service_id) = configured.id().map(|id| id.to_string()) else {
                continue;
            };
            let ipv4 = dictionary(&store, &format!("State:/Network/Service/{service_id}/IPv4"));
            let ipv6 = dictionary(&store, &format!("State:/Network/Service/{service_id}/IPv6"));
            let mut addresses = Vec::new();
            if let Some(dictionary) = ipv4.as_ref() {
                let ips = string_array(dictionary, unsafe { kSCPropNetIPv4Addresses });
                let masks = string_array(dictionary, unsafe { kSCPropNetIPv4SubnetMasks });
                for (ip, mask) in ips.into_iter().zip(masks) {
                    if let (Ok(ip), Ok(mask)) = (ip.parse(), mask.parse()) {
                        addresses.push(NativeAddress {
                            address: IpAddr::V4(ip),
                            prefix_len: ipv4_prefix(mask),
                        });
                    }
                }
            }
            if let Some(dictionary) = ipv6.as_ref() {
                let ips = string_array(dictionary, unsafe { kSCPropNetIPv6Addresses });
                let prefixes = number_array(dictionary, unsafe { kSCPropNetIPv6PrefixLength });
                for (ip, prefix_len) in ips.into_iter().zip(prefixes) {
                    if let Ok(ip) = ip.parse() {
                        addresses.push(NativeAddress {
                            address: IpAddr::V6(ip),
                            prefix_len: prefix_len.clamp(0, 128) as u8,
                        });
                    }
                }
            }
            let ipv6_router = ipv6
                .as_ref()
                .and_then(|dictionary| string(dictionary, unsafe { kSCPropNetIPv6Router }));
            let interface_state = crate::utun::interface_addresses(&interface_name);
            let interface_up = interface_state
                .as_ref()
                .is_some_and(|native| native.up && native.running);
            if let Some(interface_state) = interface_state {
                addresses.retain(|address| interface_state.addresses.contains(&address.address));
            } else {
                addresses.clear();
            }
            services.push(NativeService {
                service_id,
                is_tunnel: interface_name.starts_with("utun"),
                interface: interface_name,
                interface_up,
                addresses,
                ipv4_router: ipv4
                    .as_ref()
                    .and_then(|dictionary| string(dictionary, unsafe { kSCPropNetIPv4Router }))
                    .and_then(|router| router.parse().ok()),
                ipv6_router: ipv6_router
                    .as_deref()
                    .and_then(|router| router.split('%').next().and_then(|ip| ip.parse().ok())),
                ipv6_router_scope: ipv6_router
                    .as_deref()
                    .and_then(|router| router.split_once('%').map(|(_, scope)| scope.to_owned())),
            });
        }
        services.sort_by(|left, right| {
            (&left.interface, &left.service_id).cmp(&(&right.interface, &right.service_id))
        });
        Ok(NativeNetworkSnapshot::new(generation, services))
    }

    fn dictionary(store: &SCDynamicStore, key: &str) -> Option<CFDictionary> {
        store
            .get(key)
            .and_then(CFPropertyList::downcast_into::<CFDictionary>)
    }

    fn value(
        dictionary: &CFDictionary,
        key: core_foundation_sys::string::CFStringRef,
    ) -> Option<CFType> {
        dictionary
            .find(unsafe { CFString::wrap_under_get_rule(key) }.to_void())
            .map(|ptr| unsafe { CFType::wrap_under_get_rule(*ptr) })
    }

    fn string(
        dictionary: &CFDictionary,
        key: core_foundation_sys::string::CFStringRef,
    ) -> Option<String> {
        value(dictionary, key)
            .and_then(CFType::downcast_into::<CFString>)
            .map(|value| value.to_string())
    }

    fn string_array(
        dictionary: &CFDictionary,
        key: core_foundation_sys::string::CFStringRef,
    ) -> Vec<String> {
        value(dictionary, key)
            .and_then(CFType::downcast_into::<CFArray>)
            .map(|array| {
                array
                    .iter()
                    .filter_map(|value| {
                        unsafe { CFType::wrap_under_get_rule(*value) }.downcast_into::<CFString>()
                    })
                    .map(|value| value.to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn number_array(
        dictionary: &CFDictionary,
        key: core_foundation_sys::string::CFStringRef,
    ) -> Vec<i32> {
        value(dictionary, key)
            .and_then(CFType::downcast_into::<CFArray>)
            .map(|array| {
                array
                    .iter()
                    .filter_map(|value| {
                        unsafe { CFType::wrap_under_get_rule(*value) }.downcast_into::<CFNumber>()
                    })
                    .filter_map(|number| number.to_i32())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn ipv4_prefix(mask: Ipv4Addr) -> u8 {
        u32::from(mask).leading_ones() as u8
    }
}

#[cfg(target_os = "macos")]
pub use native::MacOsUnderlayRouteResolver;

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;

    fn service(
        interface: &str,
        address: IpAddr,
        prefix_len: u8,
        ipv4_router: Option<Ipv4Addr>,
        ipv6_router: Option<Ipv6Addr>,
    ) -> NativeService {
        NativeService {
            service_id: format!("service-{interface}"),
            interface: interface.to_owned(),
            interface_up: true,
            is_tunnel: interface.starts_with("utun"),
            addresses: vec![NativeAddress {
                address,
                prefix_len,
            }],
            ipv4_router,
            ipv6_router,
            ipv6_router_scope: None,
        }
    }

    #[test]
    fn underlay_lan_ipv4_is_on_link() {
        let snapshot = NativeNetworkSnapshot::new(
            7,
            vec![service(
                "en0",
                "192.168.1.23".parse().unwrap(),
                24,
                Some("192.168.1.1".parse().unwrap()),
                None,
            )],
        );
        let resolver = SnapshotRouteResolver::new(snapshot.clone());
        let route = resolver
            .resolve(
                &snapshot,
                "en0",
                "192.168.1.23".parse().unwrap(),
                "192.168.1.90".parse().unwrap(),
            )
            .unwrap();
        assert_eq!(route.next_hop, None);
        assert_eq!(route.network_generation, 7);
    }

    #[test]
    fn underlay_wan_ipv4_uses_service_router() {
        let snapshot = NativeNetworkSnapshot::new(
            8,
            vec![service(
                "en7",
                "10.20.30.40".parse().unwrap(),
                24,
                Some("10.20.30.1".parse().unwrap()),
                None,
            )],
        );
        let resolver = SnapshotRouteResolver::new(snapshot.clone());
        let route = resolver
            .resolve(
                &snapshot,
                "en7",
                "10.20.30.40".parse().unwrap(),
                "203.0.113.25".parse().unwrap(),
            )
            .unwrap();
        assert_eq!(route.next_hop, Some("10.20.30.1".parse().unwrap()));
    }

    #[test]
    fn underlay_ipv6_uses_interface_router() {
        let snapshot = NativeNetworkSnapshot::new(
            9,
            vec![service(
                "en0",
                "2001:db8:1::23".parse().unwrap(),
                64,
                None,
                Some("fe80::1".parse().unwrap()),
            )],
        );
        let resolver = SnapshotRouteResolver::new(snapshot.clone());
        let route = resolver
            .resolve(
                &snapshot,
                "en0",
                "2001:db8:1::23".parse().unwrap(),
                "2001:db8:ffff::1".parse().unwrap(),
            )
            .unwrap();
        assert_eq!(route.family, AddressFamily::Ipv6);
        assert_eq!(route.next_hop, Some("fe80::1".parse().unwrap()));
        assert_eq!(route.interface, "en0");
        assert_eq!(route.interface_scope.as_deref(), Some("en0"));

        let mut scoped_service = snapshot.services[0].clone();
        scoped_service.ipv6_router_scope = Some("en9".to_owned());
        let scoped_snapshot = NativeNetworkSnapshot::new(10, vec![scoped_service]);
        let scoped_resolver = SnapshotRouteResolver::new(scoped_snapshot.clone());
        let scoped_route = scoped_resolver
            .resolve(
                &scoped_snapshot,
                "en0",
                "2001:db8:1::23".parse().unwrap(),
                "2001:db8:ffff::1".parse().unwrap(),
            )
            .unwrap();
        assert_eq!(scoped_route.interface_scope.as_deref(), Some("en9"));
    }

    #[test]
    fn underlay_rejects_loopback_link_local_tunnel_and_unavailable_sources() {
        let snapshot = NativeNetworkSnapshot::new(
            1,
            vec![
                service("lo0", "127.0.0.1".parse().unwrap(), 8, None, None),
                service("en0", "169.254.2.3".parse().unwrap(), 16, None, None),
                service("utun9", "10.10.99.2".parse().unwrap(), 24, None, None),
            ],
        );
        let resolver = SnapshotRouteResolver::new(snapshot.clone());
        for (interface, source) in [
            ("lo0", "127.0.0.1"),
            ("en0", "169.254.2.3"),
            ("utun9", "10.10.99.2"),
            ("en9", "10.0.0.2"),
        ] {
            assert!(
                resolver
                    .resolve(
                        &snapshot,
                        interface,
                        source.parse().unwrap(),
                        "203.0.113.1".parse().unwrap(),
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn underlay_rejects_down_and_unassigned_sources() {
        let mut down = service(
            "en0",
            "10.0.0.23".parse().unwrap(),
            24,
            Some("10.0.0.1".parse().unwrap()),
            None,
        );
        down.interface_up = false;
        let snapshot = NativeNetworkSnapshot::new(
            3,
            vec![
                down,
                service(
                    "en7",
                    "192.168.5.8".parse().unwrap(),
                    24,
                    Some("192.168.5.1".parse().unwrap()),
                    None,
                ),
            ],
        );
        let resolver = SnapshotRouteResolver::new(snapshot.clone());
        assert!(matches!(
            resolver.resolve(
                &snapshot,
                "en0",
                "10.0.0.23".parse().unwrap(),
                "203.0.113.1".parse().unwrap(),
            ),
            Err(RouteError::InterfaceUnavailable(_))
        ));
        assert_eq!(
            resolver.resolve(
                &snapshot,
                "en7",
                "192.168.5.9".parse().unwrap(),
                "203.0.113.1".parse().unwrap(),
            ),
            Err(RouteError::SourceUnavailable(
                "192.168.5.9".parse().unwrap()
            ))
        );
    }

    #[test]
    fn underlay_requires_native_service_route_and_ignores_utun_default() {
        let snapshot = NativeNetworkSnapshot::new(
            2,
            vec![
                service("en0", "10.0.0.23".parse().unwrap(), 24, None, None),
                service(
                    "utun8",
                    "10.10.99.2".parse().unwrap(),
                    24,
                    Some("10.10.99.1".parse().unwrap()),
                    None,
                ),
            ],
        );
        let resolver = SnapshotRouteResolver::new(snapshot.clone());
        assert_eq!(
            resolver.resolve(
                &snapshot,
                "en0",
                "10.0.0.23".parse().unwrap(),
                "203.0.113.1".parse().unwrap(),
            ),
            Err(RouteError::NativeRouteUnavailable {
                interface: "en0".to_owned(),
                endpoint: "203.0.113.1".parse().unwrap(),
            })
        );
    }

    #[test]
    fn underlay_late_uplink_resolves_after_full_tunnel_snapshot() {
        let initial = NativeNetworkSnapshot::new(
            10,
            vec![service(
                "utun8",
                "10.10.99.2".parse().unwrap(),
                24,
                Some("10.10.99.1".parse().unwrap()),
                None,
            )],
        );
        let resolver = SnapshotRouteResolver::new(initial.clone());
        let late = NativeNetworkSnapshot::new(
            11,
            vec![
                initial.services[0].clone(),
                service(
                    "en5",
                    "172.20.10.4".parse().unwrap(),
                    28,
                    Some("172.20.10.1".parse().unwrap()),
                    None,
                ),
            ],
        );
        assert!(resolver.publish(late.clone()));
        assert!(matches!(
            resolver.resolve(
                &initial,
                "en5",
                "172.20.10.4".parse().unwrap(),
                "198.51.100.10".parse().unwrap(),
            ),
            Err(RouteError::SnapshotStale { .. })
        ));
        let route = resolver
            .resolve(
                &late,
                "en5",
                "172.20.10.4".parse().unwrap(),
                "198.51.100.10".parse().unwrap(),
            )
            .unwrap();
        assert_eq!(route.next_hop, Some("172.20.10.1".parse().unwrap()));
    }

    #[test]
    fn underlay_snapshot_rejects_out_of_order_publish() {
        let resolver = SnapshotRouteResolver::new(NativeNetworkSnapshot::new(5, Vec::new()));
        assert!(!resolver.publish(NativeNetworkSnapshot::new(5, Vec::new())));
        assert!(!resolver.publish(NativeNetworkSnapshot::new(4, Vec::new())));
        assert!(resolver.publish(NativeNetworkSnapshot::new(6, Vec::new())));
        assert_eq!(resolver.snapshot().generation, 6);
    }

    #[derive(Default)]
    struct FakeBackend {
        operations: Mutex<Vec<(bool, RouteKey)>>,
    }

    impl FakeBackend {
        fn operations(&self) -> Vec<(bool, RouteKey)> {
            self.operations.lock().clone()
        }
    }

    impl RouteBackend for Arc<FakeBackend> {
        fn install(&self, route: &UnderlayRoute) -> bool {
            self.operations.lock().push((true, route.key()));
            true
        }

        fn remove(&self, route: &UnderlayRoute) -> bool {
            self.operations.lock().push((false, route.key()));
            true
        }
    }

    #[derive(Default)]
    struct FailingBackend;

    impl RouteBackend for FailingBackend {
        fn install(&self, _route: &UnderlayRoute) -> bool {
            false
        }

        fn remove(&self, _route: &UnderlayRoute) -> bool {
            true
        }
    }

    fn test_route(generation: u64, endpoint: &str) -> UnderlayRoute {
        UnderlayRoute {
            endpoint: endpoint.parse().unwrap(),
            interface: "en0".to_owned(),
            source: "192.168.1.23".parse().unwrap(),
            next_hop: Some("192.168.1.1".parse().unwrap()),
            family: AddressFamily::Ipv4,
            interface_scope: None,
            network_generation: generation,
        }
    }

    #[test]
    fn route_leases_reference_count_and_remove_on_last_owner() {
        let backend = Arc::new(FakeBackend::default());
        let manager = RouteLeaseManager::new(Arc::clone(&backend), 4);
        let route = test_route(4, "203.0.113.1");
        let key = route.key();
        let first = manager.acquire(route.clone()).unwrap();
        let second = manager.acquire(route).unwrap();
        assert_eq!(manager.owner_count(&key), 2);
        assert_eq!(backend.operations().len(), 1);
        drop(first);
        assert_eq!(manager.owner_count(&key), 1);
        assert_eq!(backend.operations().len(), 1);
        drop(second);
        assert_eq!(manager.owner_count(&key), 0);
        assert_eq!(
            backend
                .operations()
                .iter()
                .map(|op| op.0)
                .collect::<Vec<_>>(),
            [true, false]
        );
    }

    #[test]
    fn route_candidate_losers_clean_up_while_winner_is_retained() {
        let backend = Arc::new(FakeBackend::default());
        let manager = RouteLeaseManager::new(Arc::clone(&backend), 6);
        let winner = manager.acquire(test_route(6, "203.0.113.1")).unwrap();
        let loser = manager.acquire(test_route(6, "198.51.100.2")).unwrap();
        drop(loser);
        let operations = backend.operations();
        assert!(operations.contains(&(false, test_route(6, "198.51.100.2").key())));
        assert!(!operations.contains(&(false, winner.key().clone())));
        drop(winner);
    }

    #[test]
    fn route_failed_install_creates_no_owner() {
        let manager = RouteLeaseManager::new(FailingBackend, 5);
        let route = test_route(5, "203.0.113.1");
        let key = route.key();
        assert!(matches!(
            manager.acquire(route),
            Err(RouteError::InstallFailed(failed_key)) if failed_key == key
        ));
        assert_eq!(manager.owner_count(&key), 0);
    }

    #[test]
    fn route_stale_generation_cannot_install_or_remove_newer_lease() {
        let backend = Arc::new(FakeBackend::default());
        let manager = RouteLeaseManager::new(Arc::clone(&backend), 7);
        let stale = manager.acquire(test_route(7, "203.0.113.1")).unwrap();
        assert!(manager.advance_generation(8));
        let current = manager.acquire(test_route(8, "203.0.113.1")).unwrap();
        let before_stale_drop = backend.operations();
        drop(stale);
        assert_eq!(backend.operations(), before_stale_drop);
        assert_eq!(manager.owner_count(current.key()), 1);
        assert!(matches!(
            manager.acquire(test_route(7, "198.51.100.2")),
            Err(RouteError::SnapshotStale { .. })
        ));
        drop(current);
    }
}
