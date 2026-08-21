import Foundation
import Testing
@testable import Multipass

@Suite("Dynamic uplink status")
@MainActor
struct DynamicUplinkTests {
    @Test("status decoding preserves zero, one, two, and three ordered uplinks", arguments: [0, 1, 2, 3])
    func decodesOrderedUplinkCounts(count: Int) throws {
        let expected = Array(Self.uplinks.prefix(count))
        let snapshot = try Self.decodeStatus(
            enabled: count > 0,
            connected: expected.contains { $0.ready },
            activeUplinkID: expected.first { $0.ready }?.id,
            uplinks: expected
        )

        #expect(snapshot.uplinks == expected)
        #expect(snapshot.uplinks.map(\.id) == expected.map(\.id))
    }

    @Test("status decoding preserves topology reorder")
    func decodesTopologyReorder() throws {
        let reordered = [Self.uplinks[2], Self.uplinks[0], Self.uplinks[1]]
        let snapshot = try Self.decodeStatus(
            enabled: true,
            connected: true,
            activeUplinkID: reordered[1].id,
            uplinks: reordered
        )

        #expect(snapshot.uplinks.map(\.id) == ["phone-hotspot", "desk-ethernet", "wifi"])
    }

    @Test("controller preserves daemon order and derives rates by stable ID after reorder")
    func controllerRatesFollowStableIDsAcrossReorder() async throws {
        let first = Self.status(
            activeUplinkID: "wifi",
            uplinks: [
                Self.uplink(id: "desk-ethernet", displayName: "Desk Ethernet", tx: 100, rx: 200),
                Self.uplink(id: "wifi", displayName: "Wi-Fi", tx: 300, rx: 400),
                Self.uplink(id: "phone-hotspot", displayName: "Phone Hotspot", tx: 500, rx: 600),
            ]
        )
        let second = Self.status(
            activeUplinkID: "wifi",
            uplinks: [
                Self.uplink(id: "phone-hotspot", displayName: "Phone Hotspot", tx: 3_500, rx: 4_600),
                Self.uplink(id: "desk-ethernet", displayName: "Desk Ethernet", tx: 1_100, rx: 2_200),
                Self.uplink(id: "wifi", displayName: "Wi-Fi", tx: 2_300, rx: 3_400),
            ]
        )
        let daemon = DynamicStatusDaemon(statuses: [first, second])
        let controller = TunnelController(client: daemon, initialDaemonAvailability: .available)

        _ = try await controller.observedStatus()
        try await Task.sleep(for: .milliseconds(10))
        _ = try await controller.observedStatus()

        #expect(controller.uplinks.map(\.id) == ["phone-hotspot", "desk-ethernet", "wifi"])
        let rates = Dictionary(uniqueKeysWithValues: controller.uplinks.map { ($0.id, ($0.txRate, $0.rxRate)) })
        #expect(rates["desk-ethernet"]!.0 > 0)
        #expect(rates["wifi"]!.0 > rates["desk-ethernet"]!.0)
        #expect(rates["phone-hotspot"]!.0 > rates["wifi"]!.0)
        #expect(rates["phone-hotspot"]!.1 > rates["phone-hotspot"]!.0)
    }

    @Test("one stable ID counter reset does not suppress other uplink rates")
    func oneIDCounterResetIsIndependent() async throws {
        let first = Self.status(uplinks: [
            Self.uplink(id: "desk-ethernet", displayName: "Desk Ethernet", tx: 10_000, rx: 20_000),
            Self.uplink(id: "wifi", displayName: "Wi-Fi", tx: 30_000, rx: 40_000),
            Self.uplink(id: "phone-hotspot", displayName: "Phone Hotspot", tx: 50_000, rx: 60_000),
        ])
        let second = Self.status(uplinks: [
            Self.uplink(id: "desk-ethernet", displayName: "Desk Ethernet", tx: 100, rx: 200),
            Self.uplink(id: "wifi", displayName: "Wi-Fi", tx: 31_000, rx: 42_000),
            Self.uplink(id: "phone-hotspot", displayName: "Phone Hotspot", tx: 53_000, rx: 64_000),
        ])
        let daemon = DynamicStatusDaemon(statuses: [first, second])
        let controller = TunnelController(client: daemon, initialDaemonAvailability: .available)

        _ = try await controller.observedStatus()
        try await Task.sleep(for: .milliseconds(10))
        _ = try await controller.observedStatus()

        let rates = Dictionary(uniqueKeysWithValues: controller.uplinks.map { ($0.id, ($0.txRate, $0.rxRate)) })
        #expect(rates["desk-ethernet"]!.0 == 0)
        #expect(rates["desk-ethernet"]!.1 == 0)
        #expect(rates["wifi"]!.0 > 0)
        #expect(rates["wifi"]!.1 > rates["wifi"]!.0)
        #expect(rates["phone-hotspot"]!.0 > rates["wifi"]!.0)
        #expect(rates["phone-hotspot"]!.1 > rates["phone-hotspot"]!.0)
    }

    @Test("active uplink ID changes trigger failover by stable ID")
    func activeIDChangeTriggersFailover() async throws {
        let paths = [
            Self.uplink(id: "desk-ethernet", displayName: "Desk Ethernet"),
            Self.uplink(id: "wifi", displayName: "Wi-Fi"),
        ]
        let daemon = DynamicStatusDaemon(statuses: [
            Self.status(activeUplinkID: "desk-ethernet", uplinks: paths),
            Self.status(activeUplinkID: "wifi", uplinks: paths),
        ])
        let controller = TunnelController(client: daemon, initialDaemonAvailability: .available)

        _ = try await controller.observedStatus()
        #expect(controller.failoverToID == nil)
        _ = try await controller.observedStatus()

        #expect(controller.activeUplinkID == "wifi")
        #expect(controller.activeUplink?.displayName == "Wi-Fi")
        #expect(controller.failoverToID == "wifi")
        #expect(controller.failoverTo?.displayName == "Wi-Fi")
    }

    @Test("enabled but waiting remains enabled, disconnected, and disconnectable")
    func enabledWaitingUsesPersistentIntent() async throws {
        let waiting = Self.uplink(
            id: "desk-ethernet",
            displayName: "Desk Ethernet",
            state: "waiting_for_address",
            ready: false,
            sourceAddress: nil,
            gatewayEndpoint: nil,
            rttMs: nil
        )
        let daemon = DynamicStatusDaemon(statuses: [
            Self.status(enabled: true, connected: false, activeUplinkID: nil, uplinks: [waiting])
        ])
        let controller = TunnelController(client: daemon, initialDaemonAvailability: .available)

        try await controller.setConnected(true, owner: .menu)

        #expect(controller.enabled)
        #expect(controller.state == .disconnected)
        #expect(controller.canToggle)
        #expect(await daemon.requests == [.status])
    }

    @Test("disabled status remains distinct from enabled waiting")
    func disabledAndWaitingStatesAreDistinct() async throws {
        let disabled = Self.status(
            enabled: false,
            connected: false,
            activeUplinkID: nil,
            uplinks: [Self.uplink(
                id: "desk-ethernet",
                displayName: "Desk Ethernet",
                configuredEnabled: false,
                state: "disabled",
                ready: false,
                sourceAddress: nil,
                gatewayEndpoint: nil,
                rttMs: nil
            )]
        )
        let waiting = Self.status(
            enabled: true,
            connected: false,
            activeUplinkID: nil,
            uplinks: [Self.uplink(
                id: "desk-ethernet",
                displayName: "Desk Ethernet",
                state: "racing_endpoints",
                ready: false,
                gatewayEndpoint: nil,
                rttMs: nil
            )]
        )
        let daemon = DynamicStatusDaemon(statuses: [disabled, waiting])
        let controller = TunnelController(client: daemon, initialDaemonAvailability: .available)

        _ = try await controller.observedStatus()
        #expect(controller.state == .disconnected)
        #expect(controller.enabled == false)

        _ = try await controller.observedStatus()
        #expect(controller.state == .disconnected)
        #expect(controller.enabled)
    }

    @Test("uplink presentation covers disabled, waiting, racing, authenticating, ready, and error")
    func dynamicStateRenderingContract() {
        #expect(UplinkPresentation(state: "disabled", configuredEnabled: false, ready: false, lastError: nil).label == "Disabled")
        #expect(UplinkPresentation(state: "waiting_for_address", configuredEnabled: true, ready: false, lastError: nil).label == "Waiting for address")
        #expect(UplinkPresentation(state: "racing_endpoints", configuredEnabled: true, ready: false, lastError: nil).label == "Racing endpoints")
        #expect(UplinkPresentation(state: "authenticating", configuredEnabled: true, ready: false, lastError: nil).label == "Authenticating")
        #expect(UplinkPresentation(state: "ready", configuredEnabled: true, ready: true, lastError: nil).label == "Ready")
        #expect(UplinkPresentation(state: "route_error", configuredEnabled: true, ready: false, lastError: "No route").label == "Error: No route")
    }

    private static let uplinks = [
        uplink(id: "desk-ethernet", displayName: "Desk Ethernet", state: "waiting_for_address", ready: false, sourceAddress: nil, gatewayEndpoint: nil, rttMs: nil),
        uplink(id: "wifi", displayName: "Wi-Fi"),
        uplink(id: "phone-hotspot", displayName: "Phone Hotspot", state: "authenticating", ready: false, gatewayEndpoint: "203.0.113.10:51823", rttMs: nil),
    ]

    private static func status(
        enabled: Bool = true,
        connected: Bool = true,
        activeUplinkID: String? = "wifi",
        uplinks: [UplinkSnapshot]
    ) -> StatusSnapshot {
        StatusSnapshot(
            enabled: enabled,
            connected: connected,
            activeUplinkID: activeUplinkID,
            tx: uplinks.reduce(0) { $0 + $1.tx },
            rx: uplinks.reduce(0) { $0 + $1.rx },
            uplinks: uplinks
        )
    }

    private static func uplink(
        id: String,
        displayName: String,
        interface: String = "en0",
        configuredEnabled: Bool = true,
        state: String = "ready",
        ready: Bool = true,
        sourceAddress: String? = "192.0.2.10",
        gatewayEndpoint: String? = "[2001:db8::10]:51823",
        rttMs: Double? = 18.4,
        tx: UInt64 = 0,
        rx: UInt64 = 0,
        lastError: String? = nil
    ) -> UplinkSnapshot {
        UplinkSnapshot(
            id: id,
            displayName: displayName,
            interface: interface,
            configuredEnabled: configuredEnabled,
            state: state,
            ready: ready,
            sourceAddress: sourceAddress,
            gatewayEndpoint: gatewayEndpoint,
            rttMs: rttMs,
            tx: tx,
            rx: rx,
            lastError: lastError
        )
    }

    private static func decodeStatus(
        enabled: Bool,
        connected: Bool,
        activeUplinkID: String?,
        uplinks: [UplinkSnapshot]
    ) throws -> StatusSnapshot {
        let object: [String: Any] = [
            "type": "status",
            "enabled": enabled,
            "connected": connected,
            "active_uplink_id": activeUplinkID ?? NSNull(),
            "tx": uplinks.reduce(0) { $0 + $1.tx },
            "rx": uplinks.reduce(0) { $0 + $1.rx },
            "uplinks": uplinks.map { uplink -> [String: Any] in
                [
                    "id": uplink.id,
                    "display_name": uplink.displayName,
                    "interface": uplink.interface,
                    "configured_enabled": uplink.configuredEnabled,
                    "state": uplink.state,
                    "ready": uplink.ready,
                    "source_address": uplink.sourceAddress ?? NSNull(),
                    "gateway_endpoint": uplink.gatewayEndpoint ?? NSNull(),
                    "rtt_ms": uplink.rttMs ?? NSNull(),
                    "tx": uplink.tx,
                    "rx": uplink.rx,
                    "last_error": uplink.lastError ?? NSNull(),
                ]
            },
        ]
        let data = try JSONSerialization.data(withJSONObject: object)
        let reply = try JSONDecoder().decode(DaemonReply.self, from: data)
        guard case .status(let snapshot) = reply else {
            throw DynamicStatusTestError.unexpectedReply
        }
        return snapshot
    }
}

private actor DynamicStatusDaemon: DaemonRequesting {
    private var statuses: [StatusSnapshot]
    private(set) var requests: [DaemonRequest] = []

    init(statuses: [StatusSnapshot]) {
        self.statuses = statuses
    }

    func request(_ request: DaemonRequest) async throws -> DaemonReply {
        requests.append(request)
        guard request == .status, !statuses.isEmpty else { return .ok }
        return .status(statuses.removeFirst())
    }
}

private enum DynamicStatusTestError: Error {
    case unexpectedReply
}
