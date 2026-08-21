import Foundation
import Testing
@testable import Multipass

@Suite("Installed build identity")
@MainActor
struct InstalledIdentityTests {
    @Test("bundle metadata prefers MultipassGitCommit")
    func bundleMetadataPrefersInjectedCommit() {
        let identity = MultipassApp.bundleIdentity(infoDictionary: [
            "MultipassGitCommit": "0123456789abcdef",
            "MultipassBuildCommit": "legacy-key-must-be-ignored",
            "CFBundleVersion": "42",
        ])

        #expect(identity == "0123456789abcdef")
    }

    @Test("bundle metadata falls back to CFBundleVersion")
    func bundleMetadataFallsBackToBundleVersion() {
        let identity = MultipassApp.bundleIdentity(infoDictionary: [
            "MultipassBuildCommit": "legacy-key-must-be-ignored",
            "CFBundleVersion": "42",
        ])

        #expect(identity == "42")
    }

    @Test("bundle metadata without an installed identity is unknown")
    func bundleMetadataWithoutIdentityIsUnknown() {
        #expect(MultipassApp.bundleIdentity(infoDictionary: [:]) == "unknown")
    }

    @Test("empty installed identity values fall through")
    func emptyInstalledIdentityValuesFallThrough() {
        #expect(MultipassApp.bundleIdentity(infoDictionary: [
            "MultipassGitCommit": "",
            "CFBundleVersion": "42",
        ]) == "42")
        #expect(MultipassApp.bundleIdentity(infoDictionary: [
            "MultipassGitCommit": "",
            "CFBundleVersion": "",
        ]) == "unknown")
    }

    @Test("daemon topology decodes daemon and server build identities")
    func daemonTopologyDecodesInstalledBuildIdentities() throws {
        let data = Data(#"""
        {
          "type": "benchmark_topology",
          "protocol_version": 2,
          "daemon_version": "daemon-0123456",
          "server_version": "server-789abcd",
          "underlay_target": "10.10.10.1",
          "tunnel_ipv4_target": "10.10.99.1",
          "tunnel_ipv6_target": "fd00:99::1",
          "listener_base_port": 5210,
          "listener_count": 16,
          "paths": [
            {
              "id": "wired",
              "display_name": "Wired",
              "interface": "en17",
              "source_address": "10.10.10.171"
            }
          ]
        }
        """#.utf8)

        let reply = try JSONDecoder().decode(DaemonReply.self, from: data)
        guard case .benchmarkTopology(let topology) = reply else {
            Issue.record("expected benchmark topology reply")
            return
        }

        #expect(topology.protocolVersion == 2)
        #expect(topology.daemonVersion == "daemon-0123456")
        #expect(topology.serverVersion == "server-789abcd")
    }

    @Test("daemon topology retains configured paths without source addresses")
    func daemonTopologyDecodesUnavailablePhysicalPath() throws {
        let data = Data(#"""
        {
          "type": "benchmark_topology",
          "protocol_version": 2,
          "daemon_version": "daemon-0123456",
          "server_version": "unknown",
          "underlay_target": "10.10.10.1",
          "tunnel_ipv4_target": "10.10.99.1",
          "tunnel_ipv6_target": null,
          "listener_base_port": 5210,
          "listener_count": 16,
          "paths": [
            {
              "id": "desk-ethernet",
              "display_name": "Desk Ethernet",
              "interface": "en17",
              "source_address": null
            }
          ]
        }
        """#.utf8)

        let reply = try JSONDecoder().decode(DaemonReply.self, from: data)
        guard case .benchmarkTopology(let topology) = reply else {
            Issue.record("expected benchmark topology reply")
            return
        }

        #expect(topology.paths.map(\.id) == ["desk-ethernet"])
        #expect(topology.paths[0].sourceAddress == nil)
    }

    @Test("daemon status decodes ordered dynamic uplink payloads")
    func daemonStatusDecodesDynamicUplinks() throws {
        let data = Data(#"""
        {
          "type": "status",
          "enabled": true,
          "connected": true,
          "active_uplink_id": "wifi",
          "tx": 1000,
          "rx": 2000,
          "uplinks": [
            {
              "id": "desk-ethernet",
              "display_name": "Desk Ethernet",
              "interface": "en17",
              "configured_enabled": true,
              "state": "waiting_for_address",
              "ready": false,
              "source_address": null,
              "gateway_endpoint": null,
              "rtt_ms": null,
              "tx": 300,
              "rx": 400,
              "last_error": null
            },
            {
              "id": "wifi",
              "display_name": "Wi-Fi",
              "interface": "en0",
              "configured_enabled": true,
              "state": "ready",
              "ready": true,
              "source_address": "192.0.2.10",
              "gateway_endpoint": "[2001:db8::10]:51823",
              "rtt_ms": 4.2,
              "tx": 700,
              "rx": 1600,
              "last_error": null
            }
          ]
        }
        """#.utf8)

        let reply = try JSONDecoder().decode(DaemonReply.self, from: data)
        guard case .status(let snapshot) = reply else {
            Issue.record("expected status reply")
            return
        }

        #expect(snapshot.enabled)
        #expect(snapshot.activeUplinkID == "wifi")
        #expect(snapshot.uplinks.map(\.id) == ["desk-ethernet", "wifi"])
        #expect(snapshot.uplinks[0].sourceAddress == nil)
        #expect(snapshot.uplinks[1].tx == 700)
        #expect(snapshot.uplinks[1].rx == 1600)
    }

    @Test("daemon topology requires daemon identity metadata")
    func daemonTopologyRequiresDaemonIdentityMetadata() {
        let data = Data(#"""
        {
          "type": "benchmark_topology",
          "protocol_version": 2,
          "server_version": "server-789abcd",
          "underlay_target": "10.10.10.1",
          "tunnel_ipv4_target": null,
          "tunnel_ipv6_target": null,
          "listener_base_port": 5210,
          "listener_count": 16,
          "paths": []
        }
        """#.utf8)

        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(DaemonReply.self, from: data)
        }
    }
}
