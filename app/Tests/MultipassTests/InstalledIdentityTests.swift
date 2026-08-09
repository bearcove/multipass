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
