import Foundation

/// IPC contract with `multipassd` over `/var/run/multipassd.sock`.
///
/// Newline-delimited JSON over a SOCK_STREAM unix socket: the app writes one
/// request object followed by `\n`, the daemon answers with exactly one
/// response object followed by `\n`. The canonical schema lives in
/// `app/README.md`; these types are the Swift encoding of it.
nonisolated enum DaemonRequest: Encodable {
    case status
    case connect
    case disconnect
    case benchmarkTopology

    private enum CodingKeys: String, CodingKey {
        case cmd
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        let cmd: String =
            switch self {
            case .status: "status"
            case .connect: "connect"
            case .disconnect: "disconnect"
            case .benchmarkTopology: "benchmark_topology"
            }
        try container.encode(cmd, forKey: .cmd)
    }
}

/// Which underlay path is currently winning the dedup race (delivering the
/// first copy of each packet). Drives the failover flash in the UI.
nonisolated enum ActivePath: String, Decodable, Sendable {
    case wired
    case wifi

    var displayName: String {
        switch self {
        case .wired: "Wired"
        case .wifi: "Wi-Fi"
        }
    }
}

/// `{"type":"status", ...}` payload. `tx`/`rx` are cumulative tunnel byte
/// counters since the daemon (re)started the session.
nonisolated struct StatusSnapshot: Decodable, Sendable {
    var connected: Bool
    var wired: Bool
    var wifi: Bool
    var activePath: ActivePath?
    var rttMs: Double?
    var tx: UInt64
    var rx: UInt64

    private enum CodingKeys: String, CodingKey {
        case connected
        case wired
        case wifi
        case activePath = "active_path"
        case rttMs = "rtt_ms"
        case tx
        case rx
    }
}

nonisolated struct BenchmarkPath: Decodable, Sendable, Equatable {
    var id: String
    var displayName: String
    var interface: String
    var sourceAddress: String

    private enum CodingKeys: String, CodingKey {
        case id
        case displayName = "display_name"
        case interface
        case sourceAddress = "source_address"
    }
}

nonisolated struct BenchmarkTopology: Decodable, Sendable, Equatable {
    var protocolVersion: UInt32
    var serverVersion: String
    var underlayTarget: String
    var tunnelIPv4Target: String?
    var tunnelIPv6Target: String?
    var listenerBasePort: UInt16
    var listenerCount: UInt16
    var paths: [BenchmarkPath]

    private enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case serverVersion = "server_version"
        case underlayTarget = "underlay_target"
        case tunnelIPv4Target = "tunnel_ipv4_target"
        case tunnelIPv6Target = "tunnel_ipv6_target"
        case listenerBasePort = "listener_base_port"
        case listenerCount = "listener_count"
        case paths
    }
}

/// One response line from the daemon, discriminated by its `type` field.
nonisolated enum DaemonReply: Decodable, Sendable {
    case status(StatusSnapshot)
    case benchmarkTopology(BenchmarkTopology)
    case ok
    case error(String)

    private enum TypeKeys: String, CodingKey {
        case type
        case message
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: TypeKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        switch type {
        case "status":
            self = .status(try StatusSnapshot(from: decoder))
        case "benchmark_topology":
            self = .benchmarkTopology(try BenchmarkTopology(from: decoder))
        case "ok":
            self = .ok
        case "error":
            self = .error(try container.decode(String.self, forKey: .message))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: container,
                debugDescription: "unknown reply type \"\(type)\""
            )
        }
    }
}
