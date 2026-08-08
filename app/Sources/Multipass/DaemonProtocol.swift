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

/// One response line from the daemon, discriminated by its `type` field.
nonisolated enum DaemonReply: Decodable, Sendable {
    case status(StatusSnapshot)
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
