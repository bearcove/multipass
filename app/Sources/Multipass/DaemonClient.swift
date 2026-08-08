import Foundation

/// Errors surfaced by the unix-socket IPC with `multipassd`.
enum DaemonError: Error, Equatable {
    /// The socket is absent or refused the connection — the daemon is not
    /// installed or not running.
    case unavailable
    /// The daemon accepted the connection but did not answer in time.
    case timeout
    /// A system call failed with the given errno.
    case posix(errno: Int32)
    /// The daemon sent bytes that are not a well-formed reply line.
    case malformedReply
    /// The daemon answered `{"type":"error", ...}`.
    case daemon(String)
}

extension DaemonError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .unavailable:
            "multipassd is not running"
        case .timeout:
            "multipassd did not answer in time"
        case .posix(let errno):
            String(cString: strerror(errno))
        case .malformedReply:
            "multipassd sent a malformed reply"
        case .daemon(let message):
            message
        }
    }
}

/// Minimal POSIX client for the daemon's newline-JSON unix socket.
///
/// One request line in, one reply line out. The socket is connected lazily and
/// retried once on a stale connection. Send/receive are bounded by a 2s
/// timeout so a wedged daemon can never block the cooperative pool for long.
actor DaemonClient {
    static let defaultSocketPath = "/var/run/multipassd.sock"
    private static let ioTimeout: TimeInterval = 2

    private let path: String
    private var fd: Int32 = -1

    init(path: String = DaemonClient.defaultSocketPath) {
        self.path = path
    }
    /// Partial bytes carried between reads; replies are newline-delimited and
    /// small, but `recv` makes no message-boundary guarantees.
    private var pending = Data()

    /// Send a request, await the single reply line. `{"type":"error"}` replies
    /// throw `DaemonError.daemon`.
    func request(_ request: DaemonRequest) async throws -> DaemonReply {
        let reply = try await roundTrip(request)
        if case .error(let message) = reply {
            throw DaemonError.daemon(message)
        }
        return reply
    }

    private func roundTrip(_ request: DaemonRequest) async throws -> DaemonReply {
        var line = try await exchangeOnce(request)
        if line == nil {
            // Stale connection (daemon restarted): reconnect and retry once.
            disconnect()
            line = try await exchangeOnce(request)
        }
        guard let line else { throw DaemonError.unavailable }
        guard let reply = try? JSONDecoder().decode(DaemonReply.self, from: line) else {
            throw DaemonError.malformedReply
        }
        return reply
    }

    /// Connect if needed, write the request, read one reply line.
    /// Returns nil when the connection itself failed (caller may retry once).
    private func exchangeOnce(_ request: DaemonRequest) async throws -> Data? {
        if fd < 0 {
            do {
                try connect()
            } catch DaemonError.posix {
                disconnect()
                return nil
            }
        }

        var payload = try JSONEncoder().encode(request)
        payload.append(0x0A)
        do {
            try writeAll(payload)
        } catch {
            disconnect()
            return nil
        }

        do {
            return try readLine()
        } catch DaemonError.posix {
            disconnect()
            return nil
        }
    }

    private func connect() throws {
        let socket = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard socket >= 0 else { throw DaemonError.posix(errno: errno) }

        var timeout = timeval(
            tv_sec: Int(Self.ioTimeout),
            tv_usec: __darwin_suseconds_t(
                Self.ioTimeout.truncatingRemainder(dividingBy: 1) * 1_000_000
            )
        )
        for option in [SO_RCVTIMEO, SO_SNDTIMEO] {
            guard setsockopt(socket, SOL_SOCKET, option, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0
            else {
                let captured = errno
                Darwin.close(socket)
                throw DaemonError.posix(errno: captured)
            }
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathLength = path.utf8CString.count
        guard pathLength <= MemoryLayout.size(ofValue: address.sun_path) else {
            Darwin.close(socket)
            throw DaemonError.unavailable
        }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            path.utf8CString.withUnsafeBytes { source in
                buffer.copyMemory(from: source)
            }
        }

        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.connect(socket, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            let captured = errno
            Darwin.close(socket)
            throw DaemonError.posix(errno: captured)
        }
        fd = socket
        pending = Data()
    }

    private func disconnect() {
        if fd >= 0 {
            Darwin.close(fd)
            fd = -1
        }
        pending = Data()
    }

    private func writeAll(_ data: Data) throws {
        try data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            var sent = 0
            while sent < buffer.count {
                let written = Darwin.send(fd, base + sent, buffer.count - sent, 0)
                guard written >= 0 else { throw DaemonError.posix(errno: errno) }
                sent += written
            }
        }
    }

    /// Read until a newline. Bounded by SO_RCVTIMEO: a recv that times out
    /// throws `.timeout` instead of blocking forever.
    private func readLine() throws -> Data {
        while true {
            if let newlineIndex = pending.firstIndex(of: 0x0A) {
                let line = pending.prefix(upTo: newlineIndex)
                pending = pending.suffix(from: pending.index(after: newlineIndex))
                return Data(line)
            }
            var chunk = [UInt8](repeating: 0, count: 4096)
            let received = chunk.withUnsafeMutableBytes { buffer in
                Darwin.recv(fd, buffer.baseAddress, buffer.count, 0)
            }
            guard received > 0 else {
                if received == 0 { throw DaemonError.unavailable }
                if errno == EAGAIN || errno == EWOULDBLOCK { throw DaemonError.timeout }
                throw DaemonError.posix(errno: errno)
            }
            pending.append(contentsOf: chunk.prefix(received))
        }
    }
}
