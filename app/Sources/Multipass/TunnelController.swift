import Foundation

/// What the UI knows about the tunnel right now.
enum TunnelState: Equatable {
    /// The daemon socket is unreachable — nothing else is meaningful.
    case daemonUnavailable
    case disconnected
    /// The user asked for a state change and we're waiting for it to take.
    case transitioning
    case connected

    var isConnected: Bool { self == .connected }
}

/// Observable bridge between `multipassd` and the menubar UI.
///
/// Polls `{"cmd":"status"}` once per second, sends connect/disconnect, and
/// derives the failover flash (active path changed while connected) plus
/// throughput rates from cumulative byte counters.
@Observable
@MainActor
final class TunnelController {
    private(set) var state: TunnelState = .disconnected
    private(set) var wiredLive = false
    private(set) var wifiLive = false
    private(set) var activePath: ActivePath?
    private(set) var rttMs: Double?
    private(set) var totalTx: UInt64 = 0
    private(set) var totalRx: UInt64 = 0
    /// Bytes/second, derived from consecutive status polls.
    private(set) var txRate: Double = 0
    private(set) var rxRate: Double = 0
    /// Non-nil while the failover flash is showing; carries the path we
    /// failed over *to*. The view animates on insertion/removal.
    private(set) var failoverTo: ActivePath?
    private(set) var lastError: String?

    private let client = DaemonClient()
    private var pollTask: Task<Void, Never>?
    /// Toggle intent is serialized through this task so a double-click can't
    /// interleave two commands.
    private var commandTask: Task<Void, Never>?
    private var previousSample: (tx: UInt64, rx: UInt64, at: ContinuousClock.Instant)?

    func start() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.poll()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func toggle() {
        guard commandTask == nil else { return }
        let connect = !state.isConnected
        commandTask = Task { [weak self] in
            guard let self else { return }
            defer { commandTask = nil }
            state = .transitioning
            do {
                _ = try await client.request(connect ? .connect : .disconnect)
                lastError = nil
            } catch {
                lastError = error.localizedDescription
            }
            // The daemon's own status is the source of truth for state; the
            // next poll settles us, but poll immediately so the UI doesn't sit
            // in "transitioning" for up to a second.
            await poll()
        }
    }

    private func poll() async {
        do {
            let reply = try await client.request(.status)
            guard case .status(let snapshot) = reply else { return }
            apply(snapshot)
            lastError = nil
        } catch {
            state = .daemonUnavailable
            wiredLive = false
            wifiLive = false
            activePath = nil
            rttMs = nil
            txRate = 0
            rxRate = 0
            previousSample = nil
            lastError = error.localizedDescription
        }
    }

    private func apply(_ snapshot: StatusSnapshot) {
        let now = ContinuousClock.now

        if let previous = previousSample {
            let elapsed = now - previous.at
            let seconds = Double(elapsed.components.seconds)
                + Double(elapsed.components.attoseconds) / 1e18
            if seconds > 0, snapshot.tx >= previous.tx, snapshot.rx >= previous.rx {
                txRate = Double(snapshot.tx - previous.tx) / seconds
                rxRate = Double(snapshot.rx - previous.rx) / seconds
            }
        }
        previousSample = (snapshot.tx, snapshot.rx, now)

        let wasConnected = state.isConnected
        state = snapshot.connected ? .connected : .disconnected
        wiredLive = snapshot.wired
        wifiLive = snapshot.wifi
        rttMs = snapshot.rttMs
        totalTx = snapshot.tx
        totalRx = snapshot.rx

        if snapshot.activePath != activePath {
            // A path change while staying connected IS a failover event.
            if wasConnected, snapshot.connected, let newPath = snapshot.activePath {
                flashFailover(to: newPath)
            }
            activePath = snapshot.activePath
        }
    }

    private func flashFailover(to path: ActivePath) {
        failoverTo = path
        Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(1200))
            guard let self, failoverTo == path else { return }
            failoverTo = nil
        }
    }
}
