import Foundation

/// What the UI knows about the tunnel right now.
nonisolated enum DaemonAvailability: Sendable, Equatable {
    case unknown
    case available
    case unavailable
}

enum TunnelState: Equatable {
    /// The daemon socket is unreachable — nothing else is meaningful.
    case daemonUnavailable
    case disconnected
    /// The user asked for a state change and we're waiting for it to take.
    case transitioning
    case connected

    var isConnected: Bool { self == .connected }
}

nonisolated enum TunnelTransitionOwner: Sendable, Equatable {
    case menu
    case benchmark(UUID)
}

nonisolated enum TunnelTransitionError: Error, Sendable, Equatable {
    case lifecycleOwnedByBenchmark
    case unexpectedReply
    case unhealthyConnectedStatus
    case transitionTimedOut(desiredConnected: Bool)
}

extension TunnelTransitionError: LocalizedError {
    nonisolated var errorDescription: String? {
        switch self {
        case .lifecycleOwnedByBenchmark:
            "A benchmark is controlling the tunnel"
        case .unexpectedReply:
            "The daemon returned an unexpected tunnel reply"
        case .unhealthyConnectedStatus:
            "The tunnel connected without a live path"
        case .transitionTimedOut(let desiredConnected):
            "Timed out waiting for the tunnel to become \(desiredConnected ? "connected" : "disconnected")"
        }
    }
}

/// Observable bridge between `multipassd` and the menubar UI.
///
/// Polls `{"cmd":"status"}` once per second, serializes owner-aware desired-state
/// transitions through daemon-observed convergence, derives throughput rates
/// from cumulative byte counters, and raises the failover flash when
/// `active_path` changes while connected.
@Observable
@MainActor
final class TunnelController {
    private(set) var state: TunnelState = .disconnected
    private(set) var daemonAvailability: DaemonAvailability = .unknown
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
    private(set) var benchmarkOwner: UUID?

    var benchmarkOwnsLifecycle: Bool { benchmarkOwner != nil }
    var canToggle: Bool {
        benchmarkOwner == nil && daemonAvailability == .available && state != .transitioning
    }

    private let client: any DaemonRequesting
    private var pollTask: Task<Void, Never>?
    private var transition: (id: UUID, task: Task<Void, Error>)?
    private var previousSample: (tx: UInt64, rx: UInt64, at: ContinuousClock.Instant)?

    init(
        client: any DaemonRequesting = DaemonClient(),
        initialDaemonAvailability: DaemonAvailability = .unknown
    ) {
        self.client = client
        daemonAvailability = initialDaemonAvailability
    }

    func start() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refreshStatus()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func stop() async {
        pollTask?.cancel()
        await pollTask?.value
        pollTask = nil
    }

    func toggle() {
        guard canToggle else { return }
        let connect = !state.isConnected
        Task { [weak self] in
            guard let self else { return }
            do {
                try await setConnected(connect, owner: .menu)
            } catch {
                lastError = error.localizedDescription
            }
        }
    }

    /// Claims lifecycle ownership after every already-admitted transition has
    func acquireBenchmarkOwnership(_ owner: UUID) async throws {
        if let benchmarkOwner, benchmarkOwner != owner {
            throw TunnelTransitionError.lifecycleOwnedByBenchmark
        }
        while let active = transition {
            _ = try? await active.task.value
            if transition?.id == active.id {
                transition = nil
            }
        }
        if let benchmarkOwner, benchmarkOwner != owner {
            throw TunnelTransitionError.lifecycleOwnedByBenchmark
        }
        benchmarkOwner = owner
    }

    func releaseBenchmarkOwnership(_ owner: UUID) {
        guard benchmarkOwner == owner else { return }
        benchmarkOwner = nil
    }

    /// Returns the daemon's observed status. No connection truth is mirrored
    /// for orchestration: callers capture state from this snapshot.
    func observedStatus() async throws -> StatusSnapshot {
        let reply = try await client.request(.status)
        guard case .status(let snapshot) = reply else {
            throw TunnelTransitionError.unexpectedReply
        }
        apply(snapshot)
        lastError = nil
        daemonAvailability = .available
        return snapshot
    }

    /// Idempotently requests and waits for the desired daemon-observed state.
    /// The command reply is not completion; following status replies are truth.
    func setConnected(_ connected: Bool, owner: TunnelTransitionOwner) async throws {
        try validate(owner: owner)
        let preceding = transition?.task
        let client = self.client
        let transitionID = UUID()
        let task = Task<Void, Error> { @MainActor [weak self] in
            if let preceding {
                _ = try? await preceding.value
            }
            guard let self else { throw CancellationError() }
            try validate(owner: owner)
            try Task.checkCancellation()

            let beforeReply = try await client.request(.status)
            guard case .status(let before) = beforeReply else {
                throw TunnelTransitionError.unexpectedReply
            }
            if !matchesDesiredStatus(before, connected: connected) {
                let commandReply = try await client.request(connected ? .connect : .disconnect)
                guard case .ok = commandReply else {
                    throw TunnelTransitionError.unexpectedReply
                }
            }

            let clock = ContinuousClock()
            let deadline = clock.now + .seconds(10)
            var observed = before
            while !matchesDesiredStatus(observed, connected: connected) {
                try Task.checkCancellation()
                guard clock.now < deadline else {
                    throw TunnelTransitionError.transitionTimedOut(desiredConnected: connected)
                }
                await Task.yield()
                let observedReply = try await client.request(.status)
                guard case .status(let snapshot) = observedReply else {
                    throw TunnelTransitionError.unexpectedReply
                }
                observed = snapshot
            }
        }
        transition = (transitionID, task)
        state = .transitioning

        do {
            try await task.value
            if transition?.id == transitionID {
                transition = nil
            }
            _ = try await observedStatus()
        } catch {
            if transition?.id == transitionID {
                transition = nil
            }
            await refreshStatus()
            throw error
        }
    }

    private nonisolated func matchesDesiredStatus(
        _ snapshot: StatusSnapshot,
        connected: Bool
    ) -> Bool {
        snapshot.connected == connected
            && (!connected || snapshot.wired || snapshot.wifi)
    }

    private func validate(owner: TunnelTransitionOwner) throws {
        switch owner {
        case .menu:
            guard benchmarkOwner == nil else {
                throw TunnelTransitionError.lifecycleOwnedByBenchmark
            }
        case .benchmark(let owner):
            guard benchmarkOwner == owner else {
                throw TunnelTransitionError.lifecycleOwnedByBenchmark
            }
        }
    }

    private func refreshStatus() async {
        do {
            _ = try await observedStatus()
        } catch {
            state = .daemonUnavailable
            daemonAvailability = .unavailable
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
        daemonAvailability = .available
        wiredLive = snapshot.wired
        wifiLive = snapshot.wifi
        rttMs = snapshot.rttMs
        totalTx = snapshot.tx
        totalRx = snapshot.rx

        if snapshot.activePath != activePath {
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
