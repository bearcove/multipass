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
    /// No authenticated uplink is ready. `enabled` distinguishes persistent
    /// waiting intent from a disabled VPN.
    case disconnected
    /// The user asked for a desired-state change and it has not converged yet.
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
    case transitionTimedOut(desiredConnected: Bool)
}

extension TunnelTransitionError: LocalizedError {
    nonisolated var errorDescription: String? {
        switch self {
        case .lifecycleOwnedByBenchmark:
            "A benchmark is controlling the tunnel"
        case .unexpectedReply:
            "The daemon returned an unexpected tunnel reply"
        case .transitionTimedOut(let desiredConnected):
            "Timed out waiting for the tunnel to become \(desiredConnected ? "enabled" : "disabled")"
        }
    }
}

/// Immutable MainActor projection of one immutable daemon uplink snapshot.
struct UplinkStatus: Identifiable, Equatable {
    let snapshot: UplinkSnapshot
    let txRate: Double
    let rxRate: Double

    var id: String { snapshot.id }
    var displayName: String { snapshot.displayName }
    var interface: String { snapshot.interface }
    var configuredEnabled: Bool { snapshot.configuredEnabled }
    var state: String { snapshot.state }
    var ready: Bool { snapshot.ready }
    var sourceAddress: String? { snapshot.sourceAddress }
    var gatewayEndpoint: String? { snapshot.gatewayEndpoint }
    var rttMs: Double? { snapshot.rttMs }
    var tx: UInt64 { snapshot.tx }
    var rx: UInt64 { snapshot.rx }
    var lastError: String? { snapshot.lastError }
}

/// Observable bridge between `multipassd` and the menubar UI.
///
/// Polls `{"cmd":"status"}` once per second, serializes owner-aware desired-state
/// transitions through daemon-observed convergence, derives aggregate and per-ID
/// throughput rates from cumulative counters, and raises a stable-ID failover flash.
@Observable
@MainActor
final class TunnelController {
    private(set) var state: TunnelState = .disconnected
    private(set) var daemonAvailability: DaemonAvailability = .unknown
    private(set) var enabled = false
    private(set) var uplinks: [UplinkStatus] = []
    private(set) var activeUplinkID: String?
    private(set) var totalTx: UInt64 = 0
    private(set) var totalRx: UInt64 = 0
    /// Bytes/second, derived from consecutive status polls.
    private(set) var txRate: Double = 0
    private(set) var rxRate: Double = 0
    /// Non-nil while the failover flash is showing; carries the stable ID we
    /// failed over to. The view resolves the current display metadata by ID.
    private(set) var failoverToID: String?
    private(set) var lastError: String?
    private(set) var benchmarkOwner: UUID?

    var activeUplink: UplinkStatus? {
        guard let activeUplinkID else { return nil }
        return uplinks.first { $0.id == activeUplinkID }
    }

    var failoverTo: UplinkStatus? {
        guard let failoverToID else { return nil }
        return uplinks.first { $0.id == failoverToID }
    }

    var rttMs: Double? { activeUplink?.rttMs }
    var benchmarkOwnsLifecycle: Bool { benchmarkOwner != nil }
    var canToggle: Bool {
        benchmarkOwner == nil && daemonAvailability == .available && state != .transitioning
    }

    private struct CounterSample {
        let tx: UInt64
        let rx: UInt64
    }

    private let client: any DaemonRequesting
    private var pollTask: Task<Void, Never>?
    private var transition: (id: UUID, task: Task<StatusSnapshot, Error>)?
    private var previousTotalSample: (counter: CounterSample, at: ContinuousClock.Instant)?
    private var previousUplinkSamples: [String: CounterSample] = [:]

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
        let desiredEnabled = !enabled
        Task { [weak self] in
            guard let self else { return }
            do {
                try await setConnected(desiredEnabled, owner: .menu)
            } catch {
                lastError = error.localizedDescription
            }
        }
    }

    /// Claims lifecycle ownership after every already-admitted transition has
    /// completed, preserving the benchmark controller's existing serialization.
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

    /// Returns the daemon's observed status. Orchestration consumes this
    /// immutable Sendable snapshot while the controller publishes MainActor UI state.
    func observedStatus() async throws -> StatusSnapshot {
        let reply = try await client.request(.status)
        guard case .status(let snapshot) = reply else {
            throw TunnelTransitionError.unexpectedReply
        }
        applyObservedStatus(snapshot)
        return snapshot
    }

    func applyObservedStatus(_ snapshot: StatusSnapshot) {
        apply(snapshot)
        lastError = nil
        daemonAvailability = .available
    }

    /// Idempotently requests and waits for persistent enabled intent. The
    /// daemon may remain enabled but disconnected while every uplink is waiting.
    func setConnected(_ connected: Bool, owner: TunnelTransitionOwner) async throws {
        try validate(owner: owner)
        let preceding = transition?.task
        let client = self.client
        let transitionID = UUID()
        let task = Task<StatusSnapshot, Error> { @MainActor [weak self] in
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
            applyObservedStatus(before)
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
                applyObservedStatus(snapshot)
            }
            return observed
        }
        transition = (transitionID, task)
        state = .transitioning

        do {
            let observed = try await task.value
            if transition?.id == transitionID {
                transition = nil
            }
            applyObservedStatus(observed)
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
        snapshot.enabled == connected
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
            enabled = false
            uplinks = []
            activeUplinkID = nil
            failoverToID = nil
            txRate = 0
            rxRate = 0
            previousTotalSample = nil
            previousUplinkSamples = [:]
            lastError = error.localizedDescription
        }
    }

    private func apply(_ snapshot: StatusSnapshot) {
        let now = ContinuousClock.now
        let totalSample = CounterSample(tx: snapshot.tx, rx: snapshot.rx)
        let seconds: Double? = previousTotalSample.map { previous in
            let elapsed = now - previous.at
            return Double(elapsed.components.seconds)
                + Double(elapsed.components.attoseconds) / 1e18
        }

        if let previous = previousTotalSample, let seconds, seconds > 0 {
            txRate = rate(current: totalSample.tx, previous: previous.counter.tx, seconds: seconds)
            rxRate = rate(current: totalSample.rx, previous: previous.counter.rx, seconds: seconds)
        } else {
            txRate = 0
            rxRate = 0
        }

        var currentUplinkSamples: [String: CounterSample] = [:]
        currentUplinkSamples.reserveCapacity(snapshot.uplinks.count)
        uplinks = snapshot.uplinks.map { uplink in
            let current = CounterSample(tx: uplink.tx, rx: uplink.rx)
            currentUplinkSamples[uplink.id] = current
            guard let previous = previousUplinkSamples[uplink.id], let seconds, seconds > 0 else {
                return UplinkStatus(snapshot: uplink, txRate: 0, rxRate: 0)
            }
            return UplinkStatus(
                snapshot: uplink,
                txRate: rate(current: current.tx, previous: previous.tx, seconds: seconds),
                rxRate: rate(current: current.rx, previous: previous.rx, seconds: seconds)
            )
        }
        previousTotalSample = (totalSample, now)
        previousUplinkSamples = currentUplinkSamples

        let wasConnected = state.isConnected
        enabled = snapshot.enabled
        state = snapshot.connected ? .connected : .disconnected
        daemonAvailability = .available
        totalTx = snapshot.tx
        totalRx = snapshot.rx

        let previousActiveUplinkID = activeUplinkID
        if snapshot.activeUplinkID != previousActiveUplinkID {
            if previousActiveUplinkID != nil, wasConnected, snapshot.connected,
               let newID = snapshot.activeUplinkID {
                flashFailover(to: newID)
            }
            activeUplinkID = snapshot.activeUplinkID
        }
    }

    private func rate(current: UInt64, previous: UInt64, seconds: Double) -> Double {
        guard current >= previous else { return 0 }
        return Double(current - previous) / seconds
    }

    private func flashFailover(to uplinkID: String) {
        failoverToID = uplinkID
        Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(1200))
            guard let self, failoverToID == uplinkID else { return }
            failoverToID = nil
        }
    }
}
