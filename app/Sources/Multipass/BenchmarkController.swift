import Foundation

nonisolated enum BenchmarkControllerState: Sendable, Equatable {
    case idle
    case loadingTopology
    case measuringRaw(BenchmarkTestID)
    case connecting
    case measuringTunnel(BenchmarkTestID)
    case restoring
    case completed
    case cancelled
    case failed
}

nonisolated enum BenchmarkResult: Sendable, Equatable {
    case measured(BenchmarkMeasurement)
    case failed(String)

    var measurement: BenchmarkMeasurement? {
        guard case .measured(let measurement) = self else { return nil }
        return measurement
    }

    var isFailure: Bool {
        if case .failed = self { return true }
        return false
    }
}

nonisolated struct BenchmarkRun: Sendable, Equatable {
    let topology: BenchmarkTopology
    let parameters: BenchmarkParameters
    let initiallyConnected: Bool
    var results: [BenchmarkTestID: BenchmarkResult]
    var restorationError: String?
}

nonisolated enum BenchmarkControllerError: Error, Sendable, Equatable {
    case unexpectedDaemonReply
    case missingInvocation(BenchmarkTestID)
    case noCompletedRun
}

extension BenchmarkControllerError: LocalizedError {
    nonisolated var errorDescription: String? {
        switch self {
        case .unexpectedDaemonReply:
            "The daemon returned an unexpected benchmark reply"
        case .missingInvocation:
            "The benchmark test is not part of this suite"
        case .noCompletedRun:
            "There is no completed benchmark suite"
        }
    }
}

@Observable
@MainActor
final class BenchmarkController {
    private(set) var state: BenchmarkControllerState = .idle
    private(set) var liveSamples: [BenchmarkTestID: [Double]] = [:]
    private(set) var measurements: [BenchmarkTestID: BenchmarkResult] = [:]
    private(set) var completedRun: BenchmarkRun?
    private(set) var lastError: String?

    var isRunning: Bool { suiteTask != nil }

    private let daemon: any DaemonRequesting
    private let tunnel: TunnelController
    private let runner: any BenchmarkRunning
    private let parameters: BenchmarkParameters
    private var suiteTask: Task<Void, Never>?
    private var cancellationRequested = false

    init(
        daemon: any DaemonRequesting,
        tunnel: TunnelController,
        runner: any BenchmarkRunning,
        parameters: BenchmarkParameters = .init()
    ) {
        self.daemon = daemon
        self.tunnel = tunnel
        self.runner = runner
        self.parameters = parameters
    }

    func startFullSuite() {
        guard suiteTask == nil else { return }
        cancellationRequested = false
        let owner = UUID()
        let priorMeasurements = measurements
        let priorSamples = liveSamples
        suiteTask = Task { [weak self] in
            guard let self else { return }
            await runFullSuite(
                owner: owner,
                priorMeasurements: priorMeasurements,
                priorSamples: priorSamples
            )
            suiteTask = nil
        }
    }

    func cancel() {
        guard let suiteTask else { return }
        cancellationRequested = true
        suiteTask.cancel()
    }

    func rerun(_ id: BenchmarkTestID) {
        guard suiteTask == nil, let completedRun else { return }
        cancellationRequested = false
        liveSamples[id] = []
        let owner = UUID()
        suiteTask = Task { [weak self] in
            guard let self else { return }
            await runRerun(id, run: completedRun, owner: owner)
            suiteTask = nil
        }
    }

    private func runFullSuite(
        owner: UUID,
        priorMeasurements: [BenchmarkTestID: BenchmarkResult],
        priorSamples: [BenchmarkTestID: [Double]]
    ) async {
        var initiallyConnected: Bool?
        var topology: BenchmarkTopology?
        var results: [BenchmarkTestID: BenchmarkResult] = [:]
        var terminalState: BenchmarkControllerState = .completed
        var terminalError: String?

        do {
            try await tunnel.acquireBenchmarkOwnership(owner)
            try checkCancellation()
            let initialStatus = try await tunnel.observedStatus()
            initiallyConnected = initialStatus.connected

            state = .loadingTopology
            let reply = try await daemon.request(.benchmarkTopology)
            guard case .benchmarkTopology(let loadedTopology) = reply else {
                throw BenchmarkControllerError.unexpectedDaemonReply
            }
            topology = loadedTopology
            let plan = try BenchmarkPlanner.plan(topology: loadedTopology, parameters: parameters)
            measurements = [:]
            liveSamples = [:]
            lastError = nil

            let raw = plan.invocations.filter { $0.id.route != .tunnel }
            let tunnelInvocations = plan.invocations.filter { $0.id.route == .tunnel }

            for invocation in raw {
                try checkCancellation()
                state = .measuringRaw(invocation.id)
                let result = await runMeasurement(invocation)
                results[invocation.id] = result
                measurements[invocation.id] = result
                try checkCancellation()
            }

            if !tunnelInvocations.isEmpty {
                do {
                    try checkCancellation()
                    if !initialStatus.connected {
                        state = .connecting
                    }
                    try await tunnel.setConnected(true, owner: .benchmark(owner))
                    try checkCancellation()
                    for invocation in tunnelInvocations {
                        try checkCancellation()
                        state = .measuringTunnel(invocation.id)
                        let result = await runMeasurement(invocation)
                        results[invocation.id] = result
                        measurements[invocation.id] = result
                        try checkCancellation()
                    }
                } catch is CancellationError {
                    throw CancellationError()
                } catch {
                    let message = error.localizedDescription
                    for invocation in tunnelInvocations where results[invocation.id] == nil {
                        let failure = BenchmarkResult.failed(message)
                        results[invocation.id] = failure
                        measurements[invocation.id] = failure
                    }
                }
            }
            try checkCancellation()
        } catch is CancellationError {
            terminalState = .cancelled
            await runner.cancelAll()
        } catch {
            terminalState = .failed
            terminalError = error.localizedDescription
        }

        let restorationError = await restore(
            initiallyConnected: initiallyConnected,
            owner: owner
        )
        tunnel.releaseBenchmarkOwnership(owner)

        if cancellationRequested || terminalState == .cancelled {
            terminalState = .cancelled
        }
        if terminalState == .completed {
            measurements = results
        } else {
            measurements = priorMeasurements
            liveSamples = priorSamples
        }
        if terminalState == .completed, let topology, let initiallyConnected {
            completedRun = BenchmarkRun(
                topology: topology,
                parameters: parameters,
                initiallyConnected: initiallyConnected,
                results: results,
                restorationError: restorationError
            )
        }
        lastError = terminalError ?? (terminalState == .cancelled ? restorationError : nil)
        state = terminalState
    }

    private func runRerun(_ id: BenchmarkTestID, run: BenchmarkRun, owner: UUID) async {
        var initiallyConnected: Bool?
        var measurement: BenchmarkMeasurement?
        var terminalState: BenchmarkControllerState = .completed
        var terminalError: String?

        do {
            try await tunnel.acquireBenchmarkOwnership(owner)
            try checkCancellation()
            let plan = try BenchmarkPlanner.plan(topology: run.topology, parameters: run.parameters)
            guard let invocation = plan.invocations.first(where: { $0.id == id }) else {
                throw BenchmarkControllerError.missingInvocation(id)
            }
            let initialStatus = try await tunnel.observedStatus()
            initiallyConnected = initialStatus.connected

            if invocation.id.route == .tunnel {
                if !initialStatus.connected {
                    state = .connecting
                }
                try await tunnel.setConnected(true, owner: .benchmark(owner))
                try checkCancellation()
                state = .measuringTunnel(id)
            } else {
                state = .measuringRaw(id)
            }
            try checkCancellation()
            measurement = try await runner.run(invocation: invocation) { [weak self] sample in
                await self?.record(sample: sample, for: id)
            }
            try checkCancellation()
        } catch is CancellationError {
            terminalState = .cancelled
            await runner.cancelAll()
        } catch {
            terminalState = .failed
            terminalError = error.localizedDescription
        }

        let restorationError = await restore(
            initiallyConnected: initiallyConnected,
            owner: owner
        )
        tunnel.releaseBenchmarkOwnership(owner)

        if cancellationRequested || terminalState == .cancelled {
            terminalState = .cancelled
        }
        if terminalState == .completed, restorationError == nil, let measurement {
            var replacement = run
            replacement.results[id] = .measured(measurement)
            completedRun = replacement
            measurements = replacement.results
        } else if restorationError != nil, terminalState == .completed {
            terminalState = .failed
        }
        lastError = terminalError ?? restorationError
        state = terminalState
    }

    /// Restoration deliberately runs in a fresh unstructured task. Cancelling
    /// the suite is latched in `cancellationRequested` but cannot cancel the
    /// cleanup transition; the suite awaits cleanup before publishing state.
    private func restore(
        initiallyConnected: Bool?,
        owner: UUID
    ) async -> String? {
        guard let initiallyConnected else { return nil }
        state = .restoring
        let tunnel = self.tunnel
        return await Task { @MainActor in
            do {
                try await tunnel.setConnected(initiallyConnected, owner: .benchmark(owner))
                return nil
            } catch {
                return "Failed to restore the initial tunnel state: \(error.localizedDescription)"
            }
        }.value
    }

    private func checkCancellation() throws {
        if cancellationRequested || Task.isCancelled {
            throw CancellationError()
        }
    }

    private func runMeasurement(_ invocation: BenchmarkInvocation) async -> BenchmarkResult {
        do {
            let id = invocation.id
            let measurement = try await runner.run(invocation: invocation) { [weak self] sample in
                await self?.record(sample: sample, for: id)
            }
            return .measured(measurement)
        } catch {
            if cancellationRequested || Task.isCancelled {
                return .failed(CancellationError().localizedDescription)
            }
            return .failed(error.localizedDescription)
        }
    }

    private func record(sample: Double, for id: BenchmarkTestID) {
        liveSamples[id, default: []].append(sample)
    }
}
