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

nonisolated enum BenchmarkResult: Codable, Sendable, Equatable {
    case measured(BenchmarkMeasurement)
    case skipped(String)
    case failed(String)

    var measurement: BenchmarkMeasurement? {
        guard case .measured(let measurement) = self else { return nil }
        return measurement
    }

    var isSkipped: Bool {
        guard case .skipped = self else { return false }
        return true
    }

    var isFailure: Bool {
        guard case .failed = self else { return false }
        return true
    }
}

nonisolated extension BenchmarkRun {
    var hasErrors: Bool {
        restorationError != nil || results.values.contains(where: \.isFailure)
    }
}

nonisolated struct BenchmarkRunIdentities: Codable, Sendable, Equatable {
    let appBuild: String
    let clientBuild: String
    let serverBuild: String
    let iperfVersion: String
}

nonisolated struct BenchmarkRun: Codable, Sendable, Equatable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let id: UUID
    let startedAt: Date
    let completedAt: Date
    var userLabel: String?
    let identities: BenchmarkRunIdentities
    let topology: BenchmarkTopology
    let parameters: BenchmarkParameters
    let initiallyConnected: Bool
    var results: [BenchmarkTestID: BenchmarkResult]
    var restorationError: String?

    init(
        schemaVersion: Int = BenchmarkRun.currentSchemaVersion,
        id: UUID = UUID(),
        startedAt: Date = Date(),
        completedAt: Date = Date(),
        userLabel: String? = nil,
        identities: BenchmarkRunIdentities = .init(
            appBuild: "unknown",
            clientBuild: "unknown",
            serverBuild: "unknown",
            iperfVersion: "unknown"
        ),
        topology: BenchmarkTopology,
        parameters: BenchmarkParameters,
        initiallyConnected: Bool,
        results: [BenchmarkTestID: BenchmarkResult],
        restorationError: String?
    ) {
        self.schemaVersion = schemaVersion
        self.id = id
        self.startedAt = startedAt
        self.completedAt = completedAt
        self.userLabel = userLabel
        self.identities = identities
        self.topology = topology
        self.parameters = parameters
        self.initiallyConnected = initiallyConnected
        self.results = results
        self.restorationError = restorationError
    }
}

nonisolated enum BenchmarkControllerError: Error, Sendable, Equatable {
    case unexpectedDaemonReply
    case refreshedTopologyChanged
    case refreshedServerIdentityUnavailable
    case missingInvocation(BenchmarkTestID)
    case noCompletedRun
}

extension BenchmarkControllerError: LocalizedError {
    nonisolated var errorDescription: String? {
        switch self {
        case .unexpectedDaemonReply:
            "The daemon returned an unexpected benchmark reply"
        case .refreshedTopologyChanged:
            "The benchmark topology changed after the tunnel connected"
        case .refreshedServerIdentityUnavailable:
            "The connected tunnel did not report an authenticated server identity"
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
    private(set) var history: [BenchmarkRun] = []
    private(set) var historyLoadErrors: [BenchmarkStoreLoadError] = []
    private(set) var selectedRunID: UUID?
    private(set) var baselineRunID: UUID?
    private(set) var loadError: String?
    private(set) var saveError: String?
    private(set) var lastError: String?
    private(set) var plannedMeasurementIDs: [BenchmarkTestID] = []
    private(set) var unsavedRun: BenchmarkRun?

    var isRunning: Bool { suiteTask != nil }
    var canStartFullSuite: Bool { runner != nil && iperfVersion != nil && !isRunning }
    var prerequisiteError: String? {
        guard runner != nil else {
            return "iperf3 is required. Install it with Homebrew: brew install iperf3."
        }
        return iperfVersion == nil ? "Checking iperf3 version…" : nil
    }
    var daemonAvailability: DaemonAvailability { tunnel.daemonAvailability }
    var daemonAvailable: Bool { daemonAvailability == .available }
    var canRunFullSuite: Bool { canStartFullSuite && daemonAvailable && unsavedRun == nil }
    var runDisabledReason: String? {
        if unsavedRun != nil {
            return "Retry Save before starting another benchmark so this unsaved result is not lost."
        }
        if let prerequisiteError { return prerequisiteError }
        switch daemonAvailability {
        case .unknown:
            return "Checking multipassd availability…"
        case .unavailable:
            return "multipassd is unavailable. Saved benchmark history remains available."
        case .available:
            return nil
        }
    }
    var canRetrySave: Bool { unsavedRun != nil }
    var activeTopology: BenchmarkTopology? { runningTopology ?? selectedRun?.topology ?? completedRun?.topology }
    var completedMeasurementIDs: [BenchmarkTestID] {
        plannedMeasurementIDs.filter { measurements[$0] != nil }
    }
    var currentPhaseTitle: String {
        switch state {
        case .idle: "Ready"
        case .loadingTopology: "Loading topology"
        case .measuringRaw: "Measuring physical capacity"
        case .connecting: "Connecting tunnel"
        case .measuringTunnel: "Measuring tunnel throughput"
        case .restoring: "Restoring initial tunnel state"
        case .completed: "Complete"
        case .cancelled: "Cancelled"
        case .failed: "Failed"
        }
    }
    var selectedRun: BenchmarkRun? {
        guard let selectedRunID else { return nil }
        if unsavedRun?.id == selectedRunID { return unsavedRun }
        return history.first { $0.id == selectedRunID }
    }
    var baselineRun: BenchmarkRun? {
        guard let baselineRunID else { return nil }
        return history.first { $0.id == baselineRunID }
    }
    var currentMeasurementID: BenchmarkTestID? {
        switch state {
        case .measuringRaw(let id), .measuringTunnel(let id): id
        default: nil
        }
    }
    var currentLiveSamples: [Double] {
        guard let currentMeasurementID else { return [] }
        return liveSamples[currentMeasurementID] ?? []
    }
    var completedMeasurementCount: Int {
        plannedMeasurementIDs.filter { measurements[$0] != nil }.count
    }
    var totalMeasurementCount: Int { plannedMeasurementIDs.count }
    var remainingMeasurementIDs: [BenchmarkTestID] {
        guard let currentMeasurementID,
              let currentIndex = plannedMeasurementIDs.firstIndex(of: currentMeasurementID) else {
            return plannedMeasurementIDs.filter { measurements[$0] == nil }
        }
        return Array(plannedMeasurementIDs.suffix(from: plannedMeasurementIDs.index(after: currentIndex)))
            .filter { measurements[$0] == nil }
    }

    private let daemon: any DaemonRequesting
    private let tunnel: TunnelController
    private let runner: (any BenchmarkRunning)?
    private let store: BenchmarkStore
    private let parameters: BenchmarkParameters
    private let appBuild: String
    private var suiteTask: Task<Void, Never>?
    private var iperfVersion: String?
    private var cancellationRequested = false
    private var activeRunStartedAt: Date?
    private var runningTopology: BenchmarkTopology?
    private static let maximumLiveSampleCount = 10

    init(
        daemon: any DaemonRequesting,
        tunnel: TunnelController,
        runner: (any BenchmarkRunning)?,
        store: BenchmarkStore = BenchmarkStore(),
        parameters: BenchmarkParameters = .init(),
        appBuild: String = "unknown",
        iperfVersion: String? = "unknown"
    ) {
        self.daemon = daemon
        self.tunnel = tunnel
        self.runner = runner
        self.store = store
        self.parameters = parameters
        self.appBuild = appBuild
        self.iperfVersion = iperfVersion
    }

    func publishIperfVersion(_ version: String) {
        guard !isRunning else { return }
        iperfVersion = version
    }

    func loadHistory() async {
        do {
            async let index = store.loadIndex()
            async let loaded = store.loadRuns()
            let (loadedIndex, loadedRuns) = try await (index, loaded)
            history = loadedRuns.runs
            historyLoadErrors = loadedRuns.errors
            baselineRunID = loadedIndex.selectedBaselineID.flatMap { id in
                history.contains(where: { $0.id == id }) ? id : nil
            }

            guard !isRunning else {
                loadError = nil
                return
            }
            if let unsavedRun {
                if selectedRunID == nil || selectedRunID == unsavedRun.id {
                    selectedRunID = unsavedRun.id
                    completedRun = unsavedRun
                    measurements = unsavedRun.results
                }
            } else if let selectedRunID, history.contains(where: { $0.id == selectedRunID }) {
                completedRun = selectedRun
                measurements = selectedRun?.results ?? [:]
            } else {
                selectedRunID = history.first?.id
                completedRun = selectedRun
                measurements = selectedRun?.results ?? [:]
            }
            loadError = nil
        } catch {
            loadError = "Failed to load benchmark history: \(error.localizedDescription)"
        }
    }

    func retrySave() async {
        guard let run = unsavedRun else { return }
        do {
            try await store.saveRun(run)
            insertOrReplaceHistory(run)
            unsavedRun = nil
            completedRun = selectedRunID == run.id ? run : selectedRun
            saveError = nil
        } catch {
            saveError = "Failed to save benchmark: \(error.localizedDescription)"
        }
    }

    func selectRun(_ id: UUID?) {
        guard !isRunning else { return }
        guard id == nil || id == unsavedRun?.id || history.contains(where: { $0.id == id }) else { return }
        selectedRunID = id
        completedRun = selectedRun
        measurements = selectedRun?.results ?? [:]
        liveSamples = [:]
        state = selectedRun == nil ? .idle : .completed
    }

    func renameRun(_ id: UUID, userLabel: String?) async {
        do {
            try await store.renameRun(id, userLabel: userLabel)
            let normalized = userLabel?.trimmingCharacters(in: .whitespacesAndNewlines)
            updateRun(id) { $0.userLabel = normalized?.isEmpty == false ? normalized : nil }
            saveError = nil
        } catch {
            saveError = "Failed to save benchmark label: \(error.localizedDescription)"
        }
    }

    func setBaseline(_ id: UUID?) async {
        do {
            try await store.selectBaseline(id)
            baselineRunID = id
            saveError = nil
        } catch {
            saveError = "Failed to save benchmark baseline: \(error.localizedDescription)"
        }
    }

    func reportMarkdown() -> String? {
        guard let selectedRun else { return nil }
        return BenchmarkReport.markdown(current: selectedRun, baseline: baselineRun)
    }
    func startFullSuite() {
        guard canRunFullSuite else { return }
        cancellationRequested = false
        activeRunStartedAt = Date()
        saveError = nil
        plannedMeasurementIDs = []
        let owner = UUID()
        let priorMeasurements = measurements
        runningTopology = nil
        let priorSamples = liveSamples
        let suiteIperfVersion = iperfVersion ?? "unknown"
        suiteTask = Task { [weak self] in
            guard let self else { return }
            await runFullSuite(
                owner: owner,
                priorMeasurements: priorMeasurements,
                priorSamples: priorSamples,
                iperfVersion: suiteIperfVersion
            )
            suiteTask = nil
        }
    }

    func cancel() {
        guard let suiteTask else { return }
        cancellationRequested = true
        suiteTask.cancel()
    }

    func canRerun(_ id: BenchmarkTestID) -> Bool {
        rerunDisabledReason(id) == nil
    }

    func rerunDisabledReason(_ id: BenchmarkTestID) -> String? {
        guard !isRunning else { return "Wait for the current benchmark operation to finish." }
        guard runner != nil else { return prerequisiteError }
        guard daemonAvailable else { return "multipassd is unavailable." }
        guard let selectedRun else { return "Select a completed benchmark first." }
        if selectedRun.results[id]?.isSkipped == true {
            return "This measurement was skipped because the captured suite has no tunnel \(id.addressFamily == .ipv4 ? "IPv4" : "IPv6") target."
        }
        guard let plan = try? BenchmarkPlanner.plan(topology: selectedRun.topology, parameters: selectedRun.parameters),
              plan.invocations.contains(where: { $0.id == id }) else {
            return "This measurement is not part of the captured benchmark suite."
        }
        return nil
    }

    func rerun(_ id: BenchmarkTestID) {
        guard canRerun(id), let selectedRun else { return }
        completedRun = selectedRun
        cancellationRequested = false
        saveError = nil
        liveSamples[id] = []
        plannedMeasurementIDs = [id]
        let owner = UUID()
        suiteTask = Task { [weak self] in
            guard let self else { return }
            await runRerun(id, run: selectedRun, owner: owner)
            suiteTask = nil
        }
    }

    func shutdown() async {
        cancellationRequested = true
        suiteTask?.cancel()
        if let runner { await runner.cancelAll() }
        await suiteTask?.value
        if let runner { await runner.cancelAll() }
    }

    private func runFullSuite(
        owner: UUID,
        priorMeasurements: [BenchmarkTestID: BenchmarkResult],
        priorSamples: [BenchmarkTestID: [Double]],
        iperfVersion: String
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
            plannedMeasurementIDs = plan.invocations.map(\.id)
            measurements = [:]
            liveSamples = [:]
            lastError = nil
            runningTopology = loadedTopology

            let raw = plan.invocations.filter { $0.id.route != .tunnel }
            let tunnelInvocations = plan.invocations.filter { $0.id.route == .tunnel }
            addUnavailableTunnelResults(topology: loadedTopology, to: &results)
            measurements = results

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
                    if !initialStatus.connected {
                        topology = try await refreshedTopology(from: loadedTopology)
                        runningTopology = topology
                    }
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
                } catch let error as BenchmarkControllerError where error == .refreshedTopologyChanged
                    || error == .refreshedServerIdentityUnavailable
                    || error == .unexpectedDaemonReply {
                    throw error
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
            if let runner { await runner.cancelAll() }
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
            let run = BenchmarkRun(
                startedAt: activeRunStartedAt ?? Date(),
                completedAt: Date(),
                identities: BenchmarkRunIdentities(
                    appBuild: appBuild,
                    clientBuild: topology.daemonVersion,
                    serverBuild: topology.serverVersion,
                    iperfVersion: iperfVersion
                ),
                topology: topology,
                parameters: parameters,
                initiallyConnected: initiallyConnected,
                results: results,
                restorationError: restorationError
            )
            completedRun = run
            selectedRunID = run.id
            do {
                try await store.saveRun(run)
                insertOrReplaceHistory(run)
                unsavedRun = nil
                saveError = nil
            } catch {
                unsavedRun = run
                saveError = "Failed to save benchmark: \(error.localizedDescription)"
            }
        }
        activeRunStartedAt = nil
        runningTopology = nil
        lastError = terminalError ?? (terminalState == .cancelled ? restorationError : nil)
        state = terminalState
    }

    private func runRerun(_ id: BenchmarkTestID, run: BenchmarkRun, owner: UUID) async {
        var initiallyConnected: Bool?
        var measurement: BenchmarkMeasurement?
        var terminalState: BenchmarkControllerState = .completed
        var terminalError: String?

        do {
            guard let runner else { return }
            try await tunnel.acquireBenchmarkOwnership(owner)
            try checkCancellation()
            runningTopology = run.topology
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
            if let runner { await runner.cancelAll() }
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
            do {
                try await store.saveRun(replacement)
                completedRun = replacement
                selectedRunID = replacement.id
                measurements = replacement.results
                insertOrReplaceHistory(replacement)
                if unsavedRun?.id == replacement.id { unsavedRun = nil }
                saveError = nil
            } catch {
                saveError = "Failed to save benchmark: \(error.localizedDescription)"
            }
            state = terminalState
        } else if restorationError != nil, terminalState == .completed {
            terminalState = .failed
        }
        lastError = terminalError ?? restorationError
        runningTopology = nil
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
    private func refreshedTopology(
        from captured: BenchmarkTopology
    ) async throws -> BenchmarkTopology {
        let reply = try await daemon.request(.benchmarkTopology)
        guard case .benchmarkTopology(let refreshed) = reply else {
            throw BenchmarkControllerError.unexpectedDaemonReply
        }
        guard Self.matchesPlanningTopology(refreshed, captured) else {
            throw BenchmarkControllerError.refreshedTopologyChanged
        }
        let serverVersion = refreshed.serverVersion.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !serverVersion.isEmpty, serverVersion.lowercased() != "unknown" else {
            throw BenchmarkControllerError.refreshedServerIdentityUnavailable
        }
        var topology = captured
        topology.serverVersion = refreshed.serverVersion
        return topology
    }

    private nonisolated static func matchesPlanningTopology(
        _ refreshed: BenchmarkTopology,
        _ captured: BenchmarkTopology
    ) -> Bool {
        refreshed.protocolVersion == captured.protocolVersion
            && refreshed.daemonVersion == captured.daemonVersion
            && refreshed.underlayTarget == captured.underlayTarget
            && refreshed.tunnelIPv4Target == captured.tunnelIPv4Target
            && refreshed.tunnelIPv6Target == captured.tunnelIPv6Target
            && refreshed.listenerBasePort == captured.listenerBasePort
            && refreshed.listenerCount == captured.listenerCount
            && refreshed.paths == captured.paths
    }

    private func runMeasurement(_ invocation: BenchmarkInvocation) async -> BenchmarkResult {
        guard let runner else {
            return .failed(prerequisiteError ?? "iperf3 is unavailable")
        }
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

    private func addUnavailableTunnelResults(
        topology: BenchmarkTopology,
        to results: inout [BenchmarkTestID: BenchmarkResult]
    ) {
        for (family, target) in [
            (BenchmarkAddressFamily.ipv4, topology.tunnelIPv4Target),
            (.ipv6, topology.tunnelIPv6Target),
        ] where target == nil {
            for direction in [BenchmarkDirection.upload, .download] {
                let id = BenchmarkTestID(
                    route: .tunnel,
                    direction: direction,
                    addressFamily: family
                )
                results[id] = .skipped(
                    "tunnel \(family == .ipv4 ? "IPv4" : "IPv6") target unavailable"
                )
            }
        }
    }

    private func record(sample: Double, for id: BenchmarkTestID) {
        var samples = liveSamples[id] ?? []
        samples.append(sample)
        if samples.count > Self.maximumLiveSampleCount {
            samples.removeFirst(samples.count - Self.maximumLiveSampleCount)
        }
        liveSamples[id] = samples
    }

    private func insertOrReplaceHistory(_ run: BenchmarkRun) {
        history.removeAll { $0.id == run.id }
        history.append(run)
        history.sort {
            if $0.startedAt != $1.startedAt { return $0.startedAt > $1.startedAt }
            return $0.id.uuidString > $1.id.uuidString
        }
    }

    private func updateRun(_ id: UUID, mutate: (inout BenchmarkRun) -> Void) {
        if let index = history.firstIndex(where: { $0.id == id }) {
            mutate(&history[index])
        }
        if completedRun?.id == id {
            mutate(&completedRun!)
        }
        if unsavedRun?.id == id {
            mutate(&unsavedRun!)
        }
    }
}
