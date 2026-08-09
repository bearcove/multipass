import Foundation
import Testing
@testable import Multipass

@Suite("Benchmark lifecycle", .serialized)
@MainActor
struct BenchmarkControllerTests {
    @Test("initially disconnected runs raw, connects, runs tunnel, then disconnects")
    func disconnectedFullSuiteRestoresDisconnected() async throws {
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .completed)
        #expect(controller.completedRun?.results.count == allInvocations.count)
        #expect(await runner.invocationIDs == allInvocations.map(\.id))
        #expect(await daemon.events == [
            .request(.status),
            .request(.benchmarkTopology),
            .run(rawInvocations[0].id),
            .run(rawInvocations[1].id),
            .run(rawInvocations[2].id),
            .run(rawInvocations[3].id),
            .request(.status),
            .request(.connect),
            .request(.status),
            .request(.status),
            .run(tunnelInvocations[0].id),
            .run(tunnelInvocations[1].id),
            .request(.status),
            .request(.disconnect),
            .request(.status),
            .request(.status),
        ])
        #expect(await daemon.connected == false)
    }

    @Test("tunnel transitions wait through stale status until daemon convergence")
    func transitionWaitsForObservedConvergence() async throws {
        let daemon = FakeDaemon(connected: false, staleStatusRepliesAfterCommand: 1)
        let tunnel = TunnelController(client: daemon)
        let owner = UUID()
        try await tunnel.acquireBenchmarkOwnership(owner)

        try await tunnel.setConnected(true, owner: .benchmark(owner))
        try await tunnel.setConnected(false, owner: .benchmark(owner))

        #expect(await daemon.requests == [
            .status,
            .connect,
            .status,
            .status,
            .status,
            .status,
            .disconnect,
            .status,
            .status,
            .status,
        ])
        #expect(tunnel.state == .disconnected)
    }

    @Test("benchmark ownership waits for an admitted menu transition before raw work")
    func benchmarkDoesNotRaceAdmittedMenuTransition() async throws {
        let daemon = FakeDaemon(
            connected: false,
            suspendOnRequest: .connect,
            rejectConcurrentRequestsWhileSuspended: true
        )
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        tunnel.toggle()
        try await waitUntil { await daemon.waitingRequest == .connect }
        controller.startFullSuite()
        await Task.yield()
        #expect(await runner.invocationIDs.isEmpty)

        await daemon.resumeSuspendedRequest()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .completed)
        #expect(await runner.invocationIDs == allInvocations.map(\.id))
    }

    @Test("benchmark ownership drains menu transitions admitted while acquisition waits")
    func benchmarkDrainsSecondAdmittedMenuTransition() async throws {
        let daemon = FakeDaemon(connected: false, suspendOnRequest: .connect)
        let tunnel = TunnelController(client: daemon)
        let owner = UUID()

        let first = Task {
            try await tunnel.setConnected(true, owner: .menu)
        }
        try await waitUntil { await daemon.waitingRequest == .connect }

        let acquisition = Task {
            try await tunnel.acquireBenchmarkOwnership(owner)
        }
        await Task.yield()
        await daemon.suspendNextRequest(.disconnect)
        let second = Task {
            try await tunnel.setConnected(false, owner: .menu)
        }
        await Task.yield()

        await daemon.resumeSuspendedRequest()
        try await waitUntil { await daemon.waitingRequest == .disconnect }
        #expect(tunnel.benchmarkOwnsLifecycle == false)

        await daemon.resumeSuspendedRequest()
        try await first.value
        try await second.value
        try await acquisition.value

        #expect(tunnel.benchmarkOwnsLifecycle)
        #expect(tunnel.state == .disconnected)
    }

    @Test("initially connected never disconnects after the suite")
    func connectedFullSuiteStaysConnected() async throws {
        let daemon = FakeDaemon(connected: true)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .completed)
        #expect(await daemon.connected)
        #expect(await daemon.requests.filter { $0 == .disconnect }.isEmpty)
        #expect(await runner.invocationIDs == allInvocations.map(\.id))
    }

    @Test("a raw measurement failure does not stop independent tests")
    func rawFailureContinuesIndependentTests() async throws {
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(
            failures: [rawInvocations[0].id: TestFailure.measurement],
            recorder: daemon
        )
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .completed)
        #expect(controller.completedRun?.results[rawInvocations[0].id]?.isFailure == true)
        #expect(controller.completedRun?.results[rawInvocations[1].id]?.measurement != nil)
        #expect(controller.completedRun?.results[tunnelInvocations[0].id]?.measurement != nil)
        #expect(await runner.invocationIDs == allInvocations.map(\.id))
        #expect(await daemon.connected == false)
    }

    @Test("connect failure fails tunnel tests as a group and restores")
    func connectFailureFailsTunnelGroupAndRestores() async throws {
        let daemon = FakeDaemon(connected: false, connectError: TestFailure.connect)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .completed)
        #expect(controller.completedRun?.results[tunnelInvocations[0].id]?.isFailure == true)
        #expect(controller.completedRun?.results[tunnelInvocations[1].id]?.isFailure == true)
        #expect(await runner.invocationIDs == rawInvocations.map(\.id))
        #expect(await daemon.connected == false)
        #expect(await daemon.requests.filter { $0 == .disconnect }.isEmpty)
        #expect(await daemon.requests.last == .status)
    }

    @Test("cancellation reaps the runner and restores the initial state")
    func cancellationReapsRunnerAndRestores() async throws {
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(
            suspendOn: tunnelInvocations[0].id,
            recorder: daemon
        )
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { await runner.suspended }
        controller.cancel()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .cancelled)
        #expect(await runner.cancelAllCount == 1)
        #expect(await runner.suspended == false)
        #expect(await daemon.connected == false)
        #expect(await daemon.requests.contains(.disconnect))
    }

    @Test("cancellation of the final measurement still marks the suite cancelled")
    func finalMeasurementCancellationIsCancelled() async throws {
        let daemon = FakeDaemon(connected: false)
        let finalInvocation = try #require(tunnelInvocations.last)
        let runner = FakeBenchmarkRunner(suspendOn: finalInvocation.id, recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { await runner.suspended }
        controller.cancel()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .cancelled)
        #expect(await runner.cancelAllCount == 1)
        #expect(await daemon.connected == false)
    }

    @Test("cancellation during connect is latched while restoration completes")
    func cancellationDuringConnectRestoresAndStaysCancelled() async throws {
        let daemon = FakeDaemon(connected: false, suspendOnRequest: .connect)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { await daemon.waitingRequest == .connect }
        controller.cancel()
        await daemon.resumeSuspendedRequest()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .cancelled)
        #expect(controller.completedRun == nil)
        #expect(await daemon.connected == false)
    }

    @Test("cancellation during restoration is latched until restoration completes")
    func cancellationDuringRestorationCompletesThenCancels() async throws {
        let daemon = FakeDaemon(connected: false, suspendOnRequest: .disconnect)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { await daemon.waitingRequest == .disconnect }
        controller.cancel()
        await daemon.resumeSuspendedRequest()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .cancelled)
        #expect(controller.completedRun == nil)
        #expect(await daemon.connected == false)
    }

    @Test("restoration failure after cancellation remains cancelled with a distinct error")
    func cancelledRestorationFailureIsDistinct() async throws {
        let daemon = FakeDaemon(
            connected: false,
            disconnectError: DaemonError.unavailable,
            suspendOnRequest: .disconnect
        )
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { await daemon.waitingRequest == .disconnect }
        controller.cancel()
        await daemon.resumeSuspendedRequest()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .cancelled)
        #expect(controller.completedRun == nil)
        #expect(controller.lastError?.contains("restore") == true)
    }

    @Test("a cancelled second suite preserves the prior completed run")
    func cancelledSecondSuitePreservesCompletedRun() async throws {
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }
        let prior = try #require(controller.completedRun)

        await runner.setResponse(.suspendThenSucceed(measurement(for: rawInvocations[0].id)), for: rawInvocations[0].id)
        controller.startFullSuite()
        try await waitUntil { await runner.suspended }
        controller.cancel()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .cancelled)
        #expect(controller.completedRun == prior)
    }

    @Test("a top-level failed second suite preserves the prior completed run")
    func failedSecondSuitePreservesCompletedRun() async throws {
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }
        let prior = try #require(controller.completedRun)

        await daemon.setTopology(BenchmarkTopology(
            protocolVersion: 1,
            serverVersion: "invalid",
            underlayTarget: "not-an-address",
            tunnelIPv4Target: nil,
            tunnelIPv6Target: nil,
            listenerBasePort: 5210,
            listenerCount: 16,
            paths: testTopology.paths
        ))
        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .failed)
        #expect(controller.completedRun == prior)
    }

    @Test("daemon loss during restoration is a distinct run-level error")
    func restorationFailureIsDistinct() async throws {
        let daemon = FakeDaemon(connected: false, disconnectError: DaemonError.unavailable)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .completed)
        #expect(controller.completedRun?.results.values.allSatisfy { $0.measurement != nil } == true)
        #expect(controller.completedRun?.restorationError?.contains("restore") == true)
        #expect(controller.lastError == nil)
    }

    @Test("menu toggle is disabled while a benchmark owns tunnel lifecycle")
    func benchmarkOwnershipDisablesMenuToggle() async throws {
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(
            suspendOn: rawInvocations[0].id,
            recorder: daemon
        )
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { await runner.suspended }

        #expect(tunnel.benchmarkOwnsLifecycle)
        #expect(tunnel.canToggle == false)
        tunnel.toggle()
        await Task.yield()
        #expect(await daemon.requests.filter { $0 == .connect || $0 == .disconnect }.isEmpty)

        controller.cancel()
        try await waitUntil { !controller.isRunning }
        #expect(tunnel.benchmarkOwnsLifecycle == false)
        #expect(tunnel.canToggle)
    }

    @Test("a partially cancelled second suite restores prior presentation state")
    func cancelledSecondSuiteRestoresPriorLiveState() async throws {
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }
        let priorMeasurements = controller.measurements
        let priorSamples = controller.liveSamples

        await runner.setResponse(.suspendThenSucceed(measurement(for: rawInvocations[1].id)), for: rawInvocations[1].id)
        controller.startFullSuite()
        try await waitUntil { await runner.suspended }
        controller.cancel()
        try await waitUntil { !controller.isRunning }

        #expect(controller.measurements == priorMeasurements)
        #expect(controller.liveSamples == priorSamples)
    }

    @Test("a partially failed second suite restores prior presentation state")
    func failedSecondSuiteRestoresPriorLiveState() async throws {
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }
        let priorMeasurements = controller.measurements
        let priorSamples = controller.liveSamples

        await daemon.suspendNextRequest(.benchmarkTopology)
        controller.startFullSuite()
        try await waitUntil { await daemon.waitingRequest == .benchmarkTopology }
        await daemon.setTopology(BenchmarkTopology(
            protocolVersion: 1,
            serverVersion: "invalid",
            underlayTarget: "not-an-address",
            tunnelIPv4Target: nil,
            tunnelIPv6Target: nil,
            listenerBasePort: 5210,
            listenerCount: 16,
            paths: testTopology.paths
        ))
        await daemon.resumeSuspendedRequest()
        try await waitUntil { !controller.isRunning }

        #expect(controller.measurements == priorMeasurements)
        #expect(controller.liveSamples == priorSamples)
    }

    @Test("rerun resets only the selected test's live samples")
    func rerunResetsSelectedLiveSamples() async throws {
        let daemon = FakeDaemon(connected: true)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }
        let selected = rawInvocations[0].id
        let untouched = rawInvocations[1].id
        let untouchedSamples = try #require(controller.liveSamples[untouched])

        await runner.setResponse(.succeed(measurement(for: selected, bitsPerSecond: 999)), for: selected)
        controller.rerun(selected)
        try await waitUntil { !controller.isRunning }

        #expect(controller.liveSamples[selected] == [100])
        #expect(controller.liveSamples[untouched] == untouchedSamples)
    }

    @Test("rerun atomically replaces a prior result only on success")
    func rerunReplacesOnlyAfterSuccess() async throws {
        let daemon = FakeDaemon(connected: true)
        let replacement = measurement(for: rawInvocations[0].id, bitsPerSecond: 999)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }
        let original = try #require(controller.completedRun?.results[rawInvocations[0].id]?.measurement)

        await runner.setResponse(.suspendThenSucceed(replacement), for: rawInvocations[0].id)
        controller.rerun(rawInvocations[0].id)
        try await waitUntil { await runner.suspended }
        #expect(controller.completedRun?.results[rawInvocations[0].id]?.measurement == original)
        await runner.resumeSuspendedRun()
        try await waitUntil { !controller.isRunning }
        #expect(controller.completedRun?.results[rawInvocations[0].id]?.measurement == replacement)

        await runner.setResponse(.fail(TestFailure.measurement), for: rawInvocations[0].id)
        controller.rerun(rawInvocations[0].id)
        try await waitUntil { !controller.isRunning }
        #expect(controller.completedRun?.results[rawInvocations[0].id]?.measurement == replacement)
    }
}

private actor FakeDaemon: DaemonRequesting, BenchmarkEventRecording {
    enum Event: Sendable, Equatable {
        case request(DaemonRequest)
        case run(BenchmarkTestID)
    }

    private(set) var connected: Bool
    private(set) var requests: [DaemonRequest] = []
    private(set) var events: [Event] = []
    private(set) var waitingRequest: DaemonRequest?
    private var topology: BenchmarkTopology
    private let connectError: (any Error & Sendable)?
    private let disconnectError: (any Error & Sendable)?
    private let staleStatusRepliesAfterCommand: Int
    private let rejectConcurrentRequestsWhileSuspended: Bool
    private var pendingConnected: Bool?
    private var staleStatusRepliesRemaining = 0
    private var requestToSuspend: DaemonRequest?
    private var requestContinuation: CheckedContinuation<Void, Never>?

    init(
        connected: Bool,
        topology: BenchmarkTopology = testTopology,
        connectError: (any Error & Sendable)? = nil,
        disconnectError: (any Error & Sendable)? = nil,
        staleStatusRepliesAfterCommand: Int = 0,
        suspendOnRequest: DaemonRequest? = nil,
        rejectConcurrentRequestsWhileSuspended: Bool = false
    ) {
        self.connected = connected
        self.topology = topology
        self.connectError = connectError
        self.disconnectError = disconnectError
        self.staleStatusRepliesAfterCommand = staleStatusRepliesAfterCommand
        self.requestToSuspend = suspendOnRequest
        self.rejectConcurrentRequestsWhileSuspended = rejectConcurrentRequestsWhileSuspended
    }

    func request(_ request: DaemonRequest) async throws -> DaemonReply {
        if rejectConcurrentRequestsWhileSuspended, waitingRequest != nil {
            throw TestFailure.concurrentDaemonRequest
        }

        requests.append(request)
        events.append(.request(request))
        if requestToSuspend == request {
            requestToSuspend = nil
            waitingRequest = request
            await withCheckedContinuation { requestContinuation = $0 }
            waitingRequest = nil
        }

        switch request {
        case .status:
            if staleStatusRepliesRemaining > 0 {
                staleStatusRepliesRemaining -= 1
            } else if let pendingConnected {
                connected = pendingConnected
                self.pendingConnected = nil
            }
            return .status(statusSnapshot(connected: connected))
        case .benchmarkTopology:
            return .benchmarkTopology(topology)
        case .connect:
            if let connectError { throw connectError }
            pendingConnected = true
            staleStatusRepliesRemaining = staleStatusRepliesAfterCommand
            if staleStatusRepliesRemaining == 0 {
                connected = true
                pendingConnected = nil
            }
            return .ok
        case .disconnect:
            if let disconnectError { throw disconnectError }
            pendingConnected = false
            staleStatusRepliesRemaining = staleStatusRepliesAfterCommand
            if staleStatusRepliesRemaining == 0 {
                connected = false
                pendingConnected = nil
            }
            return .ok
        }
    }

    func recordRun(_ id: BenchmarkTestID) {
        events.append(.run(id))
    }

    func resumeSuspendedRequest() {
        requestContinuation?.resume()
        requestContinuation = nil
    }

    func setTopology(_ topology: BenchmarkTopology) {
        self.topology = topology
    }

    func suspendNextRequest(_ request: DaemonRequest) {
        requestToSuspend = request
    }
}

private actor FakeBenchmarkRunner: BenchmarkRunning {
    enum Response: Sendable {
        case succeed(BenchmarkMeasurement)
        case fail(any Error & Sendable)
        case suspendThenSucceed(BenchmarkMeasurement)
    }

    private(set) var invocationIDs: [BenchmarkTestID] = []
    private(set) var cancelAllCount = 0
    private(set) var suspended = false
    private var responses: [BenchmarkTestID: Response]
    private var continuation: CheckedContinuation<Void, Never>?
    private let recorder: (any BenchmarkEventRecording)?

    init(
        failures: [BenchmarkTestID: any Error & Sendable] = [:],
        suspendOn: BenchmarkTestID? = nil,
        recorder: (any BenchmarkEventRecording)? = nil
    ) {
        self.recorder = recorder
        var responses: [BenchmarkTestID: Response] = failures.mapValues(Response.fail)
        if let suspendOn {
            responses[suspendOn] = .suspendThenSucceed(measurement(for: suspendOn))
        }
        self.responses = responses
    }

    func run(
        invocation: BenchmarkInvocation,
        onSample: nonisolated(nonsending) @escaping @Sendable (Double) async -> Void
    ) async throws -> BenchmarkMeasurement {
        let id = invocation.id
        invocationIDs.append(id)
        await recorder?.recordRun(id)
        await onSample(100)
        switch responses[id] ?? .succeed(measurement(for: id)) {
        case .succeed(let measurement):
            return measurement
        case .fail(let error):
            throw error
        case .suspendThenSucceed(let measurement):
            suspended = true
            await withTaskCancellationHandler {
                await withCheckedContinuation { continuation = $0 }
            } onCancel: {
                Task { await self.resumeSuspendedRun() }
            }
            suspended = false
            try Task.checkCancellation()
            return measurement
        }
    }

    func cancelAll() async {
        cancelAllCount += 1
        resumeSuspendedRun()
    }

    func setResponse(_ response: Response, for id: BenchmarkTestID) {
        responses[id] = response
    }

    func resumeSuspendedRun() {
        continuation?.resume()
        continuation = nil
    }
}

private protocol BenchmarkEventRecording: Actor, Sendable {
    func recordRun(_ id: BenchmarkTestID) async
}

private enum TestFailure: Error, Sendable {
    case measurement
    case connect
    case concurrentDaemonRequest
}

private let testTopology = BenchmarkTopology(
    protocolVersion: 1,
    serverVersion: "server-build",
    underlayTarget: "10.10.10.1",
    tunnelIPv4Target: "10.10.99.1",
    tunnelIPv6Target: nil,
    listenerBasePort: 5210,
    listenerCount: 16,
    paths: [
        BenchmarkPath(id: "wired", displayName: "Wired", interface: "en17", sourceAddress: "10.10.10.171")
    ]
)

private let allInvocations = try! BenchmarkPlanner.plan(
    topology: testTopology,
    parameters: .init()
).invocations

private let rawInvocations = allInvocations.filter { $0.id.route != .tunnel }
private let tunnelInvocations = allInvocations.filter { $0.id.route == .tunnel }

private func statusSnapshot(connected: Bool) -> StatusSnapshot {
    StatusSnapshot(
        connected: connected,
        wired: connected,
        wifi: false,
        activePath: connected ? .wired : nil,
        rttMs: connected ? 10 : nil,
        tx: 0,
        rx: 0
    )
}

private func measurement(
    for id: BenchmarkTestID,
    bitsPerSecond: Double = 100
) -> BenchmarkMeasurement {
    BenchmarkMeasurement(
        id: id,
        result: IperfFinalResult(
            bitsPerSecond: bitsPerSecond,
            bytes: UInt64(bitsPerSecond),
            retransmits: 0,
            streamCount: 4,
            meanRTTMicroseconds: 1_000,
            maximumRTTMicroseconds: 2_000,
            throughputRole: .receiver,
            startSeconds: 0,
            endSeconds: 10,
            rawFinalLine: "{}"
        ),
        diagnostics: IperfProcessDiagnostics(
            stderr: "",
            warnings: [],
            terminationStatus: 0,
            wasForceKilled: false
        ),
        members: [:]
    )
}

private func waitUntil(
    timeout: Duration = .seconds(2),
    condition: @escaping @MainActor @Sendable () async -> Bool
) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now + timeout
    while !(await condition()) {
        guard clock.now < deadline else { throw TestWaitError.timeout }
        await Task.yield()
    }
}

private enum TestWaitError: Error {
    case timeout
}
