import Foundation
import Testing
@testable import Multipass

@Suite("Benchmark lifecycle", .serialized)
@MainActor
struct BenchmarkControllerTests {
    @Test("missing iperf prevents a new suite with the actionable prerequisite")
    func missingIperfPreventsNewSuite() {
        let daemon = FakeDaemon(connected: false)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: tunnel,
            runner: nil
        )

        #expect(controller.canStartFullSuite == false)
        #expect(controller.prerequisiteError == "iperf3 is required. Install it with Homebrew: brew install iperf3.")
        controller.startFullSuite()
        #expect(controller.state == .idle)
        #expect(controller.isRunning == false)
    }


    @Test("daemon availability remains unknown until the first app-scope observation")
    func daemonAvailabilityRequiresObservation() async throws {
        let daemon = FakeDaemon(connected: false)
        let tunnel = TunnelController(client: daemon)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: tunnel,
            runner: FakeBenchmarkRunner()
        )

        #expect(controller.daemonAvailability == .unknown)
        #expect(controller.canRunFullSuite == false)
        #expect(controller.runDisabledReason == "Checking multipassd availability…")

        tunnel.start()
        try await waitUntil { controller.daemonAvailability == .available }

        #expect(controller.canRunFullSuite)
        await tunnel.stop()
    }


    @Test("a suite cannot start before daemon availability is confirmed")
    func suiteCannotStartBeforeDaemonObservation() {
        let daemon = FakeDaemon(connected: false)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: TunnelController(client: daemon),
            runner: FakeBenchmarkRunner()
        )

        controller.startFullSuite()

        #expect(controller.isRunning == false)
        #expect(controller.state == .idle)
    }
    @Test("iperf identity publication gates a suite snapshot without blocking controller creation")
    func iperfIdentityPublicationGatesSuiteSnapshot() async throws {
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = testTunnel(client: daemon)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: tunnel,
            runner: runner,
            iperfVersion: nil
        )
        tunnel.start()
        try await waitUntil { controller.daemonAvailability == .available }

        #expect(controller.canRunFullSuite == false)
        #expect(controller.runDisabledReason == "Checking iperf3 version…")

        controller.publishIperfVersion("iperf 3.21")
        #expect(controller.canRunFullSuite)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        #expect(controller.completedRun?.identities.iperfVersion == "iperf 3.21")
        await tunnel.stop()
    }

    @Test("iperf identity cannot change after a suite snapshots it")
    func iperfIdentityDoesNotChangeDuringSuite() async throws {
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(
            suspendOn: rawInvocations[0].id,
            recorder: daemon
        )
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: runner,
            iperfVersion: "iperf 3.21"
        )

        controller.startFullSuite()
        try await waitUntil { await runner.suspended }
        controller.publishIperfVersion("changed")
        await runner.resumeSuspendedRun()
        try await waitUntil { !controller.isRunning }

        #expect(controller.completedRun?.identities.iperfVersion == "iperf 3.21")
    }

    @Test("bounded iperf probing terminates a hung process and publishes unknown")
    func boundedIperfProbeTerminatesHungProcess() async throws {
        let process = FakeVersionProcess()
        let probe = IperfVersionProbe(
            processFactory: { process },
            timeout: .milliseconds(10),
            terminationGrace: .milliseconds(10)
        )

        let version = await probe.version(at: URL(filePath: "/tmp/fake-iperf3"))

        #expect(version == "unknown")
        #expect(process.runCount == 1)
        #expect(process.terminateCount == 1)
        #expect(process.forceKillCount == 1)
        #expect(process.waitCount == 1)
    }

    @Test("bounded iperf probing publishes the first version line")
    func boundedIperfProbePublishesFirstLine() async {
        let process = FakeVersionProcess(
            output: Data("iperf 3.21\nDarwin host\n".utf8),
            finishesAfterRun: true
        )
        let probe = IperfVersionProbe(processFactory: { process })

        let version = await probe.version(at: URL(filePath: "/tmp/fake-iperf3"))

        #expect(version == "iperf 3.21")
        #expect(process.terminateCount == 0)
        #expect(process.forceKillCount == 0)
    }

    @Test("loads persisted history newest first and restores the selected baseline")
    func loadsHistoryAndBaseline() async throws {
        let directory = try temporaryControllerStoreDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = BenchmarkStore(directory: directory)
        let older = benchmarkRun(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000101")!,
            startedAt: Date(timeIntervalSince1970: 1_000)
        )
        let newer = benchmarkRun(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000102")!,
            startedAt: Date(timeIntervalSince1970: 2_000)
        )
        try await store.saveRun(older)
        try await store.saveRun(newer)
        try await store.selectBaseline(older.id)
        let daemon = FakeDaemon(connected: false)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: FakeBenchmarkRunner(),
            store: store
        )

        await controller.loadHistory()

        #expect(controller.history.map(\.id) == [newer.id, older.id])
        #expect(controller.selectedRunID == newer.id)
        #expect(controller.selectedRun == newer)
        #expect(controller.baselineRunID == older.id)
        #expect(controller.baselineRun == older)
        #expect(controller.loadError == nil)
    }

    @Test("reopening history loading is idempotent and preserves an active presentation")
    func repeatedHistoryLoadPreservesActivePresentation() async throws {
        let directory = try temporaryControllerStoreDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = BenchmarkStore(directory: directory)
        let saved = benchmarkRun(startedAt: Date(timeIntervalSince1970: 1_000))
        try await store.saveRun(saved)
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(
            suspendOn: rawInvocations[1].id,
            recorder: daemon
        )
        let tunnel = testTunnel(client: daemon)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: tunnel,
            runner: runner,
            store: store
        )

        await controller.loadHistory()
        controller.startFullSuite()
        try await waitUntil { await runner.suspended }
        let activeMeasurements = controller.measurements
        let activeSelection = controller.selectedRunID

        await controller.loadHistory()

        #expect(controller.measurements == activeMeasurements)
        #expect(controller.selectedRunID == activeSelection)
        #expect(controller.completedRun == saved)
        controller.cancel()
        try await waitUntil { !controller.isRunning }
    }

    @Test("reopening history loading preserves a separately retained unsaved presentation")
    func repeatedHistoryLoadPreservesUnsavedPresentation() async throws {
        let directory = try temporaryControllerStoreDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fault = ControllerStoreCommitFault()
        let store = BenchmarkStore(directory: directory, beforeCommit: fault.check)
        let saved = benchmarkRun(startedAt: Date(timeIntervalSince1970: 1_000))
        try await store.saveRun(saved)
        let daemon = FakeDaemon(connected: false)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: FakeBenchmarkRunner(recorder: daemon),
            store: store
        )
        await controller.loadHistory()
        fault.failNextCommit(to: "index.json")
        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }
        let unsaved = try #require(controller.unsavedRun)

        await controller.loadHistory()

        #expect(controller.unsavedRun == unsaved)
        #expect(controller.selectedRunID == unsaved.id)
        #expect(controller.selectedRun == unsaved)
        #expect(controller.history == [saved])
    }

    @Test("selecting saved history retains an addressable retryable unsaved run")
    func selectingHistoryRetainsUnsavedRun() async throws {
        let directory = try temporaryControllerStoreDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fault = ControllerStoreCommitFault()
        let store = BenchmarkStore(directory: directory, beforeCommit: fault.check)
        let saved = benchmarkRun(startedAt: Date(timeIntervalSince1970: 1_000))
        try await store.saveRun(saved)
        let daemon = FakeDaemon(connected: false)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: FakeBenchmarkRunner(recorder: daemon),
            store: store
        )
        await controller.loadHistory()
        fault.failNextCommit(to: "index.json")
        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }
        let unsaved = try #require(controller.unsavedRun)

        controller.selectRun(saved.id)
        #expect(controller.selectedRun == saved)
        #expect(controller.unsavedRun == unsaved)
        #expect(controller.canRetrySave)

        controller.selectRun(unsaved.id)
        #expect(controller.selectedRun == unsaved)
        await controller.retrySave()

        #expect(controller.unsavedRun == nil)
        #expect(controller.history.contains(where: { $0.id == unsaved.id }))
        #expect(controller.selectedRunID == unsaved.id)
        #expect(controller.saveError == nil)
    }

    @Test("isolates corrupt history files while exposing their load errors")
    func exposesHistoryFileErrors() async throws {
        let directory = try temporaryControllerStoreDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = BenchmarkStore(directory: directory)
        let run = benchmarkRun()
        try await store.saveRun(run)
        try Data("not json".utf8).write(to: directory.appending(path: "corrupt.json"))
        let daemon = FakeDaemon(connected: false)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: FakeBenchmarkRunner(),
            store: store
        )

        await controller.loadHistory()

        #expect(controller.history == [run])
        #expect(controller.historyLoadErrors == [BenchmarkStoreLoadError(
            fileName: "corrupt.json",
            reason: .corrupt
        )])
        #expect(controller.loadError == nil)
    }

    @Test("skipped and absent IDs cannot rerun and explain why")
    func skippedAndAbsentIDsCannotRerun() async throws {
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: runner
        )
        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }
        let skipped = BenchmarkTestID(
            route: .tunnel,
            direction: .upload,
            addressFamily: .ipv6
        )
        let absent = BenchmarkTestID(
            route: .physical(pathID: "missing"),
            direction: .upload,
            addressFamily: .ipv4
        )

        #expect(controller.canRerun(skipped) == false)
        #expect(controller.rerunDisabledReason(skipped) == "This measurement was skipped because the captured suite has no tunnel IPv6 target.")
        #expect(controller.canRerun(absent) == false)
        #expect(controller.rerunDisabledReason(absent) == "This measurement is not part of the captured benchmark suite.")
        let priorInvocationIDs = await runner.invocationIDs

        controller.rerun(skipped)
        controller.rerun(absent)
        await Task.yield()

        #expect(controller.isRunning == false)
        #expect(await runner.invocationIDs == priorInvocationIDs)
    }

    @Test("controller shutdown cancels, joins restoration, and reaps the runner")
    func shutdownCancelsJoinsRestorationAndReapsRunner() async throws {
        let daemon = FakeDaemon(
            connected: false,
            suspendOnRequest: .disconnect
        )
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = testTunnel(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { await daemon.waitingRequest == .disconnect }
        let shutdown = Task { await controller.shutdown() }
        await Task.yield()

        #expect(controller.isRunning)
        #expect(await runner.cancelAllCount == 1)
        await daemon.resumeSuspendedRequest()
        await shutdown.value

        #expect(controller.isRunning == false)
        #expect(controller.state == .cancelled)
        #expect(await daemon.connected == false)
        #expect(tunnel.benchmarkOwnsLifecycle == false)
        #expect(await runner.cancelAllCount >= 2)
    }

    @Test("termination coordinator waits for shutdown before requesting termination")
    func terminationCoordinatorWaitsForShutdown() async {
        let shutdown = FakeApplicationShutdown()
        let coordinator = ApplicationTerminationCoordinator(shutdown: shutdown.perform)

        let reply = coordinator.requestTermination()
        #expect(reply == .terminateLater)
        await Task.yield()
        #expect(coordinator.isWaiting)
        #expect(coordinator.shouldReplyToApplication == false)

        await shutdown.finish()
        await coordinator.waitForDecision()

        #expect(coordinator.shouldReplyToApplication)
        #expect(coordinator.isWaiting == false)
    }

    @Test("termination coordinator handles shutdown finishing before the decision waiter attaches")
    func terminationCoordinatorHandlesImmediateShutdown() async {
        let coordinator = ApplicationTerminationCoordinator(shutdown: {})

        let reply = coordinator.requestTermination()
        #expect(reply == .terminateLater)
        await Task.yield()
        await coordinator.waitForDecision()

        #expect(coordinator.shouldReplyToApplication)
        #expect(coordinator.isWaiting == false)
    }

    @Test("repeated termination requests share one shutdown and one decision")
    func repeatedTerminationRequestsShareShutdown() async {
        let shutdown = FakeApplicationShutdown()
        let coordinator = ApplicationTerminationCoordinator(shutdown: shutdown.perform)

        #expect(coordinator.requestTermination() == .terminateLater)
        #expect(coordinator.requestTermination() == .terminateLater)
        await Task.yield()
        #expect(await shutdown.performCount == 1)

        await shutdown.finish()
        await coordinator.waitForDecision()

        #expect(coordinator.shouldReplyToApplication)
        #expect(coordinator.requestTermination() == .terminateNow)
    }

    @Test("app delegate creates one waiter and one reply for repeated termination requests")
    func appDelegateSharesTerminationWaiter() async throws {
        let shutdown = FakeApplicationShutdown()
        let coordinator = ApplicationTerminationCoordinator(shutdown: shutdown.perform)
        let delegate = MultipassApplicationDelegate(terminationCoordinator: coordinator)
        let replies = TerminationReplyRecorder()

        let first = delegate.requestTermination { replies.record() }
        let second = delegate.requestTermination { replies.record() }

        #expect(first == .terminateLater)
        #expect(second == .terminateLater)
        await Task.yield()
        #expect(replies.count == 0)
        #expect(await shutdown.performCount == 1)

        await shutdown.finish()
        try await waitUntil { replies.count == 1 }

        let completed = delegate.requestTermination { replies.record() }
        #expect(completed == .terminateNow)
        await Task.yield()
        #expect(replies.count == 1)
    }

    @Test("termination waits beyond the former fallback until shutdown completes")
    func terminationWaitsBeyondFormerFallback() async throws {
        let shutdown = FakeApplicationShutdown()
        let coordinator = ApplicationTerminationCoordinator(shutdown: shutdown.perform)

        #expect(coordinator.requestTermination() == .terminateLater)
        try await Task.sleep(for: .milliseconds(20))

        #expect(coordinator.isWaiting)
        #expect(coordinator.shouldReplyToApplication == false)

        await shutdown.finish()
        await coordinator.waitForDecision()

        #expect(coordinator.shouldReplyToApplication)
        #expect(coordinator.isWaiting == false)
    }

    @Test("persists a completed suite and selects it in history")
    func persistsCompletedSuite() async throws {
        let directory = try temporaryControllerStoreDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = BenchmarkStore(directory: directory)
        let daemon = FakeDaemon(connected: false)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: FakeBenchmarkRunner(recorder: daemon),
            store: store
        )
        await controller.loadHistory()

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        let completed = try #require(controller.completedRun)
        let persisted = try #require(try await store.loadRuns().runs.first)
        #expect(persisted.id == completed.id)
        #expect(persisted.identities == completed.identities)
        #expect(persisted.topology == completed.topology)
        #expect(persisted.parameters == completed.parameters)
        #expect(persisted.initiallyConnected == completed.initiallyConnected)
        #expect(persisted.results == completed.results)
        #expect(persisted.restorationError == completed.restorationError)
        #expect(controller.history == [completed])
        #expect(controller.selectedRunID == completed.id)
        #expect(controller.saveError == nil)
    }

    @Test("a save failure keeps the completed result visible but out of history")
    func saveFailureKeepsCompletedResultVisible() async throws {
        let directory = try temporaryControllerStoreDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fault = ControllerStoreCommitFault()
        let store = BenchmarkStore(directory: directory, beforeCommit: fault.check)
        let daemon = FakeDaemon(connected: false)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: FakeBenchmarkRunner(recorder: daemon),
            store: store
        )
        await controller.loadHistory()
        fault.failNextCommit(to: "index.json")

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        let completed = try #require(controller.completedRun)
        #expect(controller.state == .completed)
        #expect(controller.selectedRun == completed)
        #expect(controller.history.isEmpty)
        #expect(controller.saveError?.contains("Failed to save benchmark") == true)
        #expect(try await store.loadRuns().runs.isEmpty)

        await controller.retrySave()

        #expect(controller.history == [completed])
        #expect(controller.saveError == nil)
        #expect(controller.canRetrySave == false)
        #expect(try await store.loadRuns().runs.first?.id == completed.id)
    }

    @Test("an unsaved result blocks a new suite until Retry Save succeeds")
    func unsavedResultBlocksNewSuite() async throws {
        let directory = try temporaryControllerStoreDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fault = ControllerStoreCommitFault()
        let store = BenchmarkStore(directory: directory, beforeCommit: fault.check)
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: runner,
            store: store
        )
        await controller.loadHistory()
        fault.failNextCommit(to: "index.json")
        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }
        let unsaved = try #require(controller.unsavedRun)
        let invocationCount = await runner.invocationIDs.count

        #expect(controller.canRunFullSuite == false)
        #expect(controller.runDisabledReason == "Retry Save before starting another benchmark so this unsaved result is not lost.")

        controller.startFullSuite()
        await Task.yield()

        #expect(controller.isRunning == false)
        #expect(controller.unsavedRun == unsaved)
        #expect(await runner.invocationIDs.count == invocationCount)

        await controller.retrySave()
        #expect(controller.canRunFullSuite)
    }

    @Test("a rerun publishes its replacement only after atomic persistence succeeds")
    func rerunPublishesOnlyAfterPersistence() async throws {
        let directory = try temporaryControllerStoreDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fault = ControllerStoreCommitFault()
        let store = BenchmarkStore(directory: directory, beforeCommit: fault.check)
        let daemon = FakeDaemon(connected: true)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: runner,
            store: store
        )
        await controller.loadHistory()
        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }
        let selected = rawInvocations[0].id
        let original = try #require(controller.completedRun?.results[selected]?.measurement)
        let replacement = measurement(for: selected, bitsPerSecond: 999)
        await runner.setResponse(.succeed(replacement), for: selected)
        fault.failNextCommit(to: "index.json")

        controller.rerun(selected)
        try await waitUntil { !controller.isRunning }

        #expect(controller.completedRun?.results[selected]?.measurement == original)
        #expect(controller.history.first?.results[selected]?.measurement == original)
        #expect(try await store.loadRuns().runs.first?.results[selected]?.measurement == original)
        #expect(controller.saveError?.contains("Failed to save benchmark") == true)

        controller.rerun(selected)
        try await waitUntil { !controller.isRunning }

        #expect(controller.completedRun?.results[selected]?.measurement == replacement)
        #expect(controller.history.first?.results[selected]?.measurement == replacement)
        #expect(try await store.loadRuns().runs.first?.results[selected]?.measurement == replacement)
        #expect(controller.saveError == nil)
    }

    @Test("renaming through the controller persists a normalized human label")
    func renamePersistsNormalizedLabel() async throws {
        let directory = try temporaryControllerStoreDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = BenchmarkStore(directory: directory)
        let run = benchmarkRun(userLabel: nil)
        try await store.saveRun(run)
        let daemon = FakeDaemon(connected: false)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: FakeBenchmarkRunner(),
            store: store
        )
        await controller.loadHistory()

        await controller.renameRun(run.id, userLabel: "  Office regression  ")

        #expect(controller.history.first?.userLabel == "Office regression")
        #expect(controller.selectedRun?.userLabel == "Office regression")
        #expect(try await store.loadRuns().runs.first?.userLabel == "Office regression")
        #expect(controller.saveError == nil)
    }

    @Test("baseline changes persist through the controller")
    func baselineChangesPersist() async throws {
        let directory = try temporaryControllerStoreDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = BenchmarkStore(directory: directory)
        let run = benchmarkRun()
        try await store.saveRun(run)
        let daemon = FakeDaemon(connected: false)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: FakeBenchmarkRunner(),
            store: store
        )
        await controller.loadHistory()

        await controller.setBaseline(run.id)

        #expect(controller.baselineRunID == run.id)
        #expect(try await store.loadIndex().selectedBaselineID == run.id)

        await controller.setBaseline(nil)

        #expect(controller.baselineRunID == nil)
        #expect(try await store.loadIndex().selectedBaselineID == nil)
    }

    @Test("running progress exposes current and remaining planned measurements")
    func runningProgressTracksPlan() async throws {
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(suspendOn: rawInvocations[0].id, recorder: daemon)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: runner
        )

        controller.startFullSuite()
        try await waitUntil { await runner.suspended }

        #expect(controller.totalMeasurementCount == allInvocations.count)
        #expect(controller.completedMeasurementCount == 0)
        #expect(controller.currentMeasurementID == rawInvocations[0].id)
        #expect(controller.remainingMeasurementIDs == Array(allInvocations.dropFirst()).map(\.id))
        #expect(controller.currentLiveSamples == [100])

        controller.cancel()
        try await waitUntil { !controller.isRunning }
    }

    @Test("live samples retain only the bounded measured interval window")
    func liveSamplesStayBounded() async throws {
        let daemon = FakeDaemon(connected: true)
        let runner = FakeBenchmarkRunner(
            samples: (1 ... 15).map(Double.init),
            recorder: daemon
        )
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: runner
        )

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        #expect(controller.liveSamples[rawInvocations[0].id] == (6 ... 15).map(Double.init))
        #expect(controller.liveSamples.values.allSatisfy { $0.count <= 10 })
    }

    @Test("a disconnected suite captures the authenticated server identity after connecting")
    func disconnectedSuiteRefreshesServerIdentity() async throws {
        var disconnectedTopology = testTopology
        disconnectedTopology.serverVersion = "unknown"
        var connectedTopology = disconnectedTopology
        connectedTopology.serverVersion = "authenticated-server-build"
        let daemon = FakeDaemon(
            connected: false,
            topology: disconnectedTopology,
            connectedTopology: connectedTopology
        )
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: runner
        )

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        let run = try #require(controller.completedRun)
        #expect(controller.state == .completed)
        #expect(run.topology.serverVersion == "authenticated-server-build")
        #expect(run.identities.serverBuild == "authenticated-server-build")
        #expect(run.identities.serverBuild == run.topology.serverVersion)
        #expect(await daemon.requests.filter { $0 == .benchmarkTopology }.count == 2)
        #expect(await daemon.connected == false)
    }

    @Test("a disconnected suite rejects changed topology after connecting and restores")
    func disconnectedSuiteRejectsChangedTopology() async throws {
        let directory = try temporaryControllerStoreDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = BenchmarkStore(directory: directory)
        var disconnectedTopology = testTopology
        disconnectedTopology.serverVersion = "unknown"
        var connectedTopology = disconnectedTopology
        connectedTopology.serverVersion = "authenticated-server-build"
        connectedTopology.listenerBasePort += 1
        let daemon = FakeDaemon(
            connected: false,
            topology: disconnectedTopology,
            connectedTopology: connectedTopology
        )
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: runner,
            store: store
        )

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .failed)
        #expect(controller.lastError?.contains("topology changed") == true)
        #expect(controller.completedRun == nil)
        #expect(try await store.loadRuns().runs.isEmpty)
        #expect(await runner.invocationIDs == rawInvocations.map(\.id))
        #expect(await daemon.connected == false)
    }

    @Test("a disconnected suite rejects an unknown authenticated server identity and restores")
    func disconnectedSuiteRejectsUnknownAuthenticatedServerIdentity() async throws {
        var disconnectedTopology = testTopology
        disconnectedTopology.serverVersion = "stale-server-build"
        var connectedTopology = disconnectedTopology
        connectedTopology.serverVersion = "unknown"
        let daemon = FakeDaemon(
            connected: false,
            topology: disconnectedTopology,
            connectedTopology: connectedTopology
        )
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: testTunnel(client: daemon),
            runner: runner
        )

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .failed)
        #expect(controller.lastError?.contains("authenticated server identity") == true)
        #expect(controller.completedRun == nil)
        #expect(await runner.invocationIDs == rawInvocations.map(\.id))
        #expect(await daemon.connected == false)
    }

    @Test("initially disconnected runs raw, connects, runs tunnel, then disconnects")
    func disconnectedFullSuiteRestoresDisconnected() async throws {
        let daemon = FakeDaemon(connected: false)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = testTunnel(client: daemon)
        let controller = BenchmarkController(
            daemon: daemon,
            tunnel: tunnel,
            runner: runner,
            appBuild: "app-build",
            iperfVersion: "iperf 3.21"
        )

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .completed)
        #expect(controller.completedRun?.results.count == allInvocations.count + 2)
        #expect(controller.completedRun?.identities == BenchmarkRunIdentities(
            appBuild: "app-build",
            clientBuild: "daemon-build",
            serverBuild: "server-build",
            iperfVersion: "iperf 3.21"
        ))
        #expect(controller.completedRun?.startedAt != controller.completedRun?.completedAt)
        let skippedIPv6Upload = BenchmarkTestID(
            route: .tunnel,
            direction: .upload,
            addressFamily: .ipv6
        )
        let skippedIPv6Download = BenchmarkTestID(
            route: .tunnel,
            direction: .download,
            addressFamily: .ipv6
        )
        #expect(controller.completedRun?.results[skippedIPv6Upload] == .skipped(
            "tunnel IPv6 target unavailable"
        ))
        #expect(controller.completedRun?.results[skippedIPv6Download] == .skipped(
            "tunnel IPv6 target unavailable"
        ))
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
            .request(.benchmarkTopology),
            .run(tunnelInvocations[0].id),
            .run(tunnelInvocations[1].id),
            .request(.status),
            .request(.disconnect),
            .request(.status),
            .request(.status),
        ])
        #expect(await daemon.connected == false)
    }

    @Test("an unavailable tunnel IPv4 target is skipped without a runner invocation")
    func unavailableTunnelIPv4IsSkippedWithoutRunning() async throws {
        let topology = BenchmarkTopology(
            protocolVersion: 2,
            daemonVersion: "daemon-build",
            serverVersion: "server-build",
            underlayTarget: "10.10.10.1",
            tunnelIPv4Target: nil,
            tunnelIPv6Target: "fd00::1",
            listenerBasePort: 5210,
            listenerCount: 16,
            paths: [
                BenchmarkPath(
                    id: "wired",
                    displayName: "Wired",
                    interface: "en17",
                    sourceAddress: "10.10.10.171"
                )
            ]
        )
        let plannedInvocations = try BenchmarkPlanner.plan(
            topology: topology,
            parameters: .init()
        ).invocations
        let daemon = FakeDaemon(connected: false, topology: topology)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = testTunnel(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)
        let skippedIPv4Upload = BenchmarkTestID(
            route: .tunnel,
            direction: .upload,
            addressFamily: .ipv4
        )
        let skippedIPv4Download = BenchmarkTestID(
            route: .tunnel,
            direction: .download,
            addressFamily: .ipv4
        )

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        let invocationIDs = await runner.invocationIDs
        #expect(controller.state == .completed)
        #expect(controller.completedRun?.results.count == plannedInvocations.count + 2)
        #expect(controller.completedRun?.results[skippedIPv4Upload] == .skipped(
            "tunnel IPv4 target unavailable"
        ))
        #expect(controller.completedRun?.results[skippedIPv4Download] == .skipped(
            "tunnel IPv4 target unavailable"
        ))
        #expect(invocationIDs == plannedInvocations.map(\.id))
        #expect(invocationIDs.contains(skippedIPv4Upload) == false)
        #expect(invocationIDs.contains(skippedIPv4Download) == false)
        #expect(await daemon.connected == false)
    }

    @Test("tunnel transitions wait through stale status until daemon convergence")
    func transitionWaitsForObservedConvergence() async throws {
        let daemon = FakeDaemon(connected: false, staleStatusRepliesAfterCommand: 1)
        let tunnel = testTunnel(client: daemon)
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
        let tunnel = testTunnel(client: daemon)
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
        let tunnel = testTunnel(client: daemon)
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

    @Test("initially connected uses its initial authenticated topology and never disconnects")
    func connectedFullSuiteStaysConnected() async throws {
        let daemon = FakeDaemon(connected: true)
        let runner = FakeBenchmarkRunner(recorder: daemon)
        let tunnel = testTunnel(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .completed)
        #expect(await daemon.connected)
        #expect(await daemon.requests.filter { $0 == .benchmarkTopology }.count == 1)
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
        let tunnel = testTunnel(client: daemon)
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
        let tunnel = testTunnel(client: daemon)
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
        let tunnel = testTunnel(client: daemon)
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
        let tunnel = testTunnel(client: daemon)
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
        let tunnel = testTunnel(client: daemon)
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
        let tunnel = testTunnel(client: daemon)
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
        let tunnel = testTunnel(client: daemon)
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
        let tunnel = testTunnel(client: daemon)
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
        let tunnel = testTunnel(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }
        let prior = try #require(controller.completedRun)

        await daemon.setTopology(BenchmarkTopology(
            protocolVersion: 2,
            daemonVersion: "daemon-build",
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
        let tunnel = testTunnel(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }

        #expect(controller.state == .completed)
        #expect(controller.completedRun?.results.values.filter { !$0.isFailure && !$0.isSkipped }
            .allSatisfy { $0.measurement != nil } == true)
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
        let tunnel = testTunnel(client: daemon)
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
        let tunnel = testTunnel(client: daemon)
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
        let tunnel = testTunnel(client: daemon)
        let controller = BenchmarkController(daemon: daemon, tunnel: tunnel, runner: runner)

        controller.startFullSuite()
        try await waitUntil { !controller.isRunning }
        let priorMeasurements = controller.measurements
        let priorSamples = controller.liveSamples

        await daemon.suspendNextRequest(.benchmarkTopology)
        controller.startFullSuite()
        try await waitUntil { await daemon.waitingRequest == .benchmarkTopology }
        await daemon.setTopology(BenchmarkTopology(
            protocolVersion: 2,
            daemonVersion: "daemon-build",
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
        let tunnel = testTunnel(client: daemon)
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
        let tunnel = testTunnel(client: daemon)
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
    private let connectedTopology: BenchmarkTopology?
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
        connectedTopology: BenchmarkTopology? = nil,
        connectError: (any Error & Sendable)? = nil,
        disconnectError: (any Error & Sendable)? = nil,
        staleStatusRepliesAfterCommand: Int = 0,
        suspendOnRequest: DaemonRequest? = nil,
        rejectConcurrentRequestsWhileSuspended: Bool = false
    ) {
        self.connected = connected
        self.topology = topology
        self.connectedTopology = connectedTopology
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
            return .benchmarkTopology(connected ? connectedTopology ?? topology : topology)
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
@MainActor
private func testTunnel(client: any DaemonRequesting) -> TunnelController {
    TunnelController(client: client, initialDaemonAvailability: .available)
}

private final class FakeVersionProcess: IperfVersionProcess, @unchecked Sendable {
    private let lock = NSLock()
    private let output: Data
    private let finishesAfterRun: Bool
    private var running = false
    private var _runCount = 0
    private var _terminateCount = 0
    private var _forceKillCount = 0
    private var _waitCount = 0

    init(output: Data = Data(), finishesAfterRun: Bool = false) {
        self.output = output
        self.finishesAfterRun = finishesAfterRun
    }

    var runCount: Int { lock.withLock { _runCount } }
    var terminateCount: Int { lock.withLock { _terminateCount } }
    var forceKillCount: Int { lock.withLock { _forceKillCount } }
    var waitCount: Int { lock.withLock { _waitCount } }
    var isRunning: Bool { lock.withLock { running } }

    func run(executableURL: URL, arguments: [String]) throws {
        lock.withLock {
            _runCount += 1
            running = !finishesAfterRun
        }
    }

    func terminate() {
        lock.withLock {
            _terminateCount += 1
        }
    }

    func forceKill() {
        lock.withLock {
            _forceKillCount += 1
            running = false
        }
    }

    func waitUntilExit() {
        lock.withLock {
            _waitCount += 1
        }
    }

    func collectedOutput() -> Data { output }
}

private actor FakeApplicationShutdown {
    private var continuation: CheckedContinuation<Void, Never>?
    private(set) var performCount = 0

    func perform() async {
        performCount += 1
        await withCheckedContinuation { continuation = $0 }
    }

    func finish() {
        continuation?.resume()
        continuation = nil
    }
}

@MainActor
private final class TerminationReplyRecorder {
    private(set) var count = 0

    func record() {
        count += 1
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
    private let samples: [Double]
    private let recorder: (any BenchmarkEventRecording)?

    init(
        failures: [BenchmarkTestID: any Error & Sendable] = [:],
        suspendOn: BenchmarkTestID? = nil,
        samples: [Double] = [100],
        recorder: (any BenchmarkEventRecording)? = nil
    ) {
        self.samples = samples
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
        for sample in samples {
            await onSample(sample)
        }
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
    protocolVersion: 2,
    daemonVersion: "daemon-build",
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


private final class ControllerStoreCommitFault: @unchecked Sendable {
    private var fileNameToFail: String?

    func failNextCommit(to fileName: String) {
        fileNameToFail = fileName
    }

    func check(_ destination: URL) throws {
        if fileNameToFail == destination.lastPathComponent {
            fileNameToFail = nil
            throw CocoaError(.fileWriteUnknown)
        }
    }
}

private func temporaryControllerStoreDirectory() throws -> URL {
    let directory = FileManager.default.temporaryDirectory.appending(
        path: "multipass-benchmark-controller-tests-\(UUID().uuidString)",
        directoryHint: .isDirectory
    )
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return directory
}