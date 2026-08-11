import Darwin
import Foundation
import Testing
@testable import Multipass

@Suite("iperf process runner", .serialized)
struct IperfRunnerTests {
    @Test("passes the exact iperf argument array without a shell")
    func passesDirectArguments() async throws {
        let argsFile = temporaryURL(named: "args.json")
        let runner = IperfRunner(
            executableURL: try fixtureExecutable(),
            parameters: fastParameters,
            environment: fixtureEnvironment(
                mode: "capture",
                extra: ["IPERF_FIXTURE_ARGS_FILE": argsFile.path]
            )
        )
        let invocation = BenchmarkInvocation.single(
            id: .init(route: .physical(pathID: "wired"), direction: .download, addressFamily: .ipv4),
            target: "10.10.10.1; touch /tmp/should-not-exist",
            port: 5217,
            sourceAddress: "10.10.10.171",
            interface: "en17"
        )

        _ = try await runner.run(invocation: invocation) { _ in }

        let data = try Data(contentsOf: argsFile)
        let arguments = try JSONDecoder().decode([String].self, from: data)
        #expect(arguments == [
            "--client", "10.10.10.1; touch /tmp/should-not-exist",
            "--port", "5217",
            "--parallel", "2",
            "--time", "1",
            "--omit", "0",
            "--interval", "1",
            "--connect-timeout", "1000",
            "--json-stream",
            "--forceflush",
            "--version4",
            "--bind", "10.10.10.171%en17",
            "--reverse",
        ])
    }

    @Test("drains stderr concurrently with stdout")
    func drainsBothPipes() async throws {
        let runner = IperfRunner(
            executableURL: try fixtureExecutable(),
            parameters: fastParameters,
            environment: fixtureEnvironment(mode: "large-stderr")
        )

        let measurement = try await runner.run(invocation: uploadInvocation()) { _ in }

        #expect(measurement.result?.bitsPerSecond == 222)
        #expect(measurement.diagnostics.stderr.contains("stderr-finished"))
    }

    @Test("captures an immediate successful child exit")
    func immediateSuccessfulExitDoesNotTimeout() async throws {
        let runner = IperfRunner(
            executableURL: try fixtureExecutable(),
            parameters: .init(
                parallelStreams: 1,
                measuredSeconds: 0,
                omittedSeconds: 0,
                intervalSeconds: 1,
                connectTimeoutSeconds: 0
            ),
            environment: fixtureEnvironment(mode: "immediate-success"),
            startupTeardownMargin: .milliseconds(100),
            terminationGrace: .milliseconds(100)
        )

        let measurement = try await runner.run(invocation: uploadInvocation()) { _ in }

        #expect(measurement.result?.bitsPerSecond == 222)
    }

    @Test("delivers interval samples before process completion")
    func streamsSamplesIncrementally() async throws {
        let controlDirectory = temporaryURL(named: "incremental-control", directory: true)
        let readyFile = controlDirectory.appending(path: "ready")
        let releaseFile = controlDirectory.appending(path: "release")
        defer { try? FileManager.default.removeItem(at: controlDirectory) }
        let runner = IperfRunner(
            executableURL: try fixtureExecutable(),
            parameters: fastParameters,
            environment: fixtureEnvironment(
                mode: "incremental",
                extra: [
                    "IPERF_FIXTURE_READY_FILE": readyFile.path,
                    "IPERF_FIXTURE_RELEASE_FILE": releaseFile.path,
                ]
            )
        )
        let recorder = SampleRecorder()
        let completion = CompletionRecorder()
        let task = Task {
            do {
                let measurement = try await runner.run(invocation: uploadInvocation()) { sample in
                    await recorder.record(sample)
                }
                await completion.record()
                return measurement
            } catch {
                await completion.record()
                throw error
            }
        }

        do {
            try await waitUntil {
                guard FileManager.default.fileExists(atPath: readyFile.path) else { return false }
                return await recorder.values == [111]
            }
            #expect(!(await completion.didComplete))

            try Data().write(to: releaseFile, options: .atomic)
            let measurement = try await task.value
            #expect(await recorder.values == [111, 222])
            #expect(measurement.result?.bitsPerSecond == 222)
        } catch {
            try? Data().write(to: releaseFile, options: .atomic)
            _ = await task.result
            throw error
        }
    }

    @Test("surfaces stderr and exit status on failure")
    func nonzeroExitSurfacesStderr() async throws {
        let runner = IperfRunner(
            executableURL: try fixtureExecutable(),
            parameters: fastParameters,
            environment: fixtureEnvironment(
                mode: "fail",
                extra: ["IPERF_FIXTURE_ERROR": "listener refused", "IPERF_FIXTURE_EXIT": "23"]
            )
        )

        do {
            _ = try await runner.run(invocation: uploadInvocation()) { _ in }
            Issue.record("Expected the child failure")
        } catch let error as IperfRunnerError {
            guard case .processFailed(let status, let diagnostics) = error else {
                Issue.record("Unexpected error: \(error)")
                return
            }
            #expect(status == 23)
            #expect(diagnostics.stderr.contains("listener refused"))
        }
    }

    @Test("timeout terminates and reaps an uncooperative child")
    func timeoutKillsAndReaps() async throws {
        let pidFile = temporaryURL(named: "timeout.pid")
        let runner = IperfRunner(
            executableURL: try fixtureExecutable(),
            parameters: .init(
                parallelStreams: 1,
                measuredSeconds: 0,
                omittedSeconds: 0,
                intervalSeconds: 1,
                connectTimeoutSeconds: 0
            ),
            environment: fixtureEnvironment(
                mode: "ignore-term",
                extra: ["IPERF_FIXTURE_PID_FILE": pidFile.path]
            ),
            startupTeardownMargin: .milliseconds(100),
            terminationGrace: .milliseconds(100)
        )

        do {
            _ = try await runner.run(invocation: uploadInvocation()) { _ in }
            Issue.record("Expected timeout")
        } catch let error as IperfRunnerError {
            guard case .timedOut(let diagnostics) = error else {
                Issue.record("Unexpected error: \(error)")
                return
            }
            #expect(diagnostics.wasForceKilled)
        }

        let pid = try await waitForPID(in: pidFile)
        #expect(kill(pid, 0) == -1)
        #expect(errno == ESRCH)
    }

    @Test("direct task cancellation is classified as cancelled after reaping")
    func directCancellationIsCancelled() async throws {
        let pidFile = temporaryURL(named: "cancel.pid")
        let runner = IperfRunner(
            executableURL: try fixtureExecutable(),
            parameters: .init(
                parallelStreams: 1,
                measuredSeconds: 60,
                omittedSeconds: 0,
                intervalSeconds: 1,
                connectTimeoutSeconds: 1
            ),
            environment: fixtureEnvironment(
                mode: "sleep",
                extra: ["IPERF_FIXTURE_PID_FILE": pidFile.path]
            ),
            startupTeardownMargin: .seconds(1),
            terminationGrace: .milliseconds(100)
        )
        let task = Task {
            try await runner.run(invocation: uploadInvocation()) { _ in }
        }

        let pid = try await waitForPID(in: pidFile)
        task.cancel()

        guard case .failure(let error) = await task.result,
              case .cancelled = error as? IperfRunnerError else {
            Issue.record("Expected IperfRunnerError.cancelled")
            return
        }
        #expect(kill(pid, 0) == -1)
        #expect(errno == ESRCH)
    }

    @Test("cancelAll terminates every simultaneous child")
    func cancellationTerminatesAllMembers() async throws {
        let directory = temporaryURL(named: "member-pids", directory: true)
        let runner = IperfRunner(
            executableURL: try fixtureExecutable(),
            parameters: .init(
                parallelStreams: 1,
                measuredSeconds: 60,
                omittedSeconds: 0,
                intervalSeconds: 1,
                connectTimeoutSeconds: 1
            ),
            environment: fixtureEnvironment(
                mode: "sleep",
                extra: ["IPERF_FIXTURE_PID_DIRECTORY": directory.path]
            ),
            startupTeardownMargin: .seconds(1),
            terminationGrace: .milliseconds(100)
        )
        let task = Task {
            try await runner.run(invocation: aggregateInvocation()) { _ in }
        }

        let pids = try await waitForPIDs(in: directory, count: 2)
        await runner.cancelAll()
        let result = await task.result
        guard case .failure(let error) = result,
              case .aggregateFailed(let diagnostics) = error as? IperfRunnerError else {
            Issue.record("Expected aggregate cancellation failure")
            return
        }
        #expect(diagnostics.members.values.allSatisfy { $0.error == "iperf was cancelled" })

        for pid in pids {
            #expect(kill(pid, 0) == -1)
            #expect(errno == ESRCH)
        }
    }

    @Test("aggregate failure preserves successful member diagnostics")
    func aggregateFailurePreservesPartialDiagnostics() async throws {
        let runner = IperfRunner(
            executableURL: try fixtureExecutable(),
            parameters: fastParameters,
            environment: fixtureEnvironment(mode: "partial-fail")
        )

        do {
            _ = try await runner.run(invocation: aggregateInvocation()) { _ in }
            Issue.record("Expected aggregate failure")
        } catch let error as IperfRunnerError {
            guard case .aggregateFailed(let diagnostics) = error else {
                Issue.record("Unexpected error: \(error)")
                return
            }
            #expect(diagnostics.members["wired"]?.result?.bitsPerSecond == 100)
            #expect(diagnostics.members["wifi"]?.error?.contains("second member failed") == true)
        }
    }

    @Test("aggregate sums current member samples and final results")
    func aggregateSumsMembers() async throws {
        let runner = IperfRunner(
            executableURL: try fixtureExecutable(),
            parameters: fastParameters,
            environment: fixtureEnvironment(mode: "success")
        )
        let recorder = SampleRecorder()

        let measurement = try await runner.run(invocation: aggregateInvocation()) { sample in
            await recorder.record(sample)
        }

        #expect(measurement.result?.bitsPerSecond == 444)
        #expect(measurement.result?.bytes == 4444)
        #expect(measurement.members.keys.sorted() == ["wifi", "wired"])
        #expect(await recorder.values.last == 222)
        #expect(measurement.result?.rawFinalLine.split(separator: "\n").count == 2)
    }

    @Test("aggregate emits only complete matching interval totals")
    func aggregateAlignsMemberIntervals() async throws {
        let runner = IperfRunner(
            executableURL: try fixtureExecutable(),
            parameters: fastParameters,
            environment: fixtureEnvironment(mode: "skewed-aggregate")
        )
        let recorder = SampleRecorder()

        _ = try await runner.run(invocation: aggregateInvocation()) { sample in
            await recorder.record(sample)
        }

        #expect(await recorder.values == [300, 330])
    }

    @Test("aggregate never combines samples across a malformed measured interval")
    func aggregateDoesNotShiftAfterMalformedInterval() async throws {
        let runner = IperfRunner(
            executableURL: try fixtureExecutable(),
            parameters: fastParameters,
            environment: fixtureEnvironment(mode: "malformed-middle-aggregate")
        )
        let recorder = SampleRecorder()

        _ = try await runner.run(invocation: aggregateInvocation()) { sample in
            await recorder.record(sample)
        }

        #expect(await recorder.values == [300, 330])
    }

    @Test("aggregate reserves a type-malformed measured interval ordinal")
    func aggregateDoesNotShiftAfterTypeMalformedInterval() async throws {
        let runner = IperfRunner(
            executableURL: try fixtureExecutable(),
            parameters: fastParameters,
            environment: fixtureEnvironment(mode: "type-malformed-middle-aggregate")
        )
        let recorder = SampleRecorder()

        _ = try await runner.run(invocation: aggregateInvocation()) { sample in
            await recorder.record(sample)
        }

        #expect(await recorder.values == [300, 330])
    }
}

private actor SampleRecorder {
    private(set) var values: [Double] = []

    func record(_ value: Double) {
        values.append(value)
    }
}

private actor CompletionRecorder {
    private(set) var didComplete = false

    func record() {
        didComplete = true
    }
}

private let fastParameters = BenchmarkParameters(
    parallelStreams: 2,
    measuredSeconds: 1,
    omittedSeconds: 0,
    intervalSeconds: 1,
    connectTimeoutSeconds: 1
)

private func fixtureExecutable() throws -> URL {
    try #require(Bundle.module.url(
        forResource: "iperf-test-fixture",
        withExtension: "py",
        subdirectory: "Fixtures"
    ))
}

private func fixtureEnvironment(mode: String, extra: [String: String] = [:]) -> [String: String] {
    ProcessInfo.processInfo.environment
        .merging(["IPERF_FIXTURE_MODE": mode]) { _, new in new }
        .merging(extra) { _, new in new }
}

private func uploadInvocation(target: String = "10.10.10.1", pathID: String = "wired") -> BenchmarkInvocation {
    .single(
        id: .init(route: .physical(pathID: pathID), direction: .upload, addressFamily: .ipv4),
        target: target,
        port: pathID == "wired" ? 5210 : 5211,
        sourceAddress: pathID == "wired" ? "10.10.10.171" : "10.10.10.169",
        interface: pathID == "wired" ? "en17" : "en0"
    )
}

private func aggregateInvocation() -> BenchmarkInvocation {
    .aggregate(
        id: .init(route: .physicalAggregate, direction: .upload, addressFamily: .ipv4),
        members: [
            uploadInvocation(target: "10.10.10.1", pathID: "wired"),
            uploadInvocation(target: "10.10.10.2", pathID: "wifi"),
        ]
    )
}

private func temporaryURL(named name: String, directory: Bool = false) -> URL {
    let root = FileManager.default.temporaryDirectory
        .appending(path: "multipass-iperf-tests-\(UUID().uuidString)", directoryHint: .isDirectory)
    try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let hint: URL.DirectoryHint = directory ? .isDirectory : .notDirectory
    let url = root.appending(path: name, directoryHint: hint)
    if directory {
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }
    return url
}

private func waitUntil(
    timeout: Duration = .seconds(2),
    condition: @escaping @Sendable () async -> Bool
) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now + timeout
    while !(await condition()) {
        guard clock.now < deadline else { throw TestWaitError.timeout }
        try await Task.sleep(for: .milliseconds(10))
    }
}

private func waitForPID(in file: URL) async throws -> pid_t {
    try await waitUntil { FileManager.default.fileExists(atPath: file.path) }
    let text = try String(contentsOf: file, encoding: .utf8)
    return try #require(pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines)))
}

private func waitForPIDs(in directory: URL, count: Int) async throws -> [pid_t] {
    try await waitUntil {
        (try? FileManager.default.contentsOfDirectory(atPath: directory.path).count) == count
    }
    return try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        .map {
            try #require(pid_t(String(contentsOf: $0, encoding: .utf8)
                .trimmingCharacters(in: .whitespacesAndNewlines)))
        }
}

private enum TestWaitError: Error {
    case timeout
}
