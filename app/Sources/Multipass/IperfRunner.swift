import Darwin
import Foundation

nonisolated struct IperfProcessDiagnostics: Codable, Sendable, Equatable {
    let stderr: String
    let warnings: [String]
    let terminationStatus: Int32?
    let wasForceKilled: Bool
}

nonisolated struct IperfMemberDiagnostic: Codable, Sendable, Equatable {
    let result: IperfFinalResult?
    let diagnostics: IperfProcessDiagnostics
    let error: String?
}

nonisolated struct IperfAggregateDiagnostics: Codable, Sendable, Equatable {
    let members: [String: IperfMemberDiagnostic]
}

nonisolated struct BenchmarkMeasurement: Codable, Sendable, Equatable {
    let id: BenchmarkTestID
    let result: IperfFinalResult?
    let diagnostics: IperfProcessDiagnostics
    let members: [String: IperfFinalResult]
}

nonisolated enum IperfRunnerError: Error, Sendable, Equatable {
    case invalidInvocation
    case processFailed(status: Int32, diagnostics: IperfProcessDiagnostics)
    case timedOut(diagnostics: IperfProcessDiagnostics)
    case cancelled(diagnostics: IperfProcessDiagnostics)
    case missingFinalResult(diagnostics: IperfProcessDiagnostics)
    case aggregateFailed(IperfAggregateDiagnostics)
}

extension IperfRunnerError: LocalizedError {
    nonisolated var errorDescription: String? {
        switch self {
        case .invalidInvocation:
            "Invalid iperf invocation"
        case .processFailed(let status, let diagnostics):
            diagnostics.stderr.isEmpty
                ? "iperf exited with status \(status)"
                : "iperf exited with status \(status): \(diagnostics.stderr)"
        case .timedOut:
            "iperf timed out"
        case .cancelled:
            "iperf was cancelled"
        case .missingFinalResult:
            "iperf did not emit a valid final result"
        case .aggregateFailed:
            "One or more aggregate iperf members failed"
        }
    }
}

nonisolated protocol BenchmarkRunning: Actor, Sendable {
    func run(
        invocation: BenchmarkInvocation,
        onSample: nonisolated(nonsending) @escaping @Sendable (Double) async -> Void
    ) async throws -> BenchmarkMeasurement

    func cancelAll() async
}

actor IperfRunner: BenchmarkRunning {
    private typealias IndexedSampleHandler = @Sendable (Int, Double) async -> Void
    typealias SampleHandler = @Sendable (Double) async -> Void

    private let executableURL: URL
    private let parameters: BenchmarkParameters
    private let environment: [String: String]?
    private let startupTeardownMargin: Duration
    private let terminationGrace: Duration
    private var children: [UUID: Process] = [:]
    private var cancelledChildren: Set<UUID> = []

    init(
        executableURL: URL,
        parameters: BenchmarkParameters,
        environment: [String: String]? = nil,
        startupTeardownMargin: Duration = .seconds(5),
        terminationGrace: Duration = .seconds(1)
    ) {
        self.executableURL = executableURL
        self.parameters = parameters
        self.environment = environment
        self.startupTeardownMargin = startupTeardownMargin
        self.terminationGrace = terminationGrace
    }

    func run(
        invocation: BenchmarkInvocation,
        onSample: @escaping SampleHandler
    ) async throws -> BenchmarkMeasurement {
        switch invocation {
        case .single:
            return try await runSingle(invocation: invocation, onSample: onSample)
        case .aggregate(let id, let members):
            return try await runAggregate(id: id, members: members, onSample: onSample)
        }
    }

    func cancelAll() async {
        let running = children
        cancelledChildren.formUnion(running.keys)
        for process in running.values where process.isRunning {
            process.terminate()
        }
        try? await Task.sleep(for: terminationGrace)
        for process in running.values where process.isRunning {
            Darwin.kill(process.processIdentifier, SIGKILL)
        }
        await waitForProcesses(Array(running.values))
    }

    private func runSingle(
        invocation: BenchmarkInvocation,
        onSample: @escaping SampleHandler
    ) async throws -> BenchmarkMeasurement {
        try await runSingleIndexed(invocation: invocation) { _, bitsPerSecond in
            await onSample(bitsPerSecond)
        }
    }

    private func runSingleIndexed(
        invocation: BenchmarkInvocation,
        onSample: @escaping IndexedSampleHandler
    ) async throws -> BenchmarkMeasurement {
        guard case .single(let id, _, _, _, _) = invocation else {
            throw IperfRunnerError.invalidInvocation
        }
        let childID = UUID()
        let process = Process()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.executableURL = executableURL
        process.arguments = try arguments(for: invocation)
        process.environment = environment
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let stdoutTask = Task {
            try await consumeStdout(
                stdoutPipe.fileHandleForReading,
                direction: id.direction,
                onSample: onSample
            )
        }
        let stderrTask = Task {
            try await readAll(stderrPipe.fileHandleForReading)
        }

        do {
            try process.run()
        } catch {
            stdoutTask.cancel()
            stderrTask.cancel()
            throw error
        }
        try? stdoutPipe.fileHandleForWriting.close()
        try? stderrPipe.fileHandleForWriting.close()
        children[childID] = process

        var outcome = await waitForExitOrDeadline(process)
        if cancelledChildren.remove(childID) != nil {
            outcome = .cancelled
        }
        var forceKilled = false
        switch outcome {
        case .exited:
            break
        case .timedOut, .cancelled:
            forceKilled = await terminate(process)
        }
        process.waitUntilExit()
        children.removeValue(forKey: childID)

        let stdout: StdoutResult
        do {
            stdout = try await stdoutTask.value
        } catch {
            stdout = StdoutResult(result: nil, warnings: [error.localizedDescription])
        }
        let stderrData = (try? await stderrTask.value) ?? Data()
        let diagnostics = IperfProcessDiagnostics(
            stderr: String(decoding: stderrData, as: UTF8.self),
            warnings: stdout.warnings,
            terminationStatus: process.terminationStatus,
            wasForceKilled: forceKilled
        )

        switch outcome {
        case .timedOut:
            throw IperfRunnerError.timedOut(diagnostics: diagnostics)
        case .cancelled:
            throw IperfRunnerError.cancelled(diagnostics: diagnostics)
        case .exited:
            guard process.terminationStatus == 0 else {
                throw IperfRunnerError.processFailed(
                    status: process.terminationStatus,
                    diagnostics: diagnostics
                )
            }
            guard let result = stdout.result else {
                throw IperfRunnerError.missingFinalResult(diagnostics: diagnostics)
            }
            return BenchmarkMeasurement(
                id: id,
                result: result,
                diagnostics: diagnostics,
                members: [:]
            )
        }
    }

    private func runAggregate(
        id: BenchmarkTestID,
        members: [BenchmarkInvocation],
        onSample: @escaping SampleHandler
    ) async throws -> BenchmarkMeasurement {
        let sampleAccumulator = AggregateSampleAccumulator(
            memberCount: members.count,
            onSample: onSample
        )
        var diagnostics: [String: IperfMemberDiagnostic] = [:]

        await withTaskGroup(of: AggregateMemberOutcome.self) { group in
            for member in members {
                group.addTask { [self] in
                    let pathID = memberPathID(member)
                    do {
                        let measurement = try await runSingleIndexed(invocation: member) { slot, sample in
                            await sampleAccumulator.update(pathID: pathID, slot: slot, sample: sample)
                        }
                        return AggregateMemberOutcome(
                            pathID: pathID,
                            diagnostic: IperfMemberDiagnostic(
                                result: measurement.result,
                                diagnostics: measurement.diagnostics,
                                error: nil
                            )
                        )
                    } catch {
                        return AggregateMemberOutcome(
                            pathID: pathID,
                            diagnostic: memberDiagnostic(from: error)
                        )
                    }
                }
            }
            for await outcome in group {
                diagnostics[outcome.pathID] = outcome.diagnostic
            }
        }

        guard diagnostics.count == members.count,
              diagnostics.values.allSatisfy({ $0.result != nil && $0.error == nil }) else {
            throw IperfRunnerError.aggregateFailed(IperfAggregateDiagnostics(members: diagnostics))
        }

        let memberResults = diagnostics.compactMapValues(\.result)
        return BenchmarkMeasurement(
            id: id,
            result: aggregate(memberResults),
            diagnostics: IperfProcessDiagnostics(
                stderr: diagnostics.keys.sorted().compactMap { diagnostics[$0]?.diagnostics.stderr }
                    .filter { !$0.isEmpty }.joined(separator: "\n"),
                warnings: diagnostics.keys.sorted().flatMap { diagnostics[$0]?.diagnostics.warnings ?? [] },
                terminationStatus: 0,
                wasForceKilled: false
            ),
            members: memberResults
        )
    }

    private func arguments(for invocation: BenchmarkInvocation) throws -> [String] {
        guard case .single(let id, let target, let port, let sourceAddress, let interface) = invocation else {
            throw IperfRunnerError.invalidInvocation
        }
        var arguments = [
            "--client", target,
            "--port", String(port),
            "--parallel", String(parameters.parallelStreams),
            "--time", String(parameters.measuredSeconds),
            "--omit", String(parameters.omittedSeconds),
            "--interval", String(parameters.intervalSeconds),
            "--connect-timeout", String(parameters.connectTimeoutSeconds * 1_000),
            "--json-stream-full-output",
            "--json-stream",
            "--forceflush",
            id.addressFamily == .ipv4 ? "--version4" : "--version6",
        ]
        if let sourceAddress {
            let binding = interface.map { "\(sourceAddress)%\($0)" } ?? sourceAddress
            arguments.append(contentsOf: ["--bind", binding])
        }
        if id.direction == .download {
            arguments.append("--reverse")
        }
        return arguments
    }

    private func waitForExitOrDeadline(_ process: Process) async -> ProcessOutcome {
        let timeout = Duration.seconds(
            parameters.omittedSeconds
                + parameters.measuredSeconds
                + parameters.connectTimeoutSeconds
        ) + startupTeardownMargin
        let race = OutcomeRace()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                race.install(continuation)
                process.terminationHandler = { _ in
                    race.resolve(.exited)
                }
                if !process.isRunning {
                    race.resolve(.exited)
                }
                let deadlineTask = Task {
                    do {
                        try await Task.sleep(for: timeout)
                        race.resolve(.timedOut)
                    } catch {}
                }
                race.install(deadlineTask: deadlineTask)
            }
        } onCancel: {
            race.resolve(.cancelled)
            process.terminate()
        }
    }

    private func terminate(_ process: Process) async -> Bool {
        if process.isRunning {
            process.terminate()
        }
        let clock = ContinuousClock()
        let deadline = clock.now + terminationGrace
        while process.isRunning, clock.now < deadline {
            try? await Task.sleep(for: .milliseconds(10))
        }
        guard process.isRunning else { return false }
        Darwin.kill(process.processIdentifier, SIGKILL)
        while process.isRunning {
            try? await Task.sleep(for: .milliseconds(10))
        }
        return true
    }

    private func waitForProcesses(_ processes: [Process]) async {
        while processes.contains(where: \.isRunning) {
            try? await Task.sleep(for: .milliseconds(10))
        }
        for process in processes {
            process.waitUntilExit()
        }
    }

    nonisolated private func memberPathID(_ invocation: BenchmarkInvocation) -> String {
        switch invocation.id.execution {
        case .simultaneousMember(let pathID):
            pathID
        case .single:
            if case .physical(let pathID) = invocation.id.route {
                pathID
            } else {
                String(describing: invocation.id.route)
            }
        }
    }

    nonisolated private func memberDiagnostic(from error: Error) -> IperfMemberDiagnostic {
        switch error {
        case IperfRunnerError.processFailed(_, let diagnostics),
             IperfRunnerError.timedOut(let diagnostics),
             IperfRunnerError.cancelled(let diagnostics),
             IperfRunnerError.missingFinalResult(let diagnostics):
            return IperfMemberDiagnostic(
                result: nil,
                diagnostics: diagnostics,
                error: error.localizedDescription
            )
        default:
            return IperfMemberDiagnostic(
                result: nil,
                diagnostics: IperfProcessDiagnostics(
                    stderr: "",
                    warnings: [],
                    terminationStatus: nil,
                    wasForceKilled: false
                ),
                error: error.localizedDescription
            )
        }
    }

    private func aggregate(_ members: [String: IperfFinalResult]) -> IperfFinalResult {
        let results = members.keys.sorted().compactMap { members[$0] }
        return IperfFinalResult(
            bitsPerSecond: results.reduce(0) { $0 + $1.bitsPerSecond },
            bytes: results.reduce(0) { $0 + $1.bytes },
            retransmits: optionalSum(results.map(\.retransmits)),
            streamCount: results.reduce(0) { $0 + $1.streamCount },
            meanRTTMicroseconds: optionalMean(results.map(\.meanRTTMicroseconds)),
            maximumRTTMicroseconds: results.compactMap(\.maximumRTTMicroseconds).max(),
            throughputRole: .receiver,
            startSeconds: results.map(\.startSeconds).min() ?? 0,
            endSeconds: results.map(\.endSeconds).max() ?? 0,
            rawFinalLine: results.map(\.rawFinalLine).joined(separator: "\n")
        )
    }

    private func optionalSum(_ values: [UInt64?]) -> UInt64? {
        let present = values.compactMap { $0 }
        guard !present.isEmpty else { return nil }
        return present.reduce(0, +)
    }

    private func optionalMean(_ values: [UInt64?]) -> UInt64? {
        let present = values.compactMap { $0 }
        guard !present.isEmpty else { return nil }
        return present.reduce(0, +) / UInt64(present.count)
    }
}

private nonisolated enum ProcessOutcome: Sendable {
    case exited
    case timedOut
    case cancelled
}

private nonisolated struct StdoutResult: Sendable {
    let result: IperfFinalResult?
    let warnings: [String]
}

private nonisolated struct AggregateMemberOutcome: Sendable {
    let pathID: String
    let diagnostic: IperfMemberDiagnostic
}

private actor AggregateSampleAccumulator {
    private let memberCount: Int
    private var samplesBySlot: [Int: [String: Double]] = [:]
    private let onSample: IperfRunner.SampleHandler

    init(memberCount: Int, onSample: @escaping IperfRunner.SampleHandler) {
        self.memberCount = memberCount
        self.onSample = onSample
    }

    func update(pathID: String, slot: Int, sample: Double) async {
        samplesBySlot[slot, default: [:]][pathID] = sample
        guard samplesBySlot[slot]?.count == memberCount,
              let samples = samplesBySlot.removeValue(forKey: slot) else { return }
        await onSample(samples.values.reduce(0, +))
    }
}

private nonisolated final class OutcomeRace: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<ProcessOutcome, Never>?
    private var pendingOutcome: ProcessOutcome?
    private var deadlineTask: Task<Void, Never>?
    private var resolved = false

    func install(_ continuation: CheckedContinuation<ProcessOutcome, Never>) {
        lock.lock()
        if resolved, let pendingOutcome {
            self.pendingOutcome = nil
            lock.unlock()
            continuation.resume(returning: pendingOutcome)
        } else {
            self.continuation = continuation
            lock.unlock()
        }
    }

    func install(deadlineTask: Task<Void, Never>) {
        lock.lock()
        if resolved {
            lock.unlock()
            deadlineTask.cancel()
        } else {
            self.deadlineTask = deadlineTask
            lock.unlock()
        }
    }

    func resolve(_ outcome: ProcessOutcome) {
        lock.lock()
        guard !resolved else {
            lock.unlock()
            return
        }
        resolved = true
        guard let continuation else {
            pendingOutcome = outcome
            lock.unlock()
            return
        }
        self.continuation = nil
        let deadlineTask = self.deadlineTask
        self.deadlineTask = nil
        lock.unlock()
        deadlineTask?.cancel()
        continuation.resume(returning: outcome)
    }
}

private nonisolated func consumeStdout(
    _ handle: FileHandle,
    direction: BenchmarkDirection,
    onSample: @escaping @Sendable (Int, Double) async -> Void
) async throws -> StdoutResult {
    var parser = IperfStreamParser(direction: direction)
    var pending = Data()
    var warnings: [String] = []

    for try await chunk in pipeChunks(from: handle) {
        pending.append(chunk)
        while let newline = pending.firstIndex(of: 0x0A) {
            let line = pending[..<newline]
            if !line.isEmpty {
                await consumeLine(
                    String(decoding: line, as: UTF8.self),
                    parser: &parser,
                    warnings: &warnings,
                    onSample: onSample
                )
            }
            pending.removeSubrange(...newline)
        }
    }
    if !pending.isEmpty {
        await consumeLine(
            String(decoding: pending, as: UTF8.self),
            parser: &parser,
            warnings: &warnings,
            onSample: onSample
        )
    }
    return StdoutResult(result: try? parser.finish(), warnings: warnings)
}

private nonisolated func consumeLine(
    _ line: String,
    parser: inout IperfStreamParser,
    warnings: inout [String],
    onSample: @escaping @Sendable (Int, Double) async -> Void
) async {
    for event in parser.consume(line: line) {
        switch event {
        case .interval(let ordinal, let bitsPerSecond):
            await onSample(ordinal, bitsPerSecond)
        case .completed:
            break
        case .warning(let warning):
            warnings.append(warning)
        }
    }
}

private nonisolated func readAll(_ handle: FileHandle) async throws -> Data {
    var data = Data()
    for try await chunk in pipeChunks(from: handle) {
        data.append(chunk)
    }
    return data
}

private nonisolated func pipeChunks(
    from handle: FileHandle
) -> AsyncThrowingStream<Data, any Error> {
    AsyncThrowingStream { continuation in
        handle.readabilityHandler = { readableHandle in
            let chunk = readableHandle.availableData
            guard !chunk.isEmpty else {
                readableHandle.readabilityHandler = nil
                continuation.finish()
                return
            }
            continuation.yield(chunk)
        }
        continuation.onTermination = { _ in
            handle.readabilityHandler = nil
        }
    }
}
