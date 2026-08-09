import Darwin
import Foundation

nonisolated protocol IperfVersionProcess: AnyObject, Sendable {
    var isRunning: Bool { get }

    func run(executableURL: URL, arguments: [String]) throws
    func terminate()
    func forceKill()
    func waitUntilExit()
    func collectedOutput() -> Data
}

nonisolated struct IperfVersionProbe: Sendable {
    private let processFactory: @Sendable () -> any IperfVersionProcess
    private let timeout: Duration
    private let terminationGrace: Duration

    init(
        processFactory: @escaping @Sendable () -> any IperfVersionProcess = { FoundationIperfVersionProcess() },
        timeout: Duration = .seconds(2),
        terminationGrace: Duration = .milliseconds(250)
    ) {
        self.processFactory = processFactory
        self.timeout = timeout
        self.terminationGrace = terminationGrace
    }
    @concurrent
    func version(at executableURL: URL) async -> String {
        let process = processFactory()
        do {
            try process.run(executableURL: executableURL, arguments: ["--version"])
        } catch {
            return "unknown"
        }

        let clock = ContinuousClock()
        let deadline = clock.now + timeout
        while process.isRunning, clock.now < deadline {
            try? await Task.sleep(for: .milliseconds(10))
        }

        if process.isRunning {
            process.terminate()
            let graceDeadline = clock.now + terminationGrace
            while process.isRunning, clock.now < graceDeadline {
                try? await Task.sleep(for: .milliseconds(10))
            }
            if process.isRunning {
                process.forceKill()
            }
        }
        process.waitUntilExit()

        return String(decoding: process.collectedOutput(), as: UTF8.self)
            .split(whereSeparator: \Character.isNewline)
            .first
            .map(String.init)
            ?? "unknown"
    }
}

private nonisolated final class FoundationIperfVersionProcess: IperfVersionProcess, @unchecked Sendable {
    private let process = Process()
    private let output = Pipe()

    var isRunning: Bool { process.isRunning }

    func run(executableURL: URL, arguments: [String]) throws {
        process.executableURL = executableURL
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = output
        try process.run()
        try? output.fileHandleForWriting.close()
    }

    func terminate() {
        if process.isRunning { process.terminate() }
    }

    func forceKill() {
        if process.isRunning { Darwin.kill(process.processIdentifier, SIGKILL) }
    }

    func waitUntilExit() {
        process.waitUntilExit()
    }

    func collectedOutput() -> Data {
        output.fileHandleForReading.readDataToEndOfFile()
    }
}
