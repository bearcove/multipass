import Foundation
import SwiftUI

@MainActor
final class ApplicationTerminationCoordinator: NSObject {
    private let shutdown: @MainActor @Sendable () async -> Void
    private var shutdownTask: Task<Void, Never>?
    private var decisionContinuation: CheckedContinuation<Void, Never>?
    private(set) var isWaiting = false
    private(set) var shouldReplyToApplication = false

    init(shutdown: @escaping @MainActor @Sendable () async -> Void) {
        self.shutdown = shutdown
    }

    func requestTermination() -> NSApplication.TerminateReply {
        if shouldReplyToApplication { return .terminateNow }
        guard !isWaiting else { return .terminateLater }
        isWaiting = true
        shutdownTask = Task { [weak self] in
            guard let self else { return }
            await shutdown()
            finishTermination()
        }
        return .terminateLater
    }

    func waitForDecision() async {
        guard !shouldReplyToApplication else { return }
        await withCheckedContinuation { decisionContinuation = $0 }
    }

    private func finishTermination() {
        guard isWaiting else { return }
        isWaiting = false
        shouldReplyToApplication = true
        decisionContinuation?.resume()
        decisionContinuation = nil
    }
}

@MainActor
final class MultipassApplicationDelegate: NSObject, NSApplicationDelegate {
    private var terminationCoordinator: ApplicationTerminationCoordinator?
    private var benchmarkController: BenchmarkController?
    private var terminationReplyTask: Task<Void, Never>?

    override init() {}

    init(terminationCoordinator: ApplicationTerminationCoordinator) {
        self.terminationCoordinator = terminationCoordinator
    }

    func configure(benchmarkController: BenchmarkController) {
        guard self.benchmarkController == nil else { return }
        self.benchmarkController = benchmarkController
        terminationCoordinator = ApplicationTerminationCoordinator(
            shutdown: { [weak benchmarkController] in
                await benchmarkController?.shutdown()
            }
        )
    }

    func requestQuit() {
        NSApplication.shared.terminate(nil)
    }

    func requestTermination(reply: @escaping @MainActor @Sendable () -> Void) -> NSApplication.TerminateReply {
        guard let terminationCoordinator else { return .terminateNow }
        let result = terminationCoordinator.requestTermination()
        guard result == .terminateLater, terminationReplyTask == nil else { return result }
        terminationReplyTask = Task { [weak self] in
            await terminationCoordinator.waitForDecision()
            reply()
            self?.terminationReplyTask = nil
        }
        return result
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        requestTermination {
            sender.reply(toApplicationShouldTerminate: true)
        }
    }
}

@main
struct MultipassApp: App {
    static let benchmarkWindowID = "benchmarks"

    @State private var tunnelController: TunnelController
    @State private var benchmarkController: BenchmarkController
    @NSApplicationDelegateAdaptor private var appDelegate: MultipassApplicationDelegate

    init() {
        let daemon = DaemonClient()
        let tunnel = TunnelController(client: daemon)
        let parameters = BenchmarkParameters()
        let iperfURL = IperfDiscovery.findExecutable()
        let runner = iperfURL.map { IperfRunner(executableURL: $0, parameters: parameters) }
        let iperfVersion: String? = iperfURL == nil ? "unavailable" : nil
        let benchmark = BenchmarkController(
            daemon: daemon,
            tunnel: tunnel,
            runner: runner,
            store: BenchmarkStore(),
            parameters: parameters,
            appBuild: Self.bundleIdentity,
            clientBuild: Self.bundleIdentity,
            iperfVersion: iperfVersion
        )
        _tunnelController = State(initialValue: tunnel)
        _benchmarkController = State(initialValue: benchmark)
        appDelegate.configure(benchmarkController: benchmark)
        tunnel.start()
        Task {
            await benchmark.loadHistory()
            if let iperfURL {
                let version = await IperfVersionProbe().version(at: iperfURL)
                benchmark.publishIperfVersion(version)
            }
        }
    }

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(
                controller: tunnelController,
                benchmarkController: benchmarkController,
                requestQuit: appDelegate.requestQuit
            )
        } label: {
            MenuBarIcon(controller: tunnelController)
        }
        .menuBarExtraStyle(.window)

        Window("Benchmarks", id: Self.benchmarkWindowID) {
            BenchmarkWindow(controller: benchmarkController)
        }
        .defaultSize(width: 1120, height: 720)
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(after: .newItem) {
                OpenWindowButton(windowID: Self.benchmarkWindowID)
            }
        }
    }

    private static var bundleIdentity: String {
        let bundle = Bundle.main
        return (bundle.object(forInfoDictionaryKey: "MultipassBuildCommit") as? String)
            ?? (bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String)
            ?? "unknown"
    }
}
private struct OpenWindowButton: View {
    @Environment(\.openWindow) private var openWindow
    let windowID: String

    var body: some View {
        Button("Benchmark…") {
            openWindow(id: windowID)
        }
        .keyboardShortcut("b", modifiers: [.command, .shift])
    }
}

private struct MenuBarIcon: View {
    let controller: TunnelController

    private var symbolName: String {
        switch controller.state {
        case .connected:
            if controller.failoverTo != nil {
                return "arrow.triangle.2.circlepath"
            }
            return "point.3.filled.connected.trianglepath.dotted"
        case .transitioning:
            return "arrow.triangle.2.circlepath"
        case .disconnected:
            return "point.3.connected.trianglepath.dotted"
        case .daemonUnavailable:
            return "network.slash"
        }
    }

    var body: some View {
        Image(systemName: symbolName)
            .symbolRenderingMode(.monochrome)
            .contentTransition(.symbolEffect(.replace))
            .symbolEffect(.bounce, value: controller.failoverTo)
    }
}
