import SwiftUI

/// The menubar panel: tunnel state, per-path health, throughput, and the
/// connect/disconnect toggle. All state comes from `TunnelController` — this
/// view is a pure projection of the daemon's status replies.
struct MenuBarView: View {
    @Bindable var controller: TunnelController
    @Bindable var benchmarkController: BenchmarkController
    let requestQuit: () -> Void
    @Environment(\.openWindow) private var openWindow
    @State private var launchAtLogin = LaunchAtLogin.status == .enabled

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            if controller.state == .daemonUnavailable {
                daemonUnavailableNotice
            } else {
                statusBody
            }
            toggleButton
            benchmarkButton
            Divider()
            footer
        }
        .padding(16)
        .frame(width: 292)
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: controller.state.isConnected
                ? "point.3.filled.connected.trianglepath.dotted"
                : "point.3.connected.trianglepath.dotted")
                .font(.title2)
                .foregroundStyle(controller.state.isConnected ? Color.accentColor : .secondary)
                .contentTransition(.symbolEffect(.replace))
            VStack(alignment: .leading, spacing: 2) {
                Text("Multipass")
                    .font(.headline)
                Text(stateDescription)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }

    private var stateDescription: String {
        switch controller.state {
        case .daemonUnavailable: "Daemon unavailable"
        case .disconnected: "Disconnected"
        case .transitioning: "Working…"
        case .connected:
            if let path = controller.activePath {
                "Connected via \(path.displayName)"
            } else {
                "Connected"
            }
        }
    }

    // MARK: - Status body

    private var statusBody: some View {
        VStack(alignment: .leading, spacing: 12) {
            failoverBanner
            pathRow(
                name: "Wired",
                symbol: "cable.connector",
                live: controller.wiredLive,
                active: controller.activePath == .wired,
                txRate: controller.wiredTxRate,
                rxRate: controller.wiredRxRate,
            )
            pathRow(
                name: "Wi-Fi",
                symbol: "wifi",
                live: controller.wifiLive,
                active: controller.activePath == .wifi,
                txRate: controller.wifiTxRate,
                rxRate: controller.wifiRxRate,
            )
            Divider()
            statsGrid
        }
        .animation(.snappy, value: controller.failoverTo)
    }

    /// Appears briefly when the active path changes while connected — the
    /// failover event this VPN exists for.
    @ViewBuilder
    private var failoverBanner: some View {
        if let failoverTo = controller.failoverTo {
            Label("Failover → \(failoverTo.displayName)", systemImage: "arrow.triangle.2.circlepath")
                .font(.subheadline.weight(.medium))
                .foregroundStyle(.white)
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.accentColor, in: .rect(cornerRadius: 8))
                .transition(.opacity.combined(with: .move(edge: .top)))
        }
    }

    private func pathRow(
        name: String,
        symbol: String,
        live: Bool,
        active: Bool,
        txRate: Double,
        rxRate: Double
    ) -> some View {
        HStack(spacing: 10) {
            Image(systemName: symbol)
                .frame(width: 20)
                .foregroundStyle(live ? .primary : .secondary)
            Text(name)
                .font(.body)
            if active, controller.state.isConnected {
                Text("ACTIVE")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(Color.accentColor)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 2)
                    .background(Color.accentColor.opacity(0.15), in: .capsule)
            }
            Spacer()
            if controller.state.isConnected {
                Text("↑ \(rateText(txRate))  ↓ \(rateText(rxRate))")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .contentTransition(.numericText())
            }
            Circle()
                .fill(live ? Color.green : Color.red)
                .frame(width: 8, height: 8)
                .shadow(color: live ? .green.opacity(0.6) : .clear, radius: 3)
            Text(live ? "live" : "down")
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(width: 34, alignment: .trailing)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            "\(name) path \(live ? "live" : "down")\(active ? ", active" : "")"
                + (controller.state.isConnected
                    ? ", upload \(rateText(txRate)), download \(rateText(rxRate))"
                    : "")
        )
    }

    private var statsGrid: some View {
        Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
            GridRow {
                statLabel("RTT")
                statValue(rttText)
                statLabel("Up")
                statValue(rateText(controller.txRate))
            }
            GridRow {
                statLabel("Sent")
                statValue(bytesText(controller.totalTx))
                statLabel("Down")
                statValue(rateText(controller.rxRate))
            }
            GridRow {
                statLabel("Received")
                statValue(bytesText(controller.totalRx))
            }
        }
        .opacity(controller.state.isConnected ? 1 : 0.45)
    }

    private func statLabel(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
    }

    private func statValue(_ text: String) -> some View {
        Text(text)
            .font(.callout.monospacedDigit())
            .contentTransition(.numericText())
            .animation(.default, value: text)
    }

    private var rttText: String {
        guard let rtt = controller.rttMs else { return "—" }
        return rtt < 10
            ? String(format: "%.1f ms", rtt)
            : String(format: "%.0f ms", rtt)
    }

    private func rateText(_ bytesPerSecond: Double) -> String {
        Self.byteFormatter.string(fromByteCount: Int64(bytesPerSecond)) + "/s"
    }

    private func bytesText(_ bytes: UInt64) -> String {
        Self.byteFormatter.string(fromByteCount: Int64(bytes))
    }

    private static let byteFormatter: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        formatter.allowedUnits = [.useKB, .useMB, .useGB]
        return formatter
    }()

    // MARK: - Daemon unavailable

    private var daemonUnavailableNotice: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("multipassd is not running", systemImage: "exclamationmark.triangle")
                .font(.subheadline.weight(.medium))
                .foregroundStyle(.orange)
            Text("The privileged daemon must be installed and loaded before the tunnel can be controlled. See the multipass README for the LaunchDaemon setup.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - Toggle

    private var toggleButton: some View {
        Button(action: controller.toggle) {
            Group {
                if controller.state == .transitioning {
                    ProgressView()
                        .controlSize(.small)
                        .frame(maxWidth: .infinity)
                } else {
                    Text(controller.state.isConnected ? "Disconnect" : "Connect")
                        .frame(maxWidth: .infinity)
                }
            }
            .padding(.vertical, 4)
        }
        .buttonStyle(.borderedProminent)
        .tint(controller.state.isConnected ? .red : .accentColor)
        .disabled(!controller.canToggle)
        .keyboardShortcut("d")
        .help(toggleHelp)
        .accessibilityHint(toggleHelp)
    }

    private var toggleHelp: String {
        if controller.benchmarkOwnsLifecycle {
            return "A benchmark is running and controls the tunnel until restoration completes."
        }
        if controller.state == .daemonUnavailable {
            return "multipassd is unavailable."
        }
        if controller.state == .transitioning {
            return "The tunnel is changing state."
        }
        return controller.state.isConnected ? "Disconnect the Multipass tunnel." : "Connect the Multipass tunnel."
    }

    private var benchmarkButton: some View {
        Button {
            openWindow(id: MultipassApp.benchmarkWindowID)
        } label: {
            Label("Benchmark…", systemImage: "speedometer")
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .buttonStyle(.plain)
        .keyboardShortcut("b", modifiers: [.command, .shift])
        .help("Open the benchmark window. Saved history remains available when the daemon is offline.")
    }


    // MARK: - Footer

    private var footer: some View {
        HStack {
            Toggle("Launch at Login", isOn: $launchAtLogin)
                .toggleStyle(.checkbox)
                .font(.callout)
                .disabled(!LaunchAtLogin.isRunningAsAppBundle)
                .onChange(of: launchAtLogin) { _, enabled in
                    do {
                        if enabled {
                            try LaunchAtLogin.register()
                        } else {
                            try LaunchAtLogin.unregister()
                        }
                    } catch {
                        launchAtLogin = LaunchAtLogin.status == .enabled
                    }
                }
            Spacer()
            Button("Quit", action: requestQuit)
            .keyboardShortcut("q")
        }
    }
}

#Preview("Connected") {
    let daemon = DaemonClient()
    let controller = TunnelController(client: daemon)
    let benchmark = BenchmarkController(daemon: daemon, tunnel: controller, runner: nil)
    MenuBarView(
        controller: controller,
        benchmarkController: benchmark,
        requestQuit: { NSApplication.shared.terminate(nil) }
    )
}
