import SwiftUI

nonisolated struct UplinkPresentation: Equatable {
    nonisolated enum Tone: Equatable {
        case disabled
        case waiting
        case working
        case ready
        case error
    }

    let label: String
    let tone: Tone
    let symbol: String

    nonisolated init(state: String, configuredEnabled: Bool, ready: Bool, lastError: String?) {
        if !configuredEnabled || state == "disabled" {
            label = "Disabled"
            tone = .disabled
            symbol = "minus.circle"
        } else if let lastError, !lastError.isEmpty {
            label = "Error: \(lastError)"
            tone = .error
            symbol = "exclamationmark.triangle.fill"
        } else if ready || state == "ready" {
            label = "Ready"
            tone = .ready
            symbol = "checkmark.circle.fill"
        } else {
            switch state {
            case "waiting_for_address":
                label = "Waiting for address"
                tone = .waiting
                symbol = "clock"
            case "racing_endpoints", "resolving_endpoints":
                label = "Racing endpoints"
                tone = .working
                symbol = "arrow.trianglehead.branch"
            case "authenticating":
                label = "Authenticating"
                tone = .working
                symbol = "lock.rotation"
            case "waiting", "idle":
                label = "Waiting"
                tone = .waiting
                symbol = "clock"
            default:
                label = state.replacingOccurrences(of: "_", with: " ").capitalized
                tone = state.localizedCaseInsensitiveContains("error") ? .error : .waiting
                symbol = tone == .error ? "exclamationmark.triangle.fill" : "clock"
            }
        }
    }

}

/// The menubar panel: tunnel state, ordered uplink health, throughput, and the
/// connect/disconnect toggle. It is a pure projection of `TunnelController`.
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
        .frame(width: 360)
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
        case .daemonUnavailable:
            "Daemon unavailable"
        case .transitioning:
            "Working…"
        case .connected:
            if let uplink = controller.activeUplink {
                "Connected via \(uplink.displayName)"
            } else {
                "Connected"
            }
        case .disconnected:
            controller.enabled ? "Enabled — waiting for connectivity" : "Disabled"
        }
    }

    // MARK: - Status body

    private var statusBody: some View {
        VStack(alignment: .leading, spacing: 12) {
            failoverBanner
            if controller.uplinks.isEmpty {
                Text(controller.enabled ? "No configured uplinks are available yet." : "No uplinks configured.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(controller.uplinks, id: \.id) { uplink in
                    uplinkRow(uplink)
                }
            }
            Divider()
            statsGrid
        }
        .animation(.snappy, value: controller.failoverToID)
    }

    /// Appears briefly when the active ID changes while the tunnel stays ready.
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

    private func uplinkRow(_ uplink: UplinkStatus) -> some View {
        let presentation = UplinkPresentation(
            state: uplink.state,
            configuredEnabled: uplink.configuredEnabled,
            ready: uplink.ready,
            lastError: uplink.lastError
        )
        let active = controller.activeUplinkID == uplink.id

        return VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 8) {
                Image(systemName: presentation.symbol)
                    .frame(width: 18)
                    .foregroundStyle(presentationColor(presentation.tone))
                VStack(alignment: .leading, spacing: 1) {
                    Text(uplink.displayName)
                        .font(.body.weight(.medium))
                    Text(uplink.interface)
                        .font(.caption.monospaced())
                        .foregroundStyle(.tertiary)
                }
                if active, controller.state.isConnected {
                    Text("ACTIVE")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(Color.accentColor)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(Color.accentColor.opacity(0.15), in: .capsule)
                }
                Spacer()
                Text("↑ \(rateText(uplink.txRate))  ↓ \(rateText(uplink.rxRate))")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .contentTransition(.numericText())
            }
            HStack(spacing: 6) {
                Text(presentation.label)
                    .foregroundStyle(presentationColor(presentation.tone))
                if let rtt = uplink.rttMs {
                    Text("•")
                    Text(rttText(rtt))
                }
                Spacer()
            }
            .font(.caption)
            diagnosticLine(uplink)
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(uplinkAccessibilityLabel(uplink, presentation: presentation, active: active))
    }

    @ViewBuilder
    private func diagnosticLine(_ uplink: UplinkStatus) -> some View {
        let source = uplink.sourceAddress ?? "No source address"
        let endpoint = uplink.gatewayEndpoint ?? "No endpoint selected"
        Text("\(source)  →  \(endpoint)")
            .font(.caption2.monospaced())
            .foregroundStyle(.tertiary)
            .lineLimit(1)
            .truncationMode(.middle)
            .help("Source: \(source)\nGateway: \(endpoint)")
    }

    private func uplinkAccessibilityLabel(
        _ uplink: UplinkStatus,
        presentation: UplinkPresentation,
        active: Bool
    ) -> String {
        "\(uplink.displayName), interface \(uplink.interface), \(presentation.label)"
            + (active ? ", active" : "")
            + ", upload \(rateText(uplink.txRate)), download \(rateText(uplink.rxRate))"
    }
    private func presentationColor(_ tone: UplinkPresentation.Tone) -> Color {
        switch tone {
        case .disabled: .secondary
        case .waiting: .orange
        case .working: .blue
        case .ready: .green
        case .error: .red
        }
    }


    private var statsGrid: some View {
        Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
            GridRow {
                statLabel("RTT")
                statValue(controller.rttMs.map(rttText) ?? "—")
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

    private func rttText(_ rtt: Double) -> String {
        rtt < 10 ? String(format: "%.1f ms", rtt) : String(format: "%.0f ms", rtt)
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
                    Text(controller.enabled ? "Disconnect" : "Connect")
                        .frame(maxWidth: .infinity)
                }
            }
            .padding(.vertical, 4)
        }
        .buttonStyle(.borderedProminent)
        .tint(controller.enabled ? .red : .accentColor)
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
        return controller.enabled ? "Disable the Multipass tunnel." : "Enable the Multipass tunnel."
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
