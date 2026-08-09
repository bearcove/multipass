import AppKit
import SwiftUI

struct BenchmarkResultsView: View {
    @Bindable var controller: BenchmarkController
    let run: BenchmarkRun

    private var comparison: BenchmarkComparison? {
        controller.baselineRun.map { BenchmarkComparison(current: run, baseline: $0) }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                metadataHeader

                if let restorationError = run.restorationError {
                    errorBanner(restorationError, title: "Tunnel state was not restored")
                }
                if let saveError = controller.saveError {
                    saveErrorBanner(saveError)
                }

                resultSection(
                    "Physical Paths",
                    rows: run.topology.paths.map {
                        ResultRow(label: $0.displayName, route: .physical(pathID: $0.id), family: .ipv4)
                    }
                )
                resultSection(
                    "Raw Aggregate",
                    rows: [ResultRow(label: "All physical paths", route: .physicalAggregate, family: .ipv4)]
                )
                resultSection(
                    "Tunnel IPv4",
                    rows: [ResultRow(label: "Tunnel IPv4", route: .tunnel, family: .ipv4)]
                )
                resultSection(
                    "Tunnel IPv6",
                    rows: [ResultRow(label: "Tunnel IPv6", route: .tunnel, family: .ipv6)]
                )
                efficiencySection
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var metadataHeader: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(BenchmarkFormatting.displayLabel(for: run))
                        .font(.title2.weight(.semibold))
                    Text("\(BenchmarkFormatting.iso8601(run.startedAt)) · \(BenchmarkFormatting.duration(run.startedAt, run.completedAt))")
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
                Spacer()
                Button("Copy Report", action: copyReport)
                    .keyboardShortcut("c", modifiers: [.command, .shift])
                Button("Run Full Suite") {
                    controller.startFullSuite()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!controller.canRunFullSuite)
                .help(controller.runDisabledReason ?? "Run the complete benchmark suite")
                .keyboardShortcut("r", modifiers: [.command, .shift])
            }

            Grid(alignment: .leading, horizontalSpacing: 22, verticalSpacing: 6) {
                metadataRow("App", run.identities.appBuild, "Client/daemon", run.identities.clientBuild)
                metadataRow("Server", run.identities.serverBuild, "iperf", run.identities.iperfVersion)
                metadataRow("Underlay", run.topology.underlayTarget, "Listeners", BenchmarkFormatting.listenerRange(base: run.topology.listenerBasePort, count: run.topology.listenerCount))
                metadataRow("Tunnel IPv4", run.topology.tunnelIPv4Target ?? "Unavailable", "Tunnel IPv6", run.topology.tunnelIPv6Target ?? "Unavailable")
                metadataRow("Streams", String(run.parameters.parallelStreams), "Measured", "\(run.parameters.measuredSeconds) s + \(run.parameters.omittedSeconds) s warm-up")
            }
            .font(.callout)
        }
    }

    private func metadataRow(_ firstLabel: String, _ firstValue: String, _ secondLabel: String, _ secondValue: String) -> some View {
        GridRow {
            Text(firstLabel).foregroundStyle(.secondary)
            Text(firstValue).textSelection(.enabled)
            Text(secondLabel).foregroundStyle(.secondary)
            Text(secondValue).textSelection(.enabled)
        }
    }

    private func resultSection(_ title: String, rows: [ResultRow]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.headline)
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 9) {
                GridRow {
                    Text("Measurement")
                    Text("Upload")
                    Text("Download")
                    Text("")
                }
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)

                Divider().gridCellColumns(4)

                ForEach(rows) { row in
                    GridRow(alignment: .firstTextBaseline) {
                        Text(row.label)
                        resultCell(id: row.id(direction: .upload))
                        resultCell(id: row.id(direction: .download))
                        Menu("Rerun") {
                            rerunButton("Upload", id: row.id(direction: .upload))
                            rerunButton("Download", id: row.id(direction: .download))
                        }
                        .menuStyle(.borderlessButton)
                        .accessibilityLabel("Rerun \(row.label) measurement")
                    }
                }
            }
        }
    }

    private func rerunButton(_ title: String, id: BenchmarkTestID) -> some View {
        let reason = controller.rerunDisabledReason(id)
        return Button(title) { controller.rerun(id) }
            .disabled(reason != nil)
            .help(reason ?? "Rerun the \(title.lowercased()) measurement")
            .accessibilityHint(reason ?? "Reruns only this measurement")
    }

    private func resultCell(id: BenchmarkTestID) -> some View {
        let result = run.results[id]
        let comparisonResult = comparison?.results[id]
        let status = BenchmarkFormatting.resultStatus(result)
        let delta = BenchmarkFormatting.delta(comparisonResult)
        let retransmits = result?.measurement?.result?.retransmits

        return VStack(alignment: .leading, spacing: 2) {
            Text(status)
                .font(.body.monospacedDigit())
                .foregroundStyle(statusStyle(result))
            if delta != "—" {
                Text(delta)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(deltaStyle(comparisonResult))
            }
            if result?.measurement != nil {
                Text("Retransmits: \(BenchmarkFormatting.unsignedInteger(retransmits))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(BenchmarkFormatting.routeLabel(for: id, topology: run.topology)), \(BenchmarkFormatting.directionLabel(id.direction)), \(status), delta \(delta), retransmits \(BenchmarkFormatting.unsignedInteger(retransmits))")
    }

    private var efficiencySection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Tunnel Efficiency")
                .font(.headline)
            Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 8) {
                GridRow {
                    Text("Family")
                    Text("Upload")
                    Text("Download")
                }
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                ForEach([BenchmarkAddressFamily.ipv4, .ipv6], id: \.self) { family in
                    GridRow {
                        Text(family == .ipv4 ? "IPv4" : "IPv6")
                        efficiencyValue(family, .upload)
                        efficiencyValue(family, .download)
                    }
                }
            }
        }
    }

    private func efficiencyValue(_ family: BenchmarkAddressFamily, _ direction: BenchmarkDirection) -> some View {
        let value = BenchmarkComparison.efficiency(in: run, addressFamily: family, direction: direction)
        return Text(value.map(BenchmarkFormatting.percentage) ?? "—")
            .monospacedDigit()
            .accessibilityLabel("\(family == .ipv4 ? "IPv4" : "IPv6") \(BenchmarkFormatting.directionLabel(direction)) efficiency \(value.map(BenchmarkFormatting.percentage) ?? "unavailable")")
    }

    private func statusStyle(_ result: BenchmarkResult?) -> Color {
        if result?.isSkipped == true { return .secondary }
        return result?.isFailure == true ? .red : .primary
    }

    private func deltaStyle(_ result: BenchmarkResultComparison?) -> Color {
        guard case .comparable(let delta) = result else { return .secondary }
        if delta.absoluteBitsPerSecond > 0 { return .green }
        if delta.absoluteBitsPerSecond < 0 { return .red }
        return .secondary
    }

    private func errorBanner(_ message: String, title: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(title, systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
            Text(message)
                .textSelection(.enabled)
        }
        .foregroundStyle(.red)
        .accessibilityElement(children: .combine)
    }

    private func saveErrorBanner(_ message: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Label("Result is visible but not saved", systemImage: "exclamationmark.triangle.fill")
                    .font(.headline)
                Text(message)
                    .textSelection(.enabled)
            }
            Spacer()
            if controller.canRetrySave {
                Button("Retry Save") {
                    Task { await controller.retrySave() }
                }
            }
        }
        .foregroundStyle(.red)
        .accessibilityElement(children: .contain)
    }

    private func copyReport() {
        guard let report = controller.reportMarkdown() else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(report, forType: .string)
    }
}

private struct ResultRow: Identifiable {
    let label: String
    let route: BenchmarkRoute
    let family: BenchmarkAddressFamily

    var id: String { "\(label)-\(family.rawValue)" }

    func id(direction: BenchmarkDirection) -> BenchmarkTestID {
        BenchmarkTestID(route: route, direction: direction, addressFamily: family)
    }
}
