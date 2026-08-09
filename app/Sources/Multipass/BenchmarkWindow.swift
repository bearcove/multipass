import SwiftUI

struct BenchmarkWindow: View {
    @Bindable var controller: BenchmarkController

    var body: some View {
        NavigationSplitView {
            BenchmarkHistorySidebar(controller: controller)
        } detail: {
            detail
                .navigationTitle("Benchmark")
        }
        .navigationSplitViewStyle(.balanced)
        .frame(minWidth: 920, minHeight: 600)
    }

    @ViewBuilder
    private var detail: some View {
        if controller.isRunning {
            runningView
        } else if let run = controller.selectedRun ?? controller.completedRun {
            BenchmarkResultsView(controller: controller, run: run)
        } else {
            idleView
        }
    }

    private var idleView: some View {
        VStack(spacing: 18) {
            ContentUnavailableView {
                Label("No Benchmark Selected", systemImage: "speedometer")
            } description: {
                Text("Run the complete suite to measure physical paths, aggregate capacity, and tunnel throughput.")
            } actions: {
                Button("Run Full Suite") {
                    controller.startFullSuite()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!controller.canRunFullSuite)
                .keyboardShortcut(.defaultAction)
            }

            if let reason = controller.runDisabledReason {
                Text(reason)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .accessibilityLabel(reason)
            }
            if let loadError = controller.loadError {
                errorText(loadError)
            }
            if let saveError = controller.saveError {
                errorText(saveError)
            }
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var runningView: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Running Full Suite")
                            .font(.title2.weight(.semibold))
                        Text("\(controller.completedMeasurementCount) of \(controller.totalMeasurementCount) measurements complete")
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    }
                    Spacer()
                    Button("Cancel", role: .cancel) {
                        controller.cancel()
                    }
                    .keyboardShortcut(.cancelAction)
                }

                ProgressView(
                    value: Double(controller.completedMeasurementCount),
                    total: Double(max(controller.totalMeasurementCount, 1))
                )
                .accessibilityLabel("Suite progress")
                .accessibilityValue("\(controller.completedMeasurementCount) of \(controller.totalMeasurementCount)")

                VStack(alignment: .leading, spacing: 7) {
                    Text(controller.currentPhaseTitle)
                        .font(.headline)
                    if let id = controller.currentMeasurementID {
                        Text("\(BenchmarkFormatting.routeLabel(for: id, topology: controller.activeTopology)), \(BenchmarkFormatting.directionLabel(id.direction))")
                            .foregroundStyle(.secondary)
                    }
                    Text(controller.currentLiveSamples.last.map(BenchmarkFormatting.gbitsPerSecond) ?? "Waiting for throughput…")
                        .font(.system(.title, design: .rounded).weight(.semibold))
                        .monospacedDigit()
                    BenchmarkLiveChart(samples: controller.currentLiveSamples)
                }

                if !controller.measurements.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Completed Results")
                            .font(.headline)
                        ForEach(controller.completedMeasurementIDs, id: \.self) { id in
                            HStack {
                                Text("\(BenchmarkFormatting.routeLabel(for: id, topology: controller.activeTopology)) · \(BenchmarkFormatting.directionLabel(id.direction))")
                                Spacer()
                                Text(BenchmarkFormatting.resultStatus(controller.measurements[id]))
                                    .monospacedDigit()
                                    .foregroundStyle(controller.measurements[id]?.isFailure == true ? .red : .primary)
                            }
                            .accessibilityElement(children: .combine)
                        }
                    }
                }

                if !controller.remainingMeasurementIDs.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Remaining")
                            .font(.headline)
                        ForEach(controller.remainingMeasurementIDs, id: \.self) { id in
                            Text("\(BenchmarkFormatting.routeLabel(for: id, topology: controller.activeTopology)) · \(BenchmarkFormatting.directionLabel(id.direction))")
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                if let error = controller.lastError {
                    errorText(error)
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func errorText(_ text: String) -> some View {
        Label(text, systemImage: "exclamationmark.triangle.fill")
            .foregroundStyle(.red)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityElement(children: .combine)
    }
}
