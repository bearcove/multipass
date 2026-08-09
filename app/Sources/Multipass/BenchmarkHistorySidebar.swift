import SwiftUI

struct BenchmarkHistorySidebar: View {
    @Bindable var controller: BenchmarkController

    var body: some View {
        List(selection: selection) {
            Section {
                Button {
                    controller.startFullSuite()
                } label: {
                    Label("New Benchmark", systemImage: "plus")
                }
                .disabled(!controller.canRunFullSuite)
                .help(controller.runDisabledReason ?? "Run the complete benchmark suite")
                .keyboardShortcut("n", modifiers: [.command, .shift])
            }

            Section("History") {
                if let unsavedRun = controller.unsavedRun {
                    BenchmarkHistoryRow(
                        run: unsavedRun,
                        isBaseline: false,
                        statusLabel: "Unsaved",
                        onRename: { _ in },
                        onBaseline: {}
                    )
                    .tag(unsavedRun.id)
                }

                if controller.history.isEmpty, controller.unsavedRun == nil {
                    Text("No completed benchmarks")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(controller.history, id: \.id) { run in
                        BenchmarkHistoryRow(
                            run: run,
                            isBaseline: controller.baselineRunID == run.id,
                            statusLabel: nil,
                            onRename: { label in
                                Task { await controller.renameRun(run.id, userLabel: label) }
                            },
                            onBaseline: {
                                Task {
                                    await controller.setBaseline(
                                        controller.baselineRunID == run.id ? nil : run.id
                                    )
                                }
                            }
                        )
                        .tag(run.id)
                    }
                }
            }

            if !controller.historyLoadErrors.isEmpty {
                Section("History Errors") {
                    ForEach(controller.historyLoadErrors, id: \.fileName) { error in
                        Label(error.accessibilityDescription, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.secondary)
                            .font(.caption)
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .navigationSplitViewColumnWidth(min: 220, ideal: 270, max: 360)
        .navigationTitle("Benchmarks")
    }

    private var selection: Binding<UUID?> {
        Binding(
            get: { controller.selectedRunID },
            set: { controller.selectRun($0) }
        )
    }
}

private struct BenchmarkHistoryRow: View {
    let run: BenchmarkRun
    let isBaseline: Bool
    let statusLabel: String?
    let onRename: (String?) -> Void
    let onBaseline: () -> Void

    @State private var label = ""
    @State private var editingLabel = false

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                Image(systemName: hasErrors ? "exclamationmark.circle.fill" : "checkmark.circle.fill")
                    .foregroundStyle(hasErrors ? .orange : .green)
                    .accessibilityHidden(true)

                Text(BenchmarkFormatting.displayLabel(for: run))
                    .font(.body.weight(.medium))
                    .lineLimit(2)

                if let statusLabel {
                    Text(statusLabel)
                        .font(.caption2.weight(.medium))
                        .foregroundStyle(.secondary)
                } else if isBaseline {
                    Text("Baseline")
                        .font(.caption2.weight(.medium))
                        .foregroundStyle(.secondary)
                }
            }

            Text(BenchmarkFormatting.iso8601(run.startedAt))
                .font(.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(BenchmarkFormatting.displayLabel(for: run)), \(hasErrors ? "completed with errors" : "complete")\(isBaseline ? ", baseline" : "")")
        .contextMenu {
            Button("Rename…") {
                label = run.userLabel ?? ""
                editingLabel = true
            }
            Button(isBaseline ? "Clear Baseline" : "Use as Baseline", action: onBaseline)
        }
        .popover(isPresented: $editingLabel) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Benchmark Label")
                    .font(.headline)
                TextField("Optional label", text: $label)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 260)
                    .onSubmit(commitLabel)
                HStack {
                    Button("Cancel") { editingLabel = false }
                        .keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("Save", action: commitLabel)
                        .keyboardShortcut(.defaultAction)
                }
            }
            .padding()
        }
    }

    private var hasErrors: Bool {
        run.hasErrors
    }

    private func commitLabel() {
        editingLabel = false
        onRename(label)
    }
}

private extension BenchmarkStoreLoadError {
    var accessibilityDescription: String {
        switch reason {
        case .corrupt:
            "Could not load \(fileName): corrupt benchmark file"
        case .unsupportedSchema(let schema):
            "Could not load \(fileName): unsupported schema \(schema)"
        case .identityMismatch(let expectedFileName):
            "Could not load \(fileName): expected \(expectedFileName)"
        }
    }
}
