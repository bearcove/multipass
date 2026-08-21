import Foundation

nonisolated enum BenchmarkReport {
    static func markdown(current: BenchmarkRun, baseline: BenchmarkRun? = nil) -> String {
        let comparison = baseline.map { BenchmarkComparison(current: current, baseline: $0) }
        var lines: [String] = [
            "# Multipass Benchmark Report",
            "",
            "- Run: \(escapedText(reportLabel(for: current))) (\(codeSpan(current.id.uuidString.lowercased())))",
            "- Automatic label: \(escapedText(BenchmarkFormatting.reportAutomaticLabel(for: current)))",
            "- Started: \(BenchmarkFormatting.iso8601(current.startedAt))",
            "- Completed: \(BenchmarkFormatting.iso8601(current.completedAt))",
        ]
        if let baseline {
            lines.append("- Baseline: \(escapedText(reportLabel(for: baseline))) (\(codeSpan(baseline.id.uuidString.lowercased())))")
        }
        lines.append("- Initial tunnel state: \(current.initiallyConnected ? "connected" : "disconnected")")
        lines.append(contentsOf: [
            "",
            "## Build identities",
            "",
            "| Component | Identity |",
            "| --- | --- |",
            "| App | \(codeSpan(current.identities.appBuild, table: true)) |",
            "| Client/daemon | \(codeSpan(current.identities.clientBuild, table: true)) |",
            "| Server | \(codeSpan(current.identities.serverBuild, table: true)) |",
            "| iperf | \(codeSpan(current.identities.iperfVersion, table: true)) |",
            "| Benchmark protocol | \(codeSpan(String(current.topology.protocolVersion))) |",
            "",
            "## Topology",
            "",
            "- Underlay target: \(codeSpan(current.topology.underlayTarget))",
            "- Tunnel IPv4 target: \(target(current.topology.tunnelIPv4Target))",
            "- Tunnel IPv6 target: \(target(current.topology.tunnelIPv6Target))",
            "- Listener ports: \(codeSpan("\(current.topology.listenerBasePort)–\(listenerEnd(current.topology))"))",
            "- Physical paths:",
        ])
        for path in current.topology.paths {
            let source = path.sourceAddress.map { codeSpan($0) } ?? "Unavailable"
            lines.append("  - \(escapedText(path.displayName)) (\(codeSpan(path.id))): \(codeSpan(path.interface)), \(source)")
        }
        lines.append(contentsOf: [
            "",
            "## Parameters",
            "",
            "- Protocol: \(current.parameters.protocol.rawValue.uppercased())",
            "- Parallel streams: \(current.parameters.parallelStreams)",
            "- Measured duration: \(current.parameters.measuredSeconds) s",
            "- Omitted warmup: \(current.parameters.omittedSeconds) s",
            "- Interval: \(current.parameters.intervalSeconds) s",
            "- Connect timeout: \(current.parameters.connectTimeoutSeconds) s",
            "",
            "## Results",
            "",
            "| Measurement | Upload | Retransmits | Baseline delta | Download | Retransmits | Baseline delta |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ])

        for row in resultRows(for: current) {
            let upload = cell(
                id: row.uploadID,
                run: current,
                comparison: comparison
            )
            let download = cell(
                id: row.downloadID,
                run: current,
                comparison: comparison
            )
            lines.append("| \(escapedTable(row.label)) | \(upload.value) | \(upload.retransmits) | \(upload.delta) | \(download.value) | \(download.retransmits) | \(download.delta) |")
        }

        lines.append(contentsOf: [
            "",
            "## Tunnel efficiency",
            "",
            "| Family | Upload | Download |",
            "| --- | ---: | ---: |",
            efficiencyRow(family: .ipv4, run: current),
            efficiencyRow(family: .ipv6, run: current),
        ])

        if let restorationError = current.restorationError {
            lines.append(contentsOf: [
                "",
                "## Run errors",
                "",
                "- Restoration: \(escapedText(restorationError))",
            ])
        }
        return lines.joined(separator: "\n")
    }

    private struct ResultRow {
        let label: String
        let uploadID: BenchmarkTestID
        let downloadID: BenchmarkTestID
    }

    private struct ResultCell {
        let value: String
        let retransmits: String
        let delta: String
    }

    private static func resultRows(for run: BenchmarkRun) -> [ResultRow] {
        var rows = run.topology.paths.map { path in
            ResultRow(
                label: path.displayName,
                uploadID: BenchmarkTestID(
                    route: .physical(pathID: path.id),
                    direction: .upload,
                    addressFamily: .ipv4
                ),
                downloadID: BenchmarkTestID(
                    route: .physical(pathID: path.id),
                    direction: .download,
                    addressFamily: .ipv4
                )
            )
        }
        rows.append(ResultRow(
            label: "Raw aggregate",
            uploadID: BenchmarkTestID(
                route: .physicalAggregate,
                direction: .upload,
                addressFamily: .ipv4
            ),
            downloadID: BenchmarkTestID(
                route: .physicalAggregate,
                direction: .download,
                addressFamily: .ipv4
            )
        ))
        for family in [BenchmarkAddressFamily.ipv4, .ipv6] {
            rows.append(ResultRow(
                label: "Tunnel \(family == .ipv4 ? "IPv4" : "IPv6")",
                uploadID: BenchmarkTestID(route: .tunnel, direction: .upload, addressFamily: family),
                downloadID: BenchmarkTestID(route: .tunnel, direction: .download, addressFamily: family)
            ))
        }
        return rows
    }

    private static func cell(
        id: BenchmarkTestID,
        run: BenchmarkRun,
        comparison: BenchmarkComparison?
    ) -> ResultCell {
        guard let result = run.results[id] else {
            return ResultCell(value: "Not run", retransmits: "—", delta: "—")
        }
        switch result {
        case .skipped(let reason):
            return ResultCell(
                value: "Skipped: \(escapedTable(reason))",
                retransmits: "—",
                delta: "—"
            )
        case .failed(let message):
            return ResultCell(
                value: "Failed: \(escapedTable(message))",
                retransmits: "—",
                delta: "—"
            )
        case .measured(let measurement):
            guard let final = measurement.result else {
                return ResultCell(value: "Failed: missing final result", retransmits: "—", delta: "—")
            }
            return ResultCell(
                value: BenchmarkFormatting.gbitsPerSecond(final.bitsPerSecond),
                retransmits: final.retransmits.map(String.init) ?? "—",
                delta: deltaText(comparison?.results[id])
            )
        }
    }

    private static func deltaText(_ result: BenchmarkResultComparison?) -> String {
        switch result {
        case .comparable(let delta):
            "\(BenchmarkFormatting.signedGbitsPerSecond(delta.absoluteBitsPerSecond)) (\(BenchmarkFormatting.signedPercentage(delta.percentage)))"
        case .aggregatePathSetMismatch(let current, let baseline):
            "Path set differs (current: \(escapedTable(current.joined(separator: ", "))); baseline: \(escapedTable(baseline.joined(separator: ", "))))"
        case .incompatibleRun:
            "Incompatible baseline"
        case .unavailable, nil:
            "—"
        }
    }

    private static func efficiencyRow(
        family: BenchmarkAddressFamily,
        run: BenchmarkRun
    ) -> String {
        let upload = BenchmarkComparison.efficiency(
            in: run,
            addressFamily: family,
            direction: .upload
        ).map(BenchmarkFormatting.percentage) ?? "—"
        let download = BenchmarkComparison.efficiency(
            in: run,
            addressFamily: family,
            direction: .download
        ).map(BenchmarkFormatting.percentage) ?? "—"
        return "| \(family == .ipv4 ? "IPv4" : "IPv6") | \(upload) | \(download) |"
    }

    private static func target(_ value: String?) -> String {
        value.map { codeSpan($0) } ?? "Unavailable"
    }

    private static func listenerEnd(_ topology: BenchmarkTopology) -> UInt32 {
        UInt32(topology.listenerBasePort) + UInt32(topology.listenerCount) - 1
    }

    private static func reportLabel(for run: BenchmarkRun) -> String {
        run.userLabel ?? BenchmarkFormatting.reportAutomaticLabel(for: run)
    }

    private static func codeSpan(_ value: String, table: Bool = false) -> String {
        let normalized = singleLine(value)
        if normalized.isEmpty { return "`<empty>`" }
        var maximumRun = 0
        var currentRun = 0
        for character in normalized {
            if character == "`" {
                currentRun += 1
                maximumRun = max(maximumRun, currentRun)
            } else {
                currentRun = 0
            }
        }
        let delimiter = String(repeating: "`", count: maximumRun + 1)
        let allSpaces = normalized.allSatisfy { $0 == " " }
        let needsPadding = normalized.hasPrefix("`") || normalized.hasSuffix("`")
            || (!allSpaces && normalized.hasPrefix(" ") && normalized.hasSuffix(" "))
        let content = needsPadding ? " \(normalized) " : normalized
        let span = "\(delimiter)\(content)\(delimiter)"
        return table ? escapedTablePipes(in: span) : span
    }

    private static func escapedTablePipes(in value: String) -> String {
        var result = ""
        var precedingBackslashes = 0
        for character in value {
            if character == "|" && precedingBackslashes.isMultiple(of: 2) {
                result.append("\\")
            }
            result.append(character)
            precedingBackslashes = character == "\\" ? precedingBackslashes + 1 : 0
        }
        return result
    }

    private static func singleLine(_ value: String) -> String {
        value.replacingOccurrences(of: "\r\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
    }

    private static func escapedText(_ value: String) -> String {
        let controls = "\\`*_{}[]<>#&~"
        return singleLine(value).reduce(into: "") { result, character in
            if controls.contains(character) { result.append("\\") }
            result.append(character)
        }
    }

    private static func escapedTable(_ value: String) -> String {
        escapedText(value).replacingOccurrences(of: "|", with: "\\|")
    }
}
