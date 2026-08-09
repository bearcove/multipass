import Foundation

nonisolated struct BenchmarkDelta: Sendable, Equatable {
    let absoluteBitsPerSecond: Double
    let percentage: Double
}

nonisolated enum BenchmarkIdentityMismatch: Sendable, Equatable {
    case appBuild(current: String, baseline: String)
    case clientBuild(current: String, baseline: String)
    case serverBuild(current: String, baseline: String)
    case iperfVersion(current: String, baseline: String)
    case benchmarkProtocol(current: UInt32, baseline: UInt32)
    case parameters(current: BenchmarkParameters, baseline: BenchmarkParameters)
}

nonisolated enum BenchmarkRunCompatibility: Sendable, Equatable {
    case compatible
    case incompatibleIdentities([BenchmarkIdentityMismatch])
}

nonisolated enum BenchmarkResultComparison: Sendable, Equatable {
    case comparable(BenchmarkDelta)
    case unavailable
    case incompatibleRun
    case aggregatePathSetMismatch(current: [String], baseline: [String])
}

nonisolated struct BenchmarkComparison: Sendable, Equatable {
    let compatibility: BenchmarkRunCompatibility
    let results: [BenchmarkTestID: BenchmarkResultComparison]

    init(current: BenchmarkRun, baseline: BenchmarkRun) {
        let mismatches = Self.identityMismatches(current: current, baseline: baseline)
        if !mismatches.isEmpty {
            compatibility = .incompatibleIdentities(mismatches)
            results = Dictionary(
                uniqueKeysWithValues: current.results.keys.map { ($0, .incompatibleRun) }
            )
            return
        }

        compatibility = .compatible
        var comparisons: [BenchmarkTestID: BenchmarkResultComparison] = [:]
        for (id, currentResult) in current.results {
            guard let currentMeasurement = currentResult.measurement?.result,
                  let baselineMeasurement = baseline.results[id]?.measurement?.result else {
                comparisons[id] = .unavailable
                continue
            }
            if id.route == .physicalAggregate {
                let currentPaths = current.results[id]?.measurement?.members.keys.sorted() ?? []
                let baselinePaths = baseline.results[id]?.measurement?.members.keys.sorted() ?? []
                guard currentPaths == baselinePaths else {
                    comparisons[id] = .aggregatePathSetMismatch(
                        current: currentPaths,
                        baseline: baselinePaths
                    )
                    continue
                }
            }
            guard baselineMeasurement.bitsPerSecond != 0 else {
                comparisons[id] = .unavailable
                continue
            }
            let absolute = currentMeasurement.bitsPerSecond - baselineMeasurement.bitsPerSecond
            let percentage = absolute / baselineMeasurement.bitsPerSecond * 100
            comparisons[id] = .comparable(BenchmarkDelta(
                absoluteBitsPerSecond: absolute,
                percentage: percentage
            ))
        }
        results = comparisons
    }

    static func efficiency(
        in run: BenchmarkRun,
        addressFamily: BenchmarkAddressFamily,
        direction: BenchmarkDirection
    ) -> Double? {
        let aggregateID = BenchmarkTestID(
            route: .physicalAggregate,
            direction: direction,
            addressFamily: .ipv4
        )
        let tunnelID = BenchmarkTestID(
            route: .tunnel,
            direction: direction,
            addressFamily: addressFamily
        )
        guard let aggregate = run.results[aggregateID]?.measurement?.result?.bitsPerSecond,
              aggregate > 0,
              let tunnel = run.results[tunnelID]?.measurement?.result?.bitsPerSecond else {
            return nil
        }
        return tunnel / aggregate * 100
    }

    private static func identityMismatches(
        current: BenchmarkRun,
        baseline: BenchmarkRun
    ) -> [BenchmarkIdentityMismatch] {
        var mismatches: [BenchmarkIdentityMismatch] = []
        if current.identities.appBuild != baseline.identities.appBuild {
            mismatches.append(.appBuild(
                current: current.identities.appBuild,
                baseline: baseline.identities.appBuild
            ))
        }
        if current.identities.clientBuild != baseline.identities.clientBuild {
            mismatches.append(.clientBuild(
                current: current.identities.clientBuild,
                baseline: baseline.identities.clientBuild
            ))
        }
        if current.identities.serverBuild != baseline.identities.serverBuild {
            mismatches.append(.serverBuild(
                current: current.identities.serverBuild,
                baseline: baseline.identities.serverBuild
            ))
        }
        if current.identities.iperfVersion != baseline.identities.iperfVersion {
            mismatches.append(.iperfVersion(
                current: current.identities.iperfVersion,
                baseline: baseline.identities.iperfVersion
            ))
        }
        if current.topology.protocolVersion != baseline.topology.protocolVersion {
            mismatches.append(.benchmarkProtocol(
                current: current.topology.protocolVersion,
                baseline: baseline.topology.protocolVersion
            ))
        }
        if current.parameters != baseline.parameters {
            mismatches.append(.parameters(
                current: current.parameters,
                baseline: baseline.parameters
            ))
        }
        return mismatches
    }
}

nonisolated enum BenchmarkFormatting {
    private static let reportTimeZone = TimeZone(secondsFromGMT: 0)!
    private static let labelCalendar = Calendar(identifier: .gregorian)

    static func gbitsPerSecond(_ bitsPerSecond: Double) -> String {
        fixed(bitsPerSecond / 1_000_000_000, places: 3) + " Gbit/s"
    }

    static func signedGbitsPerSecond(_ bitsPerSecond: Double) -> String {
        let value = bitsPerSecond / 1_000_000_000
        let sign = value < 0 ? "−" : "+"
        return sign + fixed(abs(value), places: 3) + " Gbit/s"
    }

    static func percentage(_ value: Double) -> String {
        fixed(value, places: 1) + "%"
    }

    static func signedPercentage(_ value: Double) -> String {
        let sign = value < 0 ? "−" : "+"
        return sign + fixed(abs(value), places: 1) + "%"
    }
    static func iso8601(_ date: Date) -> String {
        ISO8601DateFormatter.string(from: date, timeZone: reportTimeZone, formatOptions: [.withInternetDateTime])
    }
    static func automaticLabel(for run: BenchmarkRun) -> String {
        automaticLabel(for: run, timeZone: .current)
    }

    private static func automaticLabel(for run: BenchmarkRun, timeZone: TimeZone) -> String {
        var calendar = labelCalendar
        calendar.timeZone = timeZone
        let components = calendar.dateComponents([.year, .month, .day, .hour, .minute], from: run.startedAt)
        let date = String(
            format: "%04d-%02d-%02d %02d:%02d",
            components.year ?? 0,
            components.month ?? 0,
            components.day ?? 0,
            components.hour ?? 0,
            components.minute ?? 0
        )
        return "\(date) · \(shortIdentity(run.identities.appBuild))"
    }

    static func reportAutomaticLabel(for run: BenchmarkRun) -> String {
        automaticLabel(for: run, timeZone: reportTimeZone)
    }

    static func displayLabel(for run: BenchmarkRun) -> String {
        run.userLabel ?? automaticLabel(for: run)
    }

    private static func shortIdentity(_ identity: String) -> String {
        let suffix = identity.split(separator: "-", omittingEmptySubsequences: true).last.map(String.init) ?? identity
        return String(suffix.prefix(7))
    }

    private static func fixed(_ value: Double, places: Int) -> String {
        String(format: "%.*f", locale: Locale(identifier: "en_US_POSIX"), places, value)
    }
}
