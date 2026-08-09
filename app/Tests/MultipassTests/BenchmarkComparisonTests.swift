import Foundation
import Testing
@testable import Multipass

@Suite("Benchmark comparison")
struct BenchmarkComparisonTests {
    @Test("computes literal signed throughput deltas")
    func computesSignedDeltas() {
        let baseline = benchmarkRun(results: [
            wiredUploadID: .measured(benchmarkMeasurement(id: wiredUploadID, bitsPerSecond: 2_000_000_000)),
            wiredDownloadID: .measured(benchmarkMeasurement(id: wiredDownloadID, bitsPerSecond: 4_000_000_000)),
        ])
        let current = benchmarkRun(results: [
            wiredUploadID: .measured(benchmarkMeasurement(id: wiredUploadID, bitsPerSecond: 2_500_000_000)),
            wiredDownloadID: .measured(benchmarkMeasurement(id: wiredDownloadID, bitsPerSecond: 3_000_000_000)),
        ])

        let comparison = BenchmarkComparison(current: current, baseline: baseline)

        #expect(comparison.results[wiredUploadID] == .comparable(BenchmarkDelta(
            absoluteBitsPerSecond: 500_000_000,
            percentage: 25
        )))
        #expect(comparison.results[wiredDownloadID] == .comparable(BenchmarkDelta(
            absoluteBitsPerSecond: -1_000_000_000,
            percentage: -25
        )))
        #expect(BenchmarkFormatting.signedGbitsPerSecond(500_000_000) == "+0.500 Gbit/s")
        #expect(BenchmarkFormatting.signedPercentage(-25) == "−25.0%")
    }

    @Test("omits percentage deltas when the baseline throughput is zero")
    func omitsPercentageForZeroBaseline() {
        let baseline = benchmarkRun(results: [
            wiredUploadID: .measured(benchmarkMeasurement(id: wiredUploadID, bitsPerSecond: 0)),
        ])
        let current = benchmarkRun(results: [
            wiredUploadID: .measured(benchmarkMeasurement(id: wiredUploadID, bitsPerSecond: 100_000_000)),
        ])

        #expect(BenchmarkComparison(current: current, baseline: baseline).results[wiredUploadID] == .unavailable)
    }

    @Test("marks all measurements incompatible when run identities differ")
    func rejectsIncompatibleRunIdentities() {
        let baseline = benchmarkRun(
            identities: BenchmarkRunIdentities(
                appBuild: "app-a",
                clientBuild: "client-a",
                serverBuild: "server-a",
                iperfVersion: "iperf 3.21"
            ),
            results: [wiredUploadID: .measured(benchmarkMeasurement(id: wiredUploadID))]
        )
        let current = benchmarkRun(
            identities: BenchmarkRunIdentities(
                appBuild: "app-b",
                clientBuild: "client-a",
                serverBuild: "server-a",
                iperfVersion: "iperf 3.21"
            ),
            results: [wiredUploadID: .measured(benchmarkMeasurement(id: wiredUploadID))]
        )

        let comparison = BenchmarkComparison(current: current, baseline: baseline)

        #expect(comparison.compatibility == .incompatibleIdentities([
            .appBuild(current: "app-b", baseline: "app-a")
        ]))
        #expect(comparison.results[wiredUploadID] == .incompatibleRun)
    }

    @Test("matches physical measurements by stable path ID rather than topology order")
    func matchesPhysicalMeasurementsByPathID() {
        let baseline = benchmarkRun(
            topology: benchmarkTopology(paths: [benchmarkWiredPath, benchmarkWiFiPath]),
            results: [wiredUploadID: .measured(benchmarkMeasurement(id: wiredUploadID, bitsPerSecond: 1_000_000_000))]
        )
        let current = benchmarkRun(
            topology: benchmarkTopology(paths: [benchmarkWiFiPath, benchmarkWiredPath]),
            results: [wiredUploadID: .measured(benchmarkMeasurement(id: wiredUploadID, bitsPerSecond: 1_100_000_000))]
        )

        let comparison = BenchmarkComparison(current: current, baseline: baseline)

        #expect(comparison.results[wiredUploadID] == .comparable(BenchmarkDelta(
            absoluteBitsPerSecond: 100_000_000,
            percentage: 10
        )))
    }

    @Test("annotates aggregate path-set mismatches but still compares tunnel results")
    func annotatesAggregatePathSetMismatch() {
        let baseline = benchmarkRun(
            topology: benchmarkTopology(paths: [benchmarkWiredPath, benchmarkWiFiPath]),
            results: [
                aggregateUploadID: .measured(benchmarkMeasurement(
                    id: aggregateUploadID,
                    bitsPerSecond: 3_000_000_000,
                    members: [
                        "wired": benchmarkFinalResult(bitsPerSecond: 2_000_000_000),
                        "wifi": benchmarkFinalResult(bitsPerSecond: 1_000_000_000),
                    ]
                )),
                tunnelIPv4UploadID: .measured(benchmarkMeasurement(
                    id: tunnelIPv4UploadID,
                    bitsPerSecond: 2_000_000_000
                )),
            ]
        )
        let current = benchmarkRun(
            topology: benchmarkTopology(paths: [benchmarkWiredPath]),
            results: [
                aggregateUploadID: .measured(benchmarkMeasurement(
                    id: aggregateUploadID,
                    bitsPerSecond: 2_500_000_000,
                    members: ["wired": benchmarkFinalResult(bitsPerSecond: 2_500_000_000)]
                )),
                tunnelIPv4UploadID: .measured(benchmarkMeasurement(
                    id: tunnelIPv4UploadID,
                    bitsPerSecond: 2_200_000_000
                )),
            ]
        )

        let comparison = BenchmarkComparison(current: current, baseline: baseline)

        #expect(comparison.results[aggregateUploadID] == .aggregatePathSetMismatch(
            current: ["wired"],
            baseline: ["wifi", "wired"]
        ))
        #expect(comparison.results[tunnelIPv4UploadID] == .comparable(BenchmarkDelta(
            absoluteBitsPerSecond: 200_000_000,
            percentage: 10
        )))
    }

    @Test("omits deltas when either result failed or is absent")
    func omitsDeltasAcrossFailureGaps() {
        let baseline = benchmarkRun(results: [
            wiredUploadID: .failed("baseline failed"),
            wiredDownloadID: .measured(benchmarkMeasurement(id: wiredDownloadID)),
        ])
        let current = benchmarkRun(results: [
            wiredUploadID: .measured(benchmarkMeasurement(id: wiredUploadID)),
            wiredDownloadID: .failed("current failed"),
            wifiUploadID: .measured(benchmarkMeasurement(id: wifiUploadID)),
        ])

        let comparison = BenchmarkComparison(current: current, baseline: baseline)

        #expect(comparison.results[wiredUploadID] == .unavailable)
        #expect(comparison.results[wiredDownloadID] == .unavailable)
        #expect(comparison.results[wifiUploadID] == .unavailable)
    }

    @Test("derives tunnel efficiency only from successful matching directions")
    func derivesTunnelEfficiency() {
        let run = benchmarkRun(results: [
            aggregateUploadID: .measured(benchmarkMeasurement(
                id: aggregateUploadID,
                bitsPerSecond: 4_000_000_000,
                members: ["wired": benchmarkFinalResult(bitsPerSecond: 4_000_000_000)]
            )),
            tunnelIPv4UploadID: .measured(benchmarkMeasurement(
                id: tunnelIPv4UploadID,
                bitsPerSecond: 3_000_000_000
            )),
            aggregateDownloadID: .failed("raw failed"),
            tunnelIPv4DownloadID: .measured(benchmarkMeasurement(
                id: tunnelIPv4DownloadID,
                bitsPerSecond: 3_000_000_000
            )),
        ])

        #expect(BenchmarkComparison.efficiency(
            in: run,
            addressFamily: .ipv4,
            direction: .upload
        ) == 75)
        #expect(BenchmarkComparison.efficiency(
            in: run,
            addressFamily: .ipv4,
            direction: .download
        ) == nil)
    }
}
