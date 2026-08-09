import Foundation
@testable import Multipass

let benchmarkWiredPath = BenchmarkPath(
    id: "wired",
    displayName: "Wired 10 GbE",
    interface: "en17",
    sourceAddress: "10.10.10.171"
)

let benchmarkWiFiPath = BenchmarkPath(
    id: "wifi",
    displayName: "Wi-Fi",
    interface: "en0",
    sourceAddress: "10.10.10.169"
)

let wiredUploadID = BenchmarkTestID(
    route: .physical(pathID: "wired"),
    direction: .upload,
    addressFamily: .ipv4
)
let wiredDownloadID = BenchmarkTestID(
    route: .physical(pathID: "wired"),
    direction: .download,
    addressFamily: .ipv4
)
let wifiUploadID = BenchmarkTestID(
    route: .physical(pathID: "wifi"),
    direction: .upload,
    addressFamily: .ipv4
)
let wifiDownloadID = BenchmarkTestID(
    route: .physical(pathID: "wifi"),
    direction: .download,
    addressFamily: .ipv4
)
let aggregateUploadID = BenchmarkTestID(
    route: .physicalAggregate,
    direction: .upload,
    addressFamily: .ipv4
)
let aggregateDownloadID = BenchmarkTestID(
    route: .physicalAggregate,
    direction: .download,
    addressFamily: .ipv4
)
let tunnelIPv4UploadID = BenchmarkTestID(
    route: .tunnel,
    direction: .upload,
    addressFamily: .ipv4
)
let tunnelIPv4DownloadID = BenchmarkTestID(
    route: .tunnel,
    direction: .download,
    addressFamily: .ipv4
)
let tunnelIPv6UploadID = BenchmarkTestID(
    route: .tunnel,
    direction: .upload,
    addressFamily: .ipv6
)
let tunnelIPv6DownloadID = BenchmarkTestID(
    route: .tunnel,
    direction: .download,
    addressFamily: .ipv6
)

func benchmarkTopology(
    paths: [BenchmarkPath] = [benchmarkWiredPath, benchmarkWiFiPath]
) -> BenchmarkTopology {
    BenchmarkTopology(
        protocolVersion: 1,
        serverVersion: "server-abc1234",
        underlayTarget: "10.10.10.1",
        tunnelIPv4Target: "10.10.99.1",
        tunnelIPv6Target: "fd00:99::1",
        listenerBasePort: 5210,
        listenerCount: 16,
        paths: paths
    )
}

func benchmarkFinalResult(
    bitsPerSecond: Double = 1_000_000_000,
    retransmits: UInt64? = 0,
    rawFinalLine: String = "{\"event\":\"end\"}"
) -> IperfFinalResult {
    IperfFinalResult(
        bitsPerSecond: bitsPerSecond,
        bytes: UInt64(bitsPerSecond / 8),
        retransmits: retransmits,
        streamCount: 4,
        meanRTTMicroseconds: 1_000,
        maximumRTTMicroseconds: 2_000,
        throughputRole: .receiver,
        startSeconds: 0,
        endSeconds: 10,
        rawFinalLine: rawFinalLine
    )
}

func benchmarkMeasurement(
    id: BenchmarkTestID,
    bitsPerSecond: Double = 1_000_000_000,
    retransmits: UInt64? = 0,
    rawFinalLine: String = "{\"event\":\"end\"}",
    members: [String: IperfFinalResult] = [:]
) -> BenchmarkMeasurement {
    BenchmarkMeasurement(
        id: id,
        result: benchmarkFinalResult(
            bitsPerSecond: bitsPerSecond,
            retransmits: retransmits,
            rawFinalLine: rawFinalLine
        ),
        diagnostics: IperfProcessDiagnostics(
            stderr: "",
            warnings: [],
            terminationStatus: 0,
            wasForceKilled: false
        ),
        members: members
    )
}

func benchmarkRun(
    id: UUID = UUID(uuidString: "10000000-0000-0000-0000-000000000001")!,
    startedAt: Date = Date(timeIntervalSince1970: 1_786_271_040),
    completedAt: Date = Date(timeIntervalSince1970: 1_786_271_050),
    userLabel: String? = nil,
    identities: BenchmarkRunIdentities = BenchmarkRunIdentities(
        appBuild: "app-abc1234",
        clientBuild: "client-def5678",
        serverBuild: "server-abc1234",
        iperfVersion: "iperf 3.21"
    ),
    topology: BenchmarkTopology = benchmarkTopology(),
    parameters: BenchmarkParameters = .init(),
    initiallyConnected: Bool = false,
    results: [BenchmarkTestID: BenchmarkResult]? = nil,
    restorationError: String? = nil
) -> BenchmarkRun {
    let defaultResults: [BenchmarkTestID: BenchmarkResult] = [
        wiredUploadID: .measured(benchmarkMeasurement(id: wiredUploadID, bitsPerSecond: 2_000_000_000)),
        aggregateUploadID: .measured(benchmarkMeasurement(
            id: aggregateUploadID,
            bitsPerSecond: 3_000_000_000,
            rawFinalLine: "{\"event\":\"end\",\"aggregate\":true}",
            members: [
                "wired": benchmarkFinalResult(
                    bitsPerSecond: 2_000_000_000,
                    rawFinalLine: "{\"event\":\"end\",\"member\":\"wired\"}"
                ),
                "wifi": benchmarkFinalResult(
                    bitsPerSecond: 1_000_000_000,
                    rawFinalLine: "{\"event\":\"end\",\"member\":\"wifi\"}"
                ),
            ]
        )),
        tunnelIPv4UploadID: .measured(benchmarkMeasurement(
            id: tunnelIPv4UploadID,
            bitsPerSecond: 2_400_000_000
        )),
    ]
    return BenchmarkRun(
        id: id,
        startedAt: startedAt,
        completedAt: completedAt,
        userLabel: userLabel,
        identities: identities,
        topology: topology,
        parameters: parameters,
        initiallyConnected: initiallyConnected,
        results: results ?? defaultResults,
        restorationError: restorationError
    )
}
