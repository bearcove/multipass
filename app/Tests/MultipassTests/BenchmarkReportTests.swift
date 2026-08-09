import Foundation
import Testing
@testable import Multipass

@Suite("Benchmark report")
struct BenchmarkReportTests {
    @Test("renders a deterministic complete Markdown report")
    func rendersCompleteMarkdownFixture() {
        let baseline = benchmarkRun(
            id: UUID(uuidString: "20000000-0000-0000-0000-000000000002")!,
            startedAt: Date(timeIntervalSince1970: 1_786_267_440),
            completedAt: Date(timeIntervalSince1970: 1_786_267_450),
            userLabel: "Known good",
            results: [
                wiredUploadID: .measured(benchmarkMeasurement(
                    id: wiredUploadID,
                    bitsPerSecond: 2_000_000_000,
                    retransmits: 4
                )),
                aggregateUploadID: .measured(benchmarkMeasurement(
                    id: aggregateUploadID,
                    bitsPerSecond: 3_000_000_000,
                    retransmits: 5,
                    members: [
                        "wired": benchmarkFinalResult(bitsPerSecond: 2_000_000_000),
                        "wifi": benchmarkFinalResult(bitsPerSecond: 1_000_000_000),
                    ]
                )),
                tunnelIPv4UploadID: .measured(benchmarkMeasurement(
                    id: tunnelIPv4UploadID,
                    bitsPerSecond: 2_000_000_000,
                    retransmits: 8
                )),
                tunnelIPv4DownloadID: .measured(benchmarkMeasurement(
                    id: tunnelIPv4DownloadID,
                    bitsPerSecond: 2_800_000_000,
                    retransmits: 1
                )),
            ]
        )
        let current = benchmarkRun(
            id: UUID(uuidString: "30000000-0000-0000-0000-000000000003")!,
            startedAt: Date(timeIntervalSince1970: 1_786_271_040),
            completedAt: Date(timeIntervalSince1970: 1_786_271_050),
            userLabel: "Desk after cable swap",
            results: [
                wiredUploadID: .measured(benchmarkMeasurement(
                    id: wiredUploadID,
                    bitsPerSecond: 2_500_000_000,
                    retransmits: 7
                )),
                wiredDownloadID: .failed("iperf listener refused connection"),
                wifiUploadID: .measured(benchmarkMeasurement(
                    id: wifiUploadID,
                    bitsPerSecond: 1_250_000_000,
                    retransmits: nil
                )),
                aggregateUploadID: .measured(benchmarkMeasurement(
                    id: aggregateUploadID,
                    bitsPerSecond: 3_750_000_000,
                    retransmits: 9,
                    members: [
                        "wired": benchmarkFinalResult(bitsPerSecond: 2_500_000_000),
                        "wifi": benchmarkFinalResult(bitsPerSecond: 1_250_000_000),
                    ]
                )),
                aggregateDownloadID: .failed("aggregate member wifi failed"),
                tunnelIPv4UploadID: .measured(benchmarkMeasurement(
                    id: tunnelIPv4UploadID,
                    bitsPerSecond: 3_000_000_000,
                    retransmits: 11
                )),
                tunnelIPv4DownloadID: .measured(benchmarkMeasurement(
                    id: tunnelIPv4DownloadID,
                    bitsPerSecond: 2_100_000_000,
                    retransmits: 2
                )),
                tunnelIPv6UploadID: .skipped("tunnel IPv6 target unavailable"),
                tunnelIPv6DownloadID: .skipped("tunnel IPv6 target unavailable"),
            ],
            restorationError: "Failed to restore the initial tunnel state: multipassd did not answer in time"
        )

        let report = BenchmarkReport.markdown(current: current, baseline: baseline)

        #expect(report == """
        # Multipass Benchmark Report

        - Run: Desk after cable swap (`30000000-0000-0000-0000-000000000003`)
        - Automatic label: 2026-08-09 10:24 · abc1234
        - Started: 2026-08-09T10:24:00Z
        - Completed: 2026-08-09T10:24:10Z
        - Baseline: Known good (`20000000-0000-0000-0000-000000000002`)
        - Initial tunnel state: disconnected

        ## Build identities

        | Component | Identity |
        | --- | --- |
        | App | `app-abc1234` |
        | Client/daemon | `client-def5678` |
        | Server | `server-abc1234` |
        | iperf | `iperf 3.21` |
        | Benchmark protocol | `2` |

        ## Topology

        - Underlay target: `10.10.10.1`
        - Tunnel IPv4 target: `10.10.99.1`
        - Tunnel IPv6 target: `fd00:99::1`
        - Listener ports: `5210–5225`
        - Physical paths:
          - Wired 10 GbE (`wired`): `en17`, `10.10.10.171`
          - Wi-Fi (`wifi`): `en0`, `10.10.10.169`

        ## Parameters

        - Protocol: TCP
        - Parallel streams: 4
        - Measured duration: 10 s
        - Omitted warmup: 3 s
        - Interval: 1 s
        - Connect timeout: 5 s

        ## Results

        | Measurement | Upload | Retransmits | Baseline delta | Download | Retransmits | Baseline delta |
        | --- | ---: | ---: | ---: | ---: | ---: | ---: |
        | Wired 10 GbE | 2.500 Gbit/s | 7 | +0.500 Gbit/s (+25.0%) | Failed: iperf listener refused connection | — | — |
        | Wi-Fi | 1.250 Gbit/s | — | — | Not run | — | — |
        | Raw aggregate | 3.750 Gbit/s | 9 | +0.750 Gbit/s (+25.0%) | Failed: aggregate member wifi failed | — | — |
        | Tunnel IPv4 | 3.000 Gbit/s | 11 | +1.000 Gbit/s (+50.0%) | 2.100 Gbit/s | 2 | −0.700 Gbit/s (−25.0%) |
        | Tunnel IPv6 | Skipped: tunnel IPv6 target unavailable | — | — | Skipped: tunnel IPv6 target unavailable | — | — |

        ## Tunnel efficiency

        | Family | Upload | Download |
        | --- | ---: | ---: |
        | IPv4 | 80.0% | — |
        | IPv6 | — | — |

        ## Run errors

        - Restoration: Failed to restore the initial tunnel state: multipassd did not answer in time
        """)
    }

    @Test("escapes hostile Markdown metadata by output context")
    func escapesHostileMarkdownMetadata() {
        let path = BenchmarkPath(
            id: "`path``id`|tail\r\nnext",
            displayName: "Path | row\r\n## forged `code` *em*",
            interface: " en`0`` ",
            sourceAddress: "a|b\r\nnext"
        )
        let uploadID = BenchmarkTestID(
            route: .physical(pathID: path.id),
            direction: .upload,
            addressFamily: .ipv4
        )
        let run = benchmarkRun(
            startedAt: Date(timeIntervalSince1970: 1_786_271_040),
            completedAt: Date(timeIntervalSince1970: 1_786_271_050),
            userLabel: "ok\n\n## forged | `label` *bold* [link](x) <tag> &copy; ~strike~ \\tail",
            identities: BenchmarkRunIdentities(
                appBuild: "`app`",
                clientBuild: "client ``build``",
                serverBuild: " leading and trailing ",
                iperfVersion: "iperf|3\r\n`bad`"
            ),
            topology: BenchmarkTopology(
                protocolVersion: 2,
                daemonVersion: "client ``build``",
                serverVersion: "server",
                underlayTarget: " underlay ",
                tunnelIPv4Target: "a`b",
                tunnelIPv6Target: "``edge",
                listenerBasePort: 5210,
                listenerCount: 16,
                paths: [path]
            ),
            results: [
                uploadID: .failed("bad|cell\r\nnext `code` **bold**")
            ],
            restorationError: "oops\r## forged\n`code` | *bold*"
        )

        let report = BenchmarkReport.markdown(current: run)

        #expect(report == """
        # Multipass Benchmark Report

        - Run: ok  \\#\\# forged | \\`label\\` \\*bold\\* \\[link\\](x) \\<tag\\> \\&copy; \\~strike\\~ \\\\tail (`10000000-0000-0000-0000-000000000001`)
        - Automatic label: 2026-08-09 10:24 · \\`app\\`
        - Started: 2026-08-09T10:24:00Z
        - Completed: 2026-08-09T10:24:10Z
        - Initial tunnel state: disconnected

        ## Build identities

        | Component | Identity |
        | --- | --- |
        | App | `` `app` `` |
        | Client/daemon | ``` client ``build`` ``` |
        | Server | `  leading and trailing  ` |
        | iperf | `` iperf\\|3 `bad` `` |
        | Benchmark protocol | `2` |

        ## Topology

        - Underlay target: `  underlay  `
        - Tunnel IPv4 target: ``a`b``
        - Tunnel IPv6 target: ``` ``edge ```
        - Listener ports: `5210–5225`
        - Physical paths:
          - Path | row \\#\\# forged \\`code\\` \\*em\\* (``` `path``id`|tail next ```): ```  en`0``  ```, `a|b next`

        ## Parameters

        - Protocol: TCP
        - Parallel streams: 4
        - Measured duration: 10 s
        - Omitted warmup: 3 s
        - Interval: 1 s
        - Connect timeout: 5 s

        ## Results

        | Measurement | Upload | Retransmits | Baseline delta | Download | Retransmits | Baseline delta |
        | --- | ---: | ---: | ---: | ---: | ---: | ---: |
        | Path \\| row \\#\\# forged \\`code\\` \\*em\\* | Failed: bad\\|cell next \\`code\\` \\*\\*bold\\*\\* | — | — | Not run | — | — |
        | Raw aggregate | Not run | — | — | Not run | — | — |
        | Tunnel IPv4 | Not run | — | — | Not run | — | — |
        | Tunnel IPv6 | Not run | — | — | Not run | — | — |

        ## Tunnel efficiency

        | Family | Upload | Download |
        | --- | ---: | ---: |
        | IPv4 | — | — |
        | IPv6 | — | — |

        ## Run errors

        - Restoration: oops \\#\\# forged \\`code\\` | \\*bold\\*
        """)
        #expect(!report.contains("\n## forged"))
        #expect(!report.contains("\n| forged"))
    }

    @Test("keeps hostile aggregate path IDs inside the delta table cell")
    func escapesAggregatePathSetMismatch() {
        let baselinePath = BenchmarkPath(
            id: "base|line\r\n## forged",
            displayName: "Baseline",
            interface: "en0",
            sourceAddress: "10.0.0.1"
        )
        let currentPath = BenchmarkPath(
            id: "current|line\n| forged",
            displayName: "Current",
            interface: "en1",
            sourceAddress: "10.0.0.2"
        )
        let baseline = benchmarkRun(
            topology: benchmarkTopology(paths: [baselinePath]),
            results: [
                aggregateUploadID: .measured(benchmarkMeasurement(
                    id: aggregateUploadID,
                    members: [baselinePath.id: benchmarkFinalResult()]
                ))
            ]
        )
        let current = benchmarkRun(
            topology: benchmarkTopology(paths: [currentPath]),
            results: [
                aggregateUploadID: .measured(benchmarkMeasurement(
                    id: aggregateUploadID,
                    members: [currentPath.id: benchmarkFinalResult()]
                ))
            ]
        )

        let report = BenchmarkReport.markdown(current: current, baseline: baseline)

        #expect(report.contains(
            "| Raw aggregate | 1.000 Gbit/s | 0 | Path set differs (current: current\\|line \\| forged; baseline: base\\|line \\#\\# forged) | Not run | — | — |"
        ))
        #expect(!report.contains("\n| forged"))
        #expect(!report.contains("\n## forged"))
    }

    @Test("renders empty code values without opening an unterminated span")
    func rendersEmptyCodeValues() {
        let path = BenchmarkPath(
            id: "",
            displayName: "Empty fields",
            interface: "",
            sourceAddress: ""
        )
        let run = benchmarkRun(
            identities: BenchmarkRunIdentities(
                appBuild: "",
                clientBuild: "",
                serverBuild: "",
                iperfVersion: ""
            ),
            topology: BenchmarkTopology(
                protocolVersion: 2,
                daemonVersion: "",
                serverVersion: "",
                underlayTarget: "",
                tunnelIPv4Target: "",
                tunnelIPv6Target: "",
                listenerBasePort: 5210,
                listenerCount: 16,
                paths: [path]
            ),
            results: [:]
        )

        let report = BenchmarkReport.markdown(current: run)

        #expect(report.contains("| App | `<empty>` |"))
        #expect(report.contains("- Underlay target: `<empty>`"))
        #expect(report.contains("- Empty fields (`<empty>`): `<empty>`, `<empty>`"))
        #expect(!report.contains("| App | `` |"))
    }

    @Test("keeps pipes escaped after existing backslashes in table code spans")
    func escapesBackslashPipeInTableCodeSpan() {
        let run = benchmarkRun(identities: BenchmarkRunIdentities(
            appBuild: "a\\|b",
            clientBuild: "client",
            serverBuild: "server",
            iperfVersion: "iperf"
        ))

        let report = BenchmarkReport.markdown(current: run)

        #expect(report.contains("| App | `a\\|b` |"))
        #expect(!report.contains("| App | `a\\\\|b` |"))
    }
}
