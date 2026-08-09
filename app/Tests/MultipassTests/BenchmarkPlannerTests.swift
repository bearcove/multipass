import Foundation
import Testing
@testable import Multipass

@Suite("Benchmark planner")
struct BenchmarkPlannerTests {
    @Test("plans one physical path and both tunnel families")
    func plansOnePhysicalPath() throws {
        let plan = try BenchmarkPlanner.plan(
            topology: topology(paths: [wired]),
            parameters: .init()
        )

        #expect(plan == BenchmarkSuitePlan(
            parameters: .init(),
            invocations: [
                single(
                    id: .init(route: .physical(pathID: "wired"), direction: .upload, addressFamily: .ipv4),
                    target: "10.10.10.1",
                    port: 5210,
                    sourceAddress: "10.10.10.171",
                    interface: "en17"
                ),
                single(
                    id: .init(route: .physical(pathID: "wired"), direction: .download, addressFamily: .ipv4),
                    target: "10.10.10.1",
                    port: 5210,
                    sourceAddress: "10.10.10.171",
                    interface: "en17"
                ),
                aggregate(
                    direction: .upload,
                    members: [
                        member(path: wired, direction: .upload, port: 5210),
                    ]
                ),
                aggregate(
                    direction: .download,
                    members: [
                        member(path: wired, direction: .download, port: 5210),
                    ]
                ),
                tunnel(addressFamily: .ipv4, direction: .upload, target: "10.10.99.1"),
                tunnel(addressFamily: .ipv4, direction: .download, target: "10.10.99.1"),
                tunnel(addressFamily: .ipv6, direction: .upload, target: "fd00:99::1"),
                tunnel(addressFamily: .ipv6, direction: .download, target: "fd00:99::1"),
            ]
        ))
    }

    @Test("plans two paths in the required literal order")
    func plansWiredAndWiFiInExactOrder() throws {
        let plan = try BenchmarkPlanner.plan(
            topology: topology(paths: [wired, wifi]),
            parameters: .init()
        )

        #expect(plan.invocations == [
            single(
                id: .init(route: .physical(pathID: "wired"), direction: .upload, addressFamily: .ipv4),
                target: "10.10.10.1",
                port: 5210,
                sourceAddress: "10.10.10.171",
                interface: "en17"
            ),
            single(
                id: .init(route: .physical(pathID: "wifi"), direction: .upload, addressFamily: .ipv4),
                target: "10.10.10.1",
                port: 5210,
                sourceAddress: "10.10.10.169",
                interface: "en0"
            ),
            single(
                id: .init(route: .physical(pathID: "wired"), direction: .download, addressFamily: .ipv4),
                target: "10.10.10.1",
                port: 5210,
                sourceAddress: "10.10.10.171",
                interface: "en17"
            ),
            single(
                id: .init(route: .physical(pathID: "wifi"), direction: .download, addressFamily: .ipv4),
                target: "10.10.10.1",
                port: 5210,
                sourceAddress: "10.10.10.169",
                interface: "en0"
            ),
            aggregate(
                direction: .upload,
                members: [
                    member(path: wired, direction: .upload, port: 5210),
                    member(path: wifi, direction: .upload, port: 5211),
                ]
            ),
            aggregate(
                direction: .download,
                members: [
                    member(path: wired, direction: .download, port: 5210),
                    member(path: wifi, direction: .download, port: 5211),
                ]
            ),
            tunnel(addressFamily: .ipv4, direction: .upload, target: "10.10.99.1"),
            tunnel(addressFamily: .ipv4, direction: .download, target: "10.10.99.1"),
            tunnel(addressFamily: .ipv6, direction: .upload, target: "fd00:99::1"),
            tunnel(addressFamily: .ipv6, direction: .download, target: "fd00:99::1"),
        ])
    }

    @Test("plans four aggregate members with distinct listener ports")
    func plansFourPaths() throws {
        let paths = [
            wired,
            wifi,
            BenchmarkPath(id: "usb", displayName: "USB", interface: "en8", sourceAddress: "10.10.10.172"),
            BenchmarkPath(id: "cellular", displayName: "Cellular", interface: "en9", sourceAddress: "10.10.10.173"),
        ]

        let plan = try BenchmarkPlanner.plan(
            topology: topology(listenerCount: 4, paths: paths),
            parameters: .init()
        )

        #expect(plan.invocations.count == 14)
        #expect(plan.invocations[8] == aggregate(
            direction: .upload,
            members: [
                member(path: paths[0], direction: .upload, port: 5210),
                member(path: paths[1], direction: .upload, port: 5211),
                member(path: paths[2], direction: .upload, port: 5212),
                member(path: paths[3], direction: .upload, port: 5213),
            ]
        ))
        #expect(plan.invocations[9] == aggregate(
            direction: .download,
            members: [
                member(path: paths[0], direction: .download, port: 5210),
                member(path: paths[1], direction: .download, port: 5211),
                member(path: paths[2], direction: .download, port: 5212),
                member(path: paths[3], direction: .download, port: 5213),
            ]
        ))
    }

    @Test("omits only the absent tunnel IPv6 family")
    func omitsAbsentTunnelIPv6Target() throws {
        let plan = try BenchmarkPlanner.plan(
            topology: topology(tunnelIPv6Target: nil, paths: [wired]),
            parameters: .init()
        )

        #expect(plan.invocations.map(\.id) == [
            .init(route: .physical(pathID: "wired"), direction: .upload, addressFamily: .ipv4),
            .init(route: .physical(pathID: "wired"), direction: .download, addressFamily: .ipv4),
            .init(route: .physicalAggregate, direction: .upload, addressFamily: .ipv4),
            .init(route: .physicalAggregate, direction: .download, addressFamily: .ipv4),
            .init(route: .tunnel, direction: .upload, addressFamily: .ipv4),
            .init(route: .tunnel, direction: .download, addressFamily: .ipv4),
        ])
    }

    @Test("omits only the absent tunnel IPv4 family")
    func omitsAbsentTunnelIPv4Target() throws {
        let plan = try BenchmarkPlanner.plan(
            topology: topology(tunnelIPv4Target: nil, paths: [wired]),
            parameters: .init()
        )

        #expect(plan.invocations.map(\.id) == [
            .init(route: .physical(pathID: "wired"), direction: .upload, addressFamily: .ipv4),
            .init(route: .physical(pathID: "wired"), direction: .download, addressFamily: .ipv4),
            .init(route: .physicalAggregate, direction: .upload, addressFamily: .ipv4),
            .init(route: .physicalAggregate, direction: .download, addressFamily: .ipv4),
            .init(route: .tunnel, direction: .upload, addressFamily: .ipv6),
            .init(route: .tunnel, direction: .download, addressFamily: .ipv6),
        ])
    }

    @Test("rejects insufficient listener count for simultaneous members")
    func rejectsInsufficientListenerCount() {
        #expect(throws: BenchmarkPlanningError.insufficientListeners(required: 2, available: 1)) {
            try BenchmarkPlanner.plan(
                topology: topology(listenerCount: 1, paths: [wired, wifi]),
                parameters: .init()
            )
        }
    }

    @Test("physical IDs and aggregate member IDs are stable across path reordering")
    func stableIDsDoNotEncodePathArrayIndexes() throws {
        let first = try BenchmarkPlanner.plan(
            topology: topology(paths: [wired, wifi]),
            parameters: .init()
        )
        let reordered = try BenchmarkPlanner.plan(
            topology: topology(paths: [wifi, wired]),
            parameters: .init()
        )

        #expect(Set(first.invocations.map(\.id)) == Set(reordered.invocations.map(\.id)))
        #expect(Set(aggregateMemberIDs(in: first)) == Set(aggregateMemberIDs(in: reordered)))
    }

    @Test("rejects an empty physical path list")
    func rejectsEmptyPaths() {
        #expect(throws: BenchmarkPlanningError.emptyPaths) {
            try BenchmarkPlanner.plan(topology: topology(paths: []), parameters: .init())
        }
    }

    @Test("rejects duplicate stable path IDs")
    func rejectsDuplicatePathIDs() {
        let duplicate = BenchmarkPath(
            id: wired.id,
            displayName: "Duplicate Wired",
            interface: "en18",
            sourceAddress: "10.10.10.172"
        )

        #expect(throws: BenchmarkPlanningError.duplicatePathID("wired")) {
            try BenchmarkPlanner.plan(
                topology: topology(paths: [wired, duplicate]),
                parameters: .init()
            )
        }
    }

    @Test(arguments: ["", "not an address", "999.10.10.10", "fd00:99::2"])
    func rejectsMissingOrInvalidPhysicalIPv4SourceAddress(sourceAddress: String) {
        let invalid = BenchmarkPath(
            id: "invalid",
            displayName: "Invalid",
            interface: "en7",
            sourceAddress: sourceAddress
        )

        #expect(throws: BenchmarkPlanningError.invalidSourceAddress(pathID: "invalid", value: sourceAddress)) {
            try BenchmarkPlanner.plan(
                topology: topology(paths: [invalid]),
                parameters: .init()
            )
        }
    }

    @Test("rejects an invalid underlay target")
    func rejectsInvalidUnderlayTarget() {
        #expect(throws: BenchmarkPlanningError.invalidTarget(
            addressFamily: .ipv4,
            value: "not an address"
        )) {
            try BenchmarkPlanner.plan(
                topology: topology(underlayTarget: "not an address", paths: [wired]),
                parameters: .init()
            )
        }
    }

    @Test("rejects present tunnel targets that do not match their family")
    func rejectsInvalidTunnelTargets() {
        #expect(throws: BenchmarkPlanningError.invalidTarget(
            addressFamily: .ipv4,
            value: "fd00:99::1"
        )) {
            try BenchmarkPlanner.plan(
                topology: topology(tunnelIPv4Target: "fd00:99::1", paths: [wired]),
                parameters: .init()
            )
        }

        #expect(throws: BenchmarkPlanningError.invalidTarget(
            addressFamily: .ipv6,
            value: "10.10.99.1"
        )) {
            try BenchmarkPlanner.plan(
                topology: topology(tunnelIPv6Target: "10.10.99.1", paths: [wired]),
                parameters: .init()
            )
        }
    }

    @Test("rejects a listener range that overflows UInt16")
    func rejectsListenerRangeOverflow() {
        #expect(throws: BenchmarkPlanningError.listenerRangeOverflow(basePort: 65_535, count: 2)) {
            try BenchmarkPlanner.plan(
                topology: topology(listenerBasePort: 65_535, listenerCount: 2, paths: [wired]),
                parameters: .init()
            )
        }
    }

    @Test("rejects decoded noncanonical full-suite parameters")
    func rejectsDecodedNoncanonicalParameters() throws {
        let data = Data("""
            {
              "protocol": "tcp",
              "parallelStreams": 8,
              "measuredSeconds": 10,
              "omittedSeconds": 3,
              "intervalSeconds": 1,
              "connectTimeoutSeconds": 5
            }
            """.utf8)
        let parameters = try JSONDecoder().decode(BenchmarkParameters.self, from: data)

        #expect(throws: BenchmarkPlanningError.noncanonicalParameters) {
            try BenchmarkPlanner.plan(
                topology: topology(paths: [wired]),
                parameters: parameters
            )
        }
    }

    @Test("fixed parameters round-trip through Codable")
    func parametersRoundTripThroughCodable() throws {
        let parameters = BenchmarkParameters()
        let data = try JSONEncoder().encode(parameters)
        let decoded = try JSONDecoder().decode(BenchmarkParameters.self, from: data)

        #expect(decoded == parameters)
        #expect(decoded.protocol == .tcp)
        #expect(decoded.parallelStreams == 4)
        #expect(decoded.measuredSeconds == 10)
        #expect(decoded.omittedSeconds == 3)
        #expect(decoded.intervalSeconds == 1)
        #expect(decoded.connectTimeoutSeconds == 5)
    }
}

private let wired = BenchmarkPath(
    id: "wired",
    displayName: "Wired",
    interface: "en17",
    sourceAddress: "10.10.10.171"
)

private let wifi = BenchmarkPath(
    id: "wifi",
    displayName: "Wi-Fi",
    interface: "en0",
    sourceAddress: "10.10.10.169"
)

private func topology(
    underlayTarget: String = "10.10.10.1",
    tunnelIPv4Target: String? = "10.10.99.1",
    tunnelIPv6Target: String? = "fd00:99::1",
    listenerBasePort: UInt16 = 5210,
    listenerCount: UInt16 = 16,
    paths: [BenchmarkPath]
) -> BenchmarkTopology {
    BenchmarkTopology(
        protocolVersion: 2,
        daemonVersion: "daemon-build",
        serverVersion: "server-build",
        underlayTarget: underlayTarget,
        tunnelIPv4Target: tunnelIPv4Target,
        tunnelIPv6Target: tunnelIPv6Target,
        listenerBasePort: listenerBasePort,
        listenerCount: listenerCount,
        paths: paths
    )
}

private func single(
    id: BenchmarkTestID,
    target: String,
    port: UInt16,
    sourceAddress: String?,
    interface: String?
) -> BenchmarkInvocation {
    .single(
        id: id,
        target: target,
        port: port,
        sourceAddress: sourceAddress,
        interface: interface
    )
}

private func member(
    path: BenchmarkPath,
    direction: BenchmarkDirection,
    port: UInt16
) -> BenchmarkInvocation {
    single(
        id: .init(
            route: .physical(pathID: path.id),
            direction: direction,
            addressFamily: .ipv4,
            execution: .simultaneousMember(pathID: path.id)
        ),
        target: "10.10.10.1",
        port: port,
        sourceAddress: path.sourceAddress,
        interface: path.interface
    )
}

private func aggregate(
    direction: BenchmarkDirection,
    members: [BenchmarkInvocation]
) -> BenchmarkInvocation {
    .aggregate(
        id: .init(route: .physicalAggregate, direction: direction, addressFamily: .ipv4),
        members: members
    )
}

private func tunnel(
    addressFamily: BenchmarkAddressFamily,
    direction: BenchmarkDirection,
    target: String
) -> BenchmarkInvocation {
    single(
        id: .init(route: .tunnel, direction: direction, addressFamily: addressFamily),
        target: target,
        port: 5210,
        sourceAddress: nil,
        interface: nil
    )
}

private func aggregateMemberIDs(in plan: BenchmarkSuitePlan) -> [BenchmarkTestID] {
    plan.invocations.flatMap { invocation -> [BenchmarkTestID] in
        switch invocation {
        case .single:
            return []
        case .aggregate(_, let members):
            return members.map(\.id)
        }
    }
}
