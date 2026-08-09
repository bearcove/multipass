import Darwin

nonisolated enum BenchmarkPlanner {
    static func plan(
        topology: BenchmarkTopology,
        parameters: BenchmarkParameters
    ) throws -> BenchmarkSuitePlan {
        guard parameters.isCanonical else {
            throw BenchmarkPlanningError.noncanonicalParameters
        }
        try validate(topology)

        var invocations: [BenchmarkInvocation] = []
        invocations.reserveCapacity(topology.paths.count * 2 + 6)

        for direction in [BenchmarkDirection.upload, .download] {
            for path in topology.paths {
                invocations.append(.single(
                    id: BenchmarkTestID(
                        route: .physical(pathID: path.id),
                        direction: direction,
                        addressFamily: .ipv4
                    ),
                    target: topology.underlayTarget,
                    port: topology.listenerBasePort,
                    sourceAddress: path.sourceAddress,
                    interface: path.interface
                ))
            }
        }

        for direction in [BenchmarkDirection.upload, .download] {
            let members = topology.paths.enumerated().map { index, path in
                BenchmarkInvocation.single(
                    id: BenchmarkTestID(
                        route: .physical(pathID: path.id),
                        direction: direction,
                        addressFamily: .ipv4,
                        execution: .simultaneousMember(pathID: path.id)
                    ),
                    target: topology.underlayTarget,
                    port: topology.listenerBasePort + UInt16(index),
                    sourceAddress: path.sourceAddress,
                    interface: path.interface
                )
            }
            invocations.append(.aggregate(
                id: BenchmarkTestID(
                    route: .physicalAggregate,
                    direction: direction,
                    addressFamily: .ipv4
                ),
                members: members
            ))
        }

        if let target = topology.tunnelIPv4Target {
            appendTunnelInvocations(
                to: &invocations,
                target: target,
                addressFamily: .ipv4,
                port: topology.listenerBasePort
            )
        }
        if let target = topology.tunnelIPv6Target {
            appendTunnelInvocations(
                to: &invocations,
                target: target,
                addressFamily: .ipv6,
                port: topology.listenerBasePort
            )
        }

        return BenchmarkSuitePlan(parameters: parameters, invocations: invocations)
    }

    private static func validate(_ topology: BenchmarkTopology) throws {
        guard !topology.paths.isEmpty else {
            throw BenchmarkPlanningError.emptyPaths
        }
        guard isAddress(topology.underlayTarget, family: .ipv4) else {
            throw BenchmarkPlanningError.invalidTarget(
                addressFamily: .ipv4,
                value: topology.underlayTarget
            )
        }
        if let target = topology.tunnelIPv4Target,
           !isAddress(target, family: .ipv4) {
            throw BenchmarkPlanningError.invalidTarget(
                addressFamily: .ipv4,
                value: target
            )
        }
        if let target = topology.tunnelIPv6Target,
           !isAddress(target, family: .ipv6) {
            throw BenchmarkPlanningError.invalidTarget(
                addressFamily: .ipv6,
                value: target
            )
        }


        var pathIDs: Set<String> = []
        pathIDs.reserveCapacity(topology.paths.count)
        for path in topology.paths {
            guard pathIDs.insert(path.id).inserted else {
                throw BenchmarkPlanningError.duplicatePathID(path.id)
            }
            guard isAddress(path.sourceAddress, family: .ipv4) else {
                throw BenchmarkPlanningError.invalidSourceAddress(
                    pathID: path.id,
                    value: path.sourceAddress
                )
            }
        }

        let listenerRangeEnd = UInt32(topology.listenerBasePort) + UInt32(topology.listenerCount)
        guard listenerRangeEnd <= UInt32(UInt16.max) + 1 else {
            throw BenchmarkPlanningError.listenerRangeOverflow(
                basePort: topology.listenerBasePort,
                count: topology.listenerCount
            )
        }

        guard Int(topology.listenerCount) >= topology.paths.count else {
            throw BenchmarkPlanningError.insufficientListeners(
                required: topology.paths.count,
                available: Int(topology.listenerCount)
            )
        }
    }

    private static func appendTunnelInvocations(
        to invocations: inout [BenchmarkInvocation],
        target: String,
        addressFamily: BenchmarkAddressFamily,
        port: UInt16
    ) {
        for direction in [BenchmarkDirection.upload, .download] {
            invocations.append(.single(
                id: BenchmarkTestID(
                    route: .tunnel,
                    direction: direction,
                    addressFamily: addressFamily
                ),
                target: target,
                port: port,
                sourceAddress: nil,
                interface: nil
            ))
        }
    }

    private static func isAddress(
        _ value: String,
        family: BenchmarkAddressFamily
    ) -> Bool {
        switch family {
        case .ipv4:
            var address = in_addr()
            return value.withCString { inet_pton(AF_INET, $0, &address) == 1 }
        case .ipv6:
            var address = in6_addr()
            return value.withCString { inet_pton(AF_INET6, $0, &address) == 1 }
        }
    }
}
