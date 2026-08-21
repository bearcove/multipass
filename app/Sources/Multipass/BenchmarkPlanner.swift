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
        let availablePaths = topology.paths.compactMap { path -> (BenchmarkPath, String)? in
            guard let sourceAddress = path.sourceAddress else { return nil }
            return (path, sourceAddress)
        }

        var invocations: [BenchmarkInvocation] = []
        invocations.reserveCapacity(availablePaths.count * 2 + 6)
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

        for (path, sourceAddress) in availablePaths {
            for direction in [BenchmarkDirection.upload, .download] {
                invocations.append(.single(
                    id: BenchmarkTestID(
                        route: .physical(pathID: path.id),
                        direction: direction,
                        addressFamily: .ipv4
                    ),
                    target: topology.underlayTarget,
                    port: topology.listenerBasePort,
                    sourceAddress: sourceAddress,
                    interface: path.interface
                ))
            }
        }

        if !availablePaths.isEmpty {
            for direction in [BenchmarkDirection.upload, .download] {
                let members = availablePaths.enumerated().map { index, available in
                    let (path, sourceAddress) = available
                    return BenchmarkInvocation.single(
                        id: BenchmarkTestID(
                            route: .physical(pathID: path.id),
                            direction: direction,
                            addressFamily: .ipv4,
                            execution: .simultaneousMember(pathID: path.id)
                        ),
                        target: topology.underlayTarget,
                        port: topology.listenerBasePort + UInt16(index),
                        sourceAddress: sourceAddress,
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
        }


        return BenchmarkSuitePlan(parameters: parameters, invocations: invocations)
    }

    private static func validate(_ topology: BenchmarkTopology) throws {
        guard !topology.paths.isEmpty || topology.tunnelIPv4Target != nil || topology.tunnelIPv6Target != nil else {
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
            if let sourceAddress = path.sourceAddress,
               !isAddress(sourceAddress, family: .ipv4) {
                throw BenchmarkPlanningError.invalidSourceAddress(
                    pathID: path.id,
                    value: sourceAddress
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

        let availablePathCount = topology.paths.lazy.filter { $0.sourceAddress != nil }.count
        guard Int(topology.listenerCount) >= availablePathCount else {
            throw BenchmarkPlanningError.insufficientListeners(
                required: availablePathCount,
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
