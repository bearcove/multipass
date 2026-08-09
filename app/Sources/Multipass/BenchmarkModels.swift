import Foundation

nonisolated enum BenchmarkProtocol: String, Codable, Sendable {
    case tcp
}

nonisolated struct BenchmarkParameters: Codable, Sendable, Equatable {
    let `protocol`: BenchmarkProtocol
    let parallelStreams: Int
    let measuredSeconds: Int
    let omittedSeconds: Int
    let intervalSeconds: Int
    let connectTimeoutSeconds: Int

    init() {
        self.protocol = .tcp
        self.parallelStreams = 4
        self.measuredSeconds = 10
        self.omittedSeconds = 3
        self.intervalSeconds = 1
        self.connectTimeoutSeconds = 5
    }

    var isCanonical: Bool {
        self == BenchmarkParameters()
    }
}

nonisolated enum BenchmarkDirection: String, Codable, Sendable {
    case upload
    case download
}

nonisolated enum BenchmarkAddressFamily: String, Codable, Sendable {
    case ipv4
    case ipv6
}

nonisolated enum BenchmarkRoute: Codable, Sendable, Hashable {
    case physical(pathID: String)
    case physicalAggregate
    case tunnel
}

nonisolated enum BenchmarkExecution: Codable, Sendable, Hashable {
    case single
    case simultaneousMember(pathID: String)
}

nonisolated struct BenchmarkTestID: Codable, Sendable, Hashable {
    let route: BenchmarkRoute
    let direction: BenchmarkDirection
    let addressFamily: BenchmarkAddressFamily
    let execution: BenchmarkExecution

    init(
        route: BenchmarkRoute,
        direction: BenchmarkDirection,
        addressFamily: BenchmarkAddressFamily,
        execution: BenchmarkExecution = .single
    ) {
        self.route = route
        self.direction = direction
        self.addressFamily = addressFamily
        self.execution = execution
    }
}

nonisolated enum BenchmarkInvocation: Codable, Sendable, Equatable {
    case single(
        id: BenchmarkTestID,
        target: String,
        port: UInt16,
        sourceAddress: String?,
        interface: String?
    )
    case aggregate(id: BenchmarkTestID, members: [BenchmarkInvocation])

    var id: BenchmarkTestID {
        switch self {
        case .single(let id, _, _, _, _), .aggregate(let id, _):
            id
        }
    }
}

nonisolated struct BenchmarkSuitePlan: Codable, Sendable, Equatable {
    let parameters: BenchmarkParameters
    let invocations: [BenchmarkInvocation]
}

nonisolated enum BenchmarkPlanningError: Error, Sendable, Equatable {
    case emptyPaths
    case duplicatePathID(String)
    case invalidSourceAddress(pathID: String, value: String)
    case invalidTarget(addressFamily: BenchmarkAddressFamily, value: String)
    case noncanonicalParameters
    case listenerRangeOverflow(basePort: UInt16, count: UInt16)
    case insufficientListeners(required: Int, available: Int)
}
