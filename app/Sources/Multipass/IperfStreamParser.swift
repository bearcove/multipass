import Foundation

nonisolated enum IperfThroughputRole: String, Codable, Sendable, Equatable {
    case receiver
}

nonisolated struct IperfFinalResult: Codable, Sendable, Equatable {
    let bitsPerSecond: Double
    let bytes: UInt64
    let retransmits: UInt64?
    let streamCount: Int
    let meanRTTMicroseconds: UInt64?
    let maximumRTTMicroseconds: UInt64?
    let throughputRole: IperfThroughputRole
    let startSeconds: Double
    let endSeconds: Double
    let rawFinalLine: String
}

nonisolated enum IperfStreamEvent: Sendable, Equatable {
    case interval(start: Double, end: Double, bitsPerSecond: Double)
    case completed(IperfFinalResult)
    case warning(String)
}

nonisolated enum IperfStreamParserError: Error, Sendable, Equatable {
    case missingFinalResult
}

nonisolated struct IperfStreamParser: Sendable {
    private let direction: BenchmarkDirection
    private var finalResult: IperfFinalResult?

    init(direction: BenchmarkDirection) {
        self.direction = direction
    }

    mutating func consume(line: String) -> [IperfStreamEvent] {
        guard let data = line.data(using: .utf8) else {
            return [.warning("iperf emitted a non-UTF-8 line")]
        }

        let decoder = JSONDecoder()
        let event: EventNameEnvelope
        do {
            event = try decoder.decode(EventNameEnvelope.self, from: data)
        } catch {
            return [.warning("malformed iperf JSON line: \(line)")]
        }

        switch event.event {
        case "start":
            return []
        case "interval":
            do {
                let envelope = try decoder.decode(IntervalEnvelope.self, from: data)
                guard !envelope.data.sum.omitted else { return [] }
                return [.interval(
                    start: envelope.data.sum.start,
                    end: envelope.data.sum.end,
                    bitsPerSecond: envelope.data.sum.bitsPerSecond
                )]
            } catch {
                return [.warning("malformed iperf interval line: \(line)")]
            }
        case "end":
            do {
                let envelope = try decoder.decode(EndEnvelope.self, from: data)
                let result = normalize(envelope.data, rawFinalLine: line)
                finalResult = result
                return [.completed(result)]
            } catch {
                return [.warning("malformed iperf final line: \(line)")]
            }
        default:
            return [.warning("unknown iperf stream event \(event.event): \(line)")]
        }
    }

    func finish() throws -> IperfFinalResult {
        guard let finalResult else {
            throw IperfStreamParserError.missingFinalResult
        }
        return finalResult
    }

    private func normalize(_ end: EndData, rawFinalLine: String) -> IperfFinalResult {
        let delivered = end.sumReceived
        let senderStreams = end.streams.map(\.sender)
        return IperfFinalResult(
            bitsPerSecond: delivered.bitsPerSecond,
            bytes: delivered.bytes,
            retransmits: end.sumSent.retransmits,
            streamCount: end.streams.count,
            meanRTTMicroseconds: average(senderStreams.compactMap(\.meanRTT)),
            maximumRTTMicroseconds: senderStreams.compactMap(\.maxRTT).max(),
            throughputRole: .receiver,
            startSeconds: delivered.start,
            endSeconds: delivered.end,
            rawFinalLine: rawFinalLine
        )
    }

    private func average(_ values: [UInt64]) -> UInt64? {
        guard !values.isEmpty else { return nil }
        return values.reduce(0, +) / UInt64(values.count)
    }
}

private nonisolated struct EventNameEnvelope: Decodable, Sendable {
    let event: String
}

private nonisolated struct IntervalEnvelope: Decodable, Sendable {
    let data: IntervalData
}

private nonisolated struct IntervalData: Decodable, Sendable {
    let sum: IntervalSummary
}

private nonisolated struct IntervalSummary: Decodable, Sendable {
    let start: Double
    let end: Double
    let bitsPerSecond: Double
    let omitted: Bool

    enum CodingKeys: String, CodingKey {
        case start
        case end
        case bitsPerSecond = "bits_per_second"
        case omitted
    }
}

private nonisolated struct EndEnvelope: Decodable, Sendable {
    let data: EndData
}

private nonisolated struct EndData: Decodable, Sendable {
    let streams: [EndStream]
    let sumSent: SenderSummary
    let sumReceived: ReceiverSummary

    enum CodingKeys: String, CodingKey {
        case streams
        case sumSent = "sum_sent"
        case sumReceived = "sum_received"
    }
}

private nonisolated struct EndStream: Decodable, Sendable {
    let sender: SenderStream
}

private nonisolated struct SenderStream: Decodable, Sendable {
    let meanRTT: UInt64?
    let maxRTT: UInt64?

    enum CodingKeys: String, CodingKey {
        case meanRTT = "mean_rtt"
        case maxRTT = "max_rtt"
    }
}

private nonisolated struct SenderSummary: Decodable, Sendable {
    let retransmits: UInt64?
}

private nonisolated struct ReceiverSummary: Decodable, Sendable {
    let start: Double
    let end: Double
    let bytes: UInt64
    let bitsPerSecond: Double

    enum CodingKeys: String, CodingKey {
        case start
        case end
        case bytes
        case bitsPerSecond = "bits_per_second"
    }
}
