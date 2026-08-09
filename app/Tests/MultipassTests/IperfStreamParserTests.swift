import Foundation
import Testing
@testable import Multipass

@Suite("iperf JSON stream parser")
struct IperfStreamParserTests {
    @Test("extracts measured interval throughput from a real upload stream")
    func extractsIntervalThroughput() throws {
        var parser = IperfStreamParser(direction: .upload)
        let events = try fixtureLines(named: "iperf-upload").flatMap { parser.consume(line: $0) }

        let samples = events.compactMap { event -> Double? in
            guard case .interval(_, let bitsPerSecond) = event else { return nil }
            return bitsPerSecond
        }

        #expect(samples == [1_264_553_060.315488])
    }

    @Test("uses upload receiver delivery while retaining sender diagnostics")
    func parsesUploadFinalResult() throws {
        var parser = IperfStreamParser(direction: .upload)
        let events = try fixtureLines(named: "iperf-upload").flatMap { parser.consume(line: $0) }
        let result = try #require(completedResult(in: events))

        #expect(result.bitsPerSecond == 1_262_344_054.6972628)
        #expect(result.bytes == 158_597_120)
        #expect(result.retransmits == 0)
        #expect(result.streamCount == 1)
        #expect(result.meanRTTMicroseconds == 1)
        #expect(result.maximumRTTMicroseconds == 2)
        #expect(result.throughputRole == .receiver)
        #expect(result.startSeconds == 0)
        #expect(result.endSeconds == 1.005096)
        #expect(result.rawFinalLine.hasPrefix("{\"event\":\"end\""))
        #expect(result.rawFinalLine.contains("\"sum_received\""))
    }

    @Test("uses reverse-download local receiver delivery and remote sender diagnostics")
    func parsesDownloadFinalResult() throws {
        var parser = IperfStreamParser(direction: .download)
        let events = try fixtureLines(named: "iperf-download").flatMap { parser.consume(line: $0) }
        let result = try #require(completedResult(in: events))

        #expect(result.bitsPerSecond == 2_315_285_906.7167873)
        #expect(result.bytes == 289_406_976)
        #expect(result.retransmits == 117)
        #expect(result.streamCount == 1)
        #expect(result.meanRTTMicroseconds == 0)
        #expect(result.maximumRTTMicroseconds == 0)
        #expect(result.throughputRole == .receiver)
        #expect(result.startSeconds == 0)
        #expect(result.endSeconds == 0.999987)
    }

    @Test("warns for malformed non-final lines without losing a later final result")
    func malformedNonFinalLineWarns() throws {
        var parser = IperfStreamParser(direction: .upload)
        let lines = try fixtureLines(named: "iperf-upload")
        let events = ["not-json"].flatMap { parser.consume(line: $0) }
            + lines.flatMap { parser.consume(line: $0) }

        let warning = try #require(events.compactMap { event -> String? in
            guard case .warning(let message) = event else { return nil }
            return message
        }.first)
        #expect(warning.contains("not-json"))
        #expect(completedResult(in: events) != nil)
    }

    @Test("recognizable malformed measured intervals reserve their ordinal")
    func malformedMeasuredIntervalReservesOrdinal() {
        var parser = IperfStreamParser(direction: .upload)

        let first = parser.consume(line: intervalLine(start: 0.15, end: 1.15, bitsPerSecond: 100))
        let malformed = parser.consume(line: "{\"event\":\"interval\",\"data\":{\"sum\":{\"start\":1.15,\"end\":2.15,\"omitted\":false}}}")
        let third = parser.consume(line: intervalLine(start: 2.15, end: 3.15, bitsPerSecond: 300))

        #expect(first == [.interval(ordinal: 0, bitsPerSecond: 100)])
        #expect(malformed.contains { if case .warning = $0 { true } else { false } })
        #expect(third == [.interval(ordinal: 2, bitsPerSecond: 300)])
    }

    @Test("generic malformed lines do not consume measured ordinals")
    func genericMalformedLineDoesNotConsumeOrdinal() {
        var parser = IperfStreamParser(direction: .upload)

        _ = parser.consume(line: "not-json")
        let event = parser.consume(line: intervalLine(start: 7.2, end: 8.2, bitsPerSecond: 100))

        #expect(event == [.interval(ordinal: 0, bitsPerSecond: 100)])
    }

    @Test("type-malformed measured throughput reserves its ordinal")
    func typeMalformedMeasuredThroughputReservesOrdinal() {
        var parser = IperfStreamParser(direction: .upload)

        _ = parser.consume(line: intervalLine(start: 0, end: 1, bitsPerSecond: 100))
        let malformed = parser.consume(line: "{\"event\":\"interval\",\"data\":{\"sum\":{\"start\":1,\"end\":2,\"bits_per_second\":\"bad\",\"omitted\":false}}}")
        let third = parser.consume(line: intervalLine(start: 2, end: 3, bitsPerSecond: 300))

        #expect(malformed.contains { if case .warning = $0 { true } else { false } })
        #expect(third == [.interval(ordinal: 2, bitsPerSecond: 300)])
    }

    @Test("omitted intervals do not consume measured ordinals")
    func omittedIntervalDoesNotConsumeOrdinal() {
        var parser = IperfStreamParser(direction: .upload)

        _ = parser.consume(line: "{\"event\":\"interval\",\"data\":{\"sum\":{\"start\":0,\"end\":1,\"bits_per_second\":100,\"omitted\":true}}}")
        let measured = parser.consume(line: intervalLine(start: 1, end: 2, bitsPerSecond: 200))

        #expect(measured == [.interval(ordinal: 0, bitsPerSecond: 200)])
    }

    @Test("a malformed final line is a warning and leaves the stream incomplete")
    func malformedFinalLineDoesNotComplete() throws {
        var parser = IperfStreamParser(direction: .upload)
        let events = parser.consume(line: "{\"event\":\"end\",\"data\":{}}")

        #expect(events.contains { event in
            guard case .warning = event else { return false }
            return true
        })
        #expect(completedResult(in: events) == nil)
        #expect(throws: IperfStreamParserError.missingFinalResult) {
            try parser.finish()
        }
    }

    @Test("a stream with no final line fails completion")
    func missingFinalLineFails() throws {
        var parser = IperfStreamParser(direction: .download)
        let lines = try fixtureLines(named: "iperf-download")
        for line in lines.dropLast() {
            _ = parser.consume(line: line)
        }

        #expect(throws: IperfStreamParserError.missingFinalResult) {
            try parser.finish()
        }
    }
}

private func fixtureLines(named name: String) throws -> [String] {
    let url = try #require(Bundle.module.url(forResource: name, withExtension: "jsonl", subdirectory: "Fixtures"))
    return try String(contentsOf: url, encoding: .utf8)
        .split(whereSeparator: \.isNewline)
        .map(String.init)
}

private func completedResult(in events: [IperfStreamEvent]) -> IperfFinalResult? {
    events.compactMap { event in
        guard case .completed(let result) = event else { return nil }
        return result
    }.last
}


private func intervalLine(start: Double, end: Double, bitsPerSecond: Double) -> String {
    "{\"event\":\"interval\",\"data\":{\"sum\":{\"start\":\(start),\"end\":\(end),\"bits_per_second\":\(bitsPerSecond),\"omitted\":false}}}"
}