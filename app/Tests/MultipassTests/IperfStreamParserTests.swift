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
            guard case .interval(_, _, let bitsPerSecond) = event else { return nil }
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
