import Foundation
import Testing
@testable import Multipass

@Suite("Benchmark store")
struct BenchmarkStoreTests {
    @Test("saves one atomic file per run and orders newest first")
    func savesOneFilePerRunAndOrdersNewestFirst() async throws {
        let directory = try temporaryBenchmarkDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = BenchmarkStore(directory: directory)
        let older = benchmarkRun(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            startedAt: Date(timeIntervalSince1970: 1_000),
            completedAt: Date(timeIntervalSince1970: 1_010),
            userLabel: "Older"
        )
        let newer = benchmarkRun(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
            startedAt: Date(timeIntervalSince1970: 2_000),
            completedAt: Date(timeIntervalSince1970: 2_010),
            userLabel: "Newer"
        )

        try await store.saveRun(older)
        try await store.saveRun(newer)

        let entries = try await store.loadIndex().entries
        #expect(entries.map(\.id) == [newer.id, older.id])
        #expect(entries.map(\.userLabel) == ["Newer", "Older"])
        #expect(try directoryContents(directory) == [
            "00000000-0000-0000-0000-000000000001.json",
            "00000000-0000-0000-0000-000000000002.json",
            "index.json",
        ])
        let loaded = try await store.loadRuns()
        #expect(loaded.runs == [newer, older])
        #expect(loaded.errors.isEmpty)
    }

    @Test("persists selected baseline across store instances")
    func persistsSelectedBaseline() async throws {
        let directory = try temporaryBenchmarkDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let run = benchmarkRun()
        let firstStore = BenchmarkStore(directory: directory)
        try await firstStore.saveRun(run)
        try await firstStore.selectBaseline(run.id)

        let secondStore = BenchmarkStore(directory: directory)
        #expect(try await secondStore.loadIndex().selectedBaselineID == run.id)
        try await secondStore.selectBaseline(nil)
        #expect(try await firstStore.loadIndex().selectedBaselineID == nil)
    }

    @Test("expected skips do not mark the history index entry as an error")
    func skippedResultsAreNotIndexedAsErrors() async throws {
        let directory = try temporaryBenchmarkDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = BenchmarkStore(directory: directory)
        let skippedID = BenchmarkTestID(
            route: .tunnel,
            direction: .upload,
            addressFamily: .ipv6
        )
        var run = benchmarkRun()
        run.results[skippedID] = .skipped("tunnel IPv6 target unavailable")

        try await store.saveRun(run)

        let entry = try #require(try await store.loadIndex().entries.first)
        #expect(entry.id == run.id)
        #expect(entry.hasErrors == false)
        #expect(run.hasErrors == false)
        #expect(run.results[skippedID]?.isSkipped == true)
        #expect(run.results[skippedID]?.isFailure == false)
    }

    @Test("isolates corrupt run files while loading valid history")
    func isolatesCorruptRunFiles() async throws {
        let directory = try temporaryBenchmarkDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = BenchmarkStore(directory: directory)
        let run = benchmarkRun()
        try await store.saveRun(run)
        try Data("not json".utf8).write(to: directory.appending(path: "corrupt.json"))

        let loaded = try await store.loadRuns()

        #expect(loaded.runs == [run])
        #expect(loaded.errors == [BenchmarkStoreLoadError(
            fileName: "corrupt.json",
            reason: .corrupt
        )])
    }

    @Test("rejects a valid run whose filename does not match its UUID")
    func rejectsMisnamedValidRun() async throws {
        let directory = try temporaryBenchmarkDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let run = benchmarkRun(id: UUID(uuidString: "00000000-0000-0000-0000-000000000011")!)
        let canonicalName = "00000000-0000-0000-0000-000000000011.json"
        try encodedRun(run).write(to: directory.appending(path: "copy.json"))

        let loaded = try await BenchmarkStore(directory: directory).loadRuns()

        #expect(loaded.runs.isEmpty)
        #expect(loaded.errors == [BenchmarkStoreLoadError(
            fileName: "copy.json",
            reason: .identityMismatch(expectedFileName: canonicalName)
        )])
    }

    @Test("a duplicate valid copy is an error and cannot shadow the canonical run")
    func duplicateValidCopyCannotShadowCanonicalRun() async throws {
        let directory = try temporaryBenchmarkDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let id = UUID(uuidString: "00000000-0000-0000-0000-000000000012")!
        let canonical = benchmarkRun(id: id, userLabel: "Canonical")
        let copied = benchmarkRun(id: id, userLabel: "Copied")
        let canonicalName = "00000000-0000-0000-0000-000000000012.json"
        try encodedRun(canonical).write(to: directory.appending(path: canonicalName))
        try encodedRun(copied).write(to: directory.appending(path: "duplicate.json"))

        let loaded = try await BenchmarkStore(directory: directory).loadRuns()

        #expect(loaded.runs == [canonical])
        #expect(loaded.errors == [BenchmarkStoreLoadError(
            fileName: "duplicate.json",
            reason: .identityMismatch(expectedFileName: canonicalName)
        )])
    }

    @Test("rejects unknown future run schemas without hiding compatible runs")
    func rejectsUnknownRunSchema() async throws {
        let directory = try temporaryBenchmarkDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = BenchmarkStore(directory: directory)
        let run = benchmarkRun()
        try await store.saveRun(run)
        let futureFile = directory.appending(path: "future.json")
        try JSONEncoder().encode(FutureSchemaFixture(schemaVersion: 99)).write(to: futureFile)

        let loaded = try await store.loadRuns()

        #expect(loaded.runs == [run])
        #expect(loaded.errors == [BenchmarkStoreLoadError(
            fileName: "future.json",
            reason: .unsupportedSchema(99)
        )])
    }

    @Test("renaming changes only the user label and preserves measurement payloads")
    func renamePreservesMeasurements() async throws {
        let directory = try temporaryBenchmarkDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = BenchmarkStore(directory: directory)
        let original = benchmarkRun(userLabel: nil)
        try await store.saveRun(original)
        let before = try Data(contentsOf: directory.appending(path: "\(original.id.uuidString.lowercased()).json"))
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let beforeRecord = try decoder.decode(BenchmarkRun.self, from: before)

        try await store.renameRun(original.id, userLabel: "Office regression")

        let renamed = try #require(try await store.loadRuns().runs.first)
        #expect(renamed.userLabel == "Office regression")
        #expect(renamed.id == beforeRecord.id)
        #expect(renamed.startedAt == beforeRecord.startedAt)
        #expect(renamed.completedAt == beforeRecord.completedAt)
        #expect(renamed.identities == beforeRecord.identities)
        #expect(renamed.topology == beforeRecord.topology)
        #expect(renamed.parameters == beforeRecord.parameters)
        #expect(renamed.initiallyConnected == beforeRecord.initiallyConnected)
        #expect(renamed.results == beforeRecord.results)
        #expect(renamed.restorationError == beforeRecord.restorationError)
        #expect(renamed.results[aggregateUploadID]?.measurement?.members["wired"]?.rawFinalLine ==
            "{\"event\":\"end\",\"member\":\"wired\"}")
        #expect(renamed.results[aggregateUploadID]?.measurement?.members["wifi"]?.rawFinalLine ==
            "{\"event\":\"end\",\"member\":\"wifi\"}")
        #expect(try directoryContents(directory).allSatisfy { !$0.contains(".tmp") })
    }

    @Test("a failed index write rolls back a newly saved run")
    func failedIndexWriteRollsBackNewRun() async throws {
        let directory = try temporaryBenchmarkDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fault = CommitFault()
        let store = BenchmarkStore(directory: directory, beforeCommit: fault.check)
        let run = benchmarkRun(id: UUID(uuidString: "00000000-0000-0000-0000-000000000021")!)
        fault.failNextCommit(to: "index.json")

        await #expect(throws: CocoaError.self) {
            try await store.saveRun(run)
        }

        let reopened = BenchmarkStore(directory: directory)
        #expect(try await reopened.loadRuns().runs.isEmpty)
        #expect(try await reopened.loadIndex().entries.isEmpty)
        #expect(try directoryContents(directory) == [])
    }

    @Test("a failed index write restores an existing run replacement")
    func failedIndexWriteRollsBackExistingRunReplacement() async throws {
        let directory = try temporaryBenchmarkDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fault = CommitFault()
        let store = BenchmarkStore(directory: directory, beforeCommit: fault.check)
        let original = benchmarkRun(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000023")!,
            userLabel: "Original"
        )
        var replacement = original
        replacement.userLabel = "Replacement"
        try await store.saveRun(original)
        fault.failNextCommit(to: "index.json")

        await #expect(throws: CocoaError.self) {
            try await store.saveRun(replacement)
        }

        let reopened = BenchmarkStore(directory: directory)
        #expect(try await reopened.loadRuns().runs == [original])
        #expect(try await reopened.loadIndex().entries.first?.userLabel == "Original")
    }

    @Test("a failed run write leaves both labels unchanged during rename")
    func failedRunWriteLeavesRenameUnchanged() async throws {
        let directory = try temporaryBenchmarkDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fault = CommitFault()
        let store = BenchmarkStore(directory: directory, beforeCommit: fault.check)
        let original = benchmarkRun(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000024")!,
            userLabel: "Original"
        )
        try await store.saveRun(original)
        fault.failNextCommit(to: "00000000-0000-0000-0000-000000000024.json")

        await #expect(throws: CocoaError.self) {
            try await store.renameRun(original.id, userLabel: "Changed")
        }

        let reopened = BenchmarkStore(directory: directory)
        #expect(try await reopened.loadRuns().runs == [original])
        #expect(try await reopened.loadIndex().entries.first?.userLabel == "Original")
    }

    @Test("a failed index write restores both labels during rename")
    func failedIndexWriteRollsBackRename() async throws {
        let directory = try temporaryBenchmarkDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fault = CommitFault()
        let store = BenchmarkStore(directory: directory, beforeCommit: fault.check)
        let original = benchmarkRun(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000022")!,
            userLabel: "Original"
        )
        try await store.saveRun(original)
        fault.failNextCommit(to: "index.json")

        await #expect(throws: CocoaError.self) {
            try await store.renameRun(original.id, userLabel: "Changed")
        }

        let reopened = BenchmarkStore(directory: directory)
        #expect(try await reopened.loadRuns().runs == [original])
        #expect(try await reopened.loadIndex().entries.first?.userLabel == "Original")
        #expect(try directoryContents(directory) == [
            "00000000-0000-0000-0000-000000000022.json",
            "index.json",
        ])
    }
}

private struct FutureSchemaFixture: Encodable {
    let schemaVersion: Int
}

private func encodedRun(_ run: BenchmarkRun) throws -> Data {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    return try encoder.encode(run)
}

private final class CommitFault: @unchecked Sendable {
    private var fileNameToFail: String?

    func failNextCommit(to fileName: String) {
        fileNameToFail = fileName
    }

    func check(_ destination: URL) throws {
        if fileNameToFail == destination.lastPathComponent {
            fileNameToFail = nil
            throw CocoaError(.fileWriteUnknown)
        }
    }
}

private func temporaryBenchmarkDirectory() throws -> URL {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "multipass-benchmark-store-tests-\(UUID().uuidString)", directoryHint: .isDirectory)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return directory
}

private func directoryContents(_ directory: URL) throws -> [String] {
    try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
}
