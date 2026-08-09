import Foundation

nonisolated struct BenchmarkRunIndexEntry: Codable, Sendable, Equatable {
    let id: UUID
    let startedAt: Date
    let completedAt: Date
    let automaticLabel: String
    var userLabel: String?
    let hasErrors: Bool
}

nonisolated struct BenchmarkRunIndex: Codable, Sendable, Equatable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    var selectedBaselineID: UUID?
    var entries: [BenchmarkRunIndexEntry]

    init(
        schemaVersion: Int = BenchmarkRunIndex.currentSchemaVersion,
        selectedBaselineID: UUID? = nil,
        entries: [BenchmarkRunIndexEntry] = []
    ) {
        self.schemaVersion = schemaVersion
        self.selectedBaselineID = selectedBaselineID
        self.entries = entries
    }
}

nonisolated enum BenchmarkStoreLoadErrorReason: Sendable, Equatable {
    case corrupt
    case unsupportedSchema(Int)
    case identityMismatch(expectedFileName: String)
}

nonisolated struct BenchmarkStoreLoadError: Sendable, Equatable {
    let fileName: String
    let reason: BenchmarkStoreLoadErrorReason
}

nonisolated struct BenchmarkRunLoadResult: Sendable, Equatable {
    let runs: [BenchmarkRun]
    let errors: [BenchmarkStoreLoadError]
}

nonisolated enum BenchmarkStoreError: Error, Sendable, Equatable {
    case unsupportedIndexSchema(Int)
    case unsupportedRunSchema(Int)
    case runNotFound(UUID)
}

actor BenchmarkStore {
    private struct SchemaEnvelope: Decodable {
        let schemaVersion: Int
    }

    private let directory: URL
    private let fileManager: FileManager
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private let beforeCommit: @Sendable (URL) throws -> Void

    init(
        directory: URL? = nil,
        fileManager: FileManager = .default,
        beforeCommit: @escaping @Sendable (URL) throws -> Void = { _ in }
    ) {
        self.fileManager = fileManager
        self.directory = directory ?? Self.defaultDirectory(fileManager: fileManager)
        self.beforeCommit = beforeCommit
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        self.encoder = encoder
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        self.decoder = decoder
    }

    func loadIndex() throws -> BenchmarkRunIndex {
        try ensureDirectory()
        let url = indexURL
        guard fileManager.fileExists(atPath: url.path) else {
            return BenchmarkRunIndex()
        }
        let data = try Data(contentsOf: url)
        let schema = try decoder.decode(SchemaEnvelope.self, from: data).schemaVersion
        guard schema == BenchmarkRunIndex.currentSchemaVersion else {
            throw BenchmarkStoreError.unsupportedIndexSchema(schema)
        }
        return try decoder.decode(BenchmarkRunIndex.self, from: data)
    }

    func loadRuns() throws -> BenchmarkRunLoadResult {
        try ensureDirectory()
        let files = try fileManager.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )
        .filter { $0.pathExtension == "json" && $0.lastPathComponent != indexURL.lastPathComponent }
        .sorted { $0.lastPathComponent < $1.lastPathComponent }

        var runs: [BenchmarkRun] = []
        var errors: [BenchmarkStoreLoadError] = []
        for file in files {
            do {
                let data = try Data(contentsOf: file)
                let schema = try decoder.decode(SchemaEnvelope.self, from: data).schemaVersion
                guard schema == BenchmarkRun.currentSchemaVersion else {
                    errors.append(BenchmarkStoreLoadError(
                        fileName: file.lastPathComponent,
                        reason: .unsupportedSchema(schema)
                    ))
                    continue
                }
                let run = try decoder.decode(BenchmarkRun.self, from: data)
                let expectedFileName = runURL(run.id).lastPathComponent
                guard file.lastPathComponent == expectedFileName else {
                    errors.append(BenchmarkStoreLoadError(
                        fileName: file.lastPathComponent,
                        reason: .identityMismatch(expectedFileName: expectedFileName)
                    ))
                    continue
                }
                runs.append(run)
            } catch {
                errors.append(BenchmarkStoreLoadError(
                    fileName: file.lastPathComponent,
                    reason: .corrupt
                ))
            }
        }

        return BenchmarkRunLoadResult(
            runs: runs.sorted(by: Self.isNewer),
            errors: errors.sorted { $0.fileName < $1.fileName }
        )
    }

    func saveRun(_ run: BenchmarkRun) throws {
        guard run.schemaVersion == BenchmarkRun.currentSchemaVersion else {
            throw BenchmarkStoreError.unsupportedRunSchema(run.schemaVersion)
        }
        try ensureDirectory()
        let runDestination = runURL(run.id)
        let previousRunData = try existingData(at: runDestination)
        var index = try loadIndex()
        index.entries.removeAll { $0.id == run.id }
        index.entries.append(Self.indexEntry(for: run))
        index.entries.sort(by: Self.isNewer)
        try writeAtomically(encoder.encode(run), to: runDestination)
        do {
            try writeAtomically(encoder.encode(index), to: indexURL)
        } catch {
            try rollback(previousRunData, at: runDestination, after: error)
        }
    }

    func renameRun(_ id: UUID, userLabel: String?) throws {
        let url = runURL(id)
        guard fileManager.fileExists(atPath: url.path) else {
            throw BenchmarkStoreError.runNotFound(id)
        }
        let originalRunData = try Data(contentsOf: url)
        var run = try decoder.decode(BenchmarkRun.self, from: originalRunData)
        guard run.schemaVersion == BenchmarkRun.currentSchemaVersion else {
            throw BenchmarkStoreError.unsupportedRunSchema(run.schemaVersion)
        }
        var index = try loadIndex()
        guard let entryIndex = index.entries.firstIndex(where: { $0.id == id }) else {
            throw BenchmarkStoreError.runNotFound(id)
        }
        run.userLabel = Self.normalizedLabel(userLabel)
        index.entries[entryIndex].userLabel = run.userLabel
        try writeAtomically(encoder.encode(run), to: url)
        do {
            try writeAtomically(encoder.encode(index), to: indexURL)
        } catch {
            try rollback(originalRunData, at: url, after: error)
        }
    }

    func selectBaseline(_ id: UUID?) throws {
        var index = try loadIndex()
        if let id, !index.entries.contains(where: { $0.id == id }) {
            throw BenchmarkStoreError.runNotFound(id)
        }
        index.selectedBaselineID = id
        try writeAtomically(encoder.encode(index), to: indexURL)
    }

    private static func defaultDirectory(fileManager: FileManager) -> URL {
        let applicationSupport = fileManager.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? fileManager.homeDirectoryForCurrentUser
            .appending(path: "Library/Application Support", directoryHint: .isDirectory)
        return applicationSupport
            .appending(path: "Multipass", directoryHint: .isDirectory)
            .appending(path: "Benchmarks", directoryHint: .isDirectory)
    }

    private static func indexEntry(for run: BenchmarkRun) -> BenchmarkRunIndexEntry {
        BenchmarkRunIndexEntry(
            id: run.id,
            startedAt: run.startedAt,
            completedAt: run.completedAt,
            automaticLabel: BenchmarkFormatting.automaticLabel(for: run),
            userLabel: run.userLabel,
            hasErrors: run.hasErrors
        )
    }

    private static func isNewer(_ lhs: BenchmarkRunIndexEntry, _ rhs: BenchmarkRunIndexEntry) -> Bool {
        if lhs.startedAt != rhs.startedAt { return lhs.startedAt > rhs.startedAt }
        return lhs.id.uuidString > rhs.id.uuidString
    }

    private static func isNewer(_ lhs: BenchmarkRun, _ rhs: BenchmarkRun) -> Bool {
        if lhs.startedAt != rhs.startedAt { return lhs.startedAt > rhs.startedAt }
        return lhs.id.uuidString > rhs.id.uuidString
    }

    private static func normalizedLabel(_ label: String?) -> String? {
        guard let label else { return nil }
        let trimmed = label.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private var indexURL: URL {
        directory.appending(path: "index.json", directoryHint: .notDirectory)
    }

    private func runURL(_ id: UUID) -> URL {
        directory.appending(path: "\(id.uuidString.lowercased()).json", directoryHint: .notDirectory)
    }

    private func existingData(at url: URL) throws -> Data? {
        guard fileManager.fileExists(atPath: url.path) else { return nil }
        return try Data(contentsOf: url)
    }

    private func rollback(_ data: Data?, at destination: URL, after error: Error) throws -> Never {
        if let data {
            try writeAtomically(data, to: destination, injectFault: false)
        } else if fileManager.fileExists(atPath: destination.path) {
            try fileManager.removeItem(at: destination)
        }
        throw error
    }

    private func ensureDirectory() throws {
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    private func writeAtomically(
        _ data: Data,
        to destination: URL,
        injectFault: Bool = true
    ) throws {
        let temporary = destination.deletingLastPathComponent().appending(
            path: ".\(destination.lastPathComponent).\(UUID().uuidString).tmp",
            directoryHint: .notDirectory
        )
        guard fileManager.createFile(atPath: temporary.path, contents: nil) else {
            throw CocoaError(.fileWriteUnknown)
        }
        do {
            let handle = try FileHandle(forWritingTo: temporary)
            do {
                try handle.write(contentsOf: data)
                try handle.synchronize()
                try handle.close()
            } catch {
                try? handle.close()
                throw error
            }
            if injectFault {
                try beforeCommit(destination)
            }
            if fileManager.fileExists(atPath: destination.path) {
                _ = try fileManager.replaceItemAt(destination, withItemAt: temporary)
            } else {
                try fileManager.moveItem(at: temporary, to: destination)
            }
        } catch {
            try? fileManager.removeItem(at: temporary)
            throw error
        }
    }
}
