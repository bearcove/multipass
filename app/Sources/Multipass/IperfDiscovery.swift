import Foundation

nonisolated enum IperfDiscovery {
    private static let candidatePaths = [
        "/opt/homebrew/bin/iperf3",
        "/usr/local/bin/iperf3",
    ]

    static func findExecutable(fileManager: FileManager = .default) -> URL? {
        candidatePaths.first { fileManager.isExecutableFile(atPath: $0) }.map {
            URL(filePath: $0)
        }
    }
}
