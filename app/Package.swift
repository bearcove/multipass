// swift-tools-version: 6.4

import PackageDescription

let package = Package(
    name: "Multipass",
    platforms: [
        .macOS(.v27)
    ],
    products: [
        .executable(name: "Multipass", targets: ["Multipass"])
    ],
    targets: [
        .executableTarget(
            name: "Multipass",
            exclude: ["Info.plist"],
            swiftSettings: [
                .enableUpcomingFeature("InferIsolatedConformances"),
                .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
                .defaultIsolation(MainActor.self),
            ]
        ),
        .testTarget(
            name: "MultipassTests",
            dependencies: ["Multipass"]
        )
    ],
    swiftLanguageModes: [.v6]
)
