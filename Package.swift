// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AirliveCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "AirliveCore", targets: ["AirliveCore"]),
    ],
    targets: [
        .target(
            name: "AirliveCore",
            path: "Sources/AirliveCore"
        ),
        .testTarget(
            name: "AirliveCoreTests",
            dependencies: ["AirliveCore"],
            path: "Tests/AirliveCoreTests"
        )
    ]
)
