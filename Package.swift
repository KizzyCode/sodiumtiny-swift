// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "SodiumCrypto",
    products: [
        .library(
            name: "SodiumMemory",
            targets: ["SodiumMemory"]),
        .library(
            name: "SodiumCore",
            targets: ["SodiumCore"])
    ],
    dependencies: [],
    targets: [
        .binaryTarget(
            name: "Clibsodium",
            path: "Clibsodium.xcframework"),
        .target(
            name: "XChaChaSIV",
            dependencies: ["Clibsodium"],
            cSettings: [.headerSearchPath("Clibsodium")]),
        
        .target(
            name: "SodiumMemory",
            dependencies: ["Clibsodium"]),
        .target(
            name: "SodiumCore",
            dependencies: ["Clibsodium", "XChaChaSIV", "SodiumMemory"]),
        
        .testTarget(
            name: "SodiumCoreTests",
            dependencies: ["SodiumCore", "SodiumMemory"],
            resources: [.process("XchachaPoly.json"), .process("HkdfSha512.json")]),
        .testTarget(
            name: "SodiumMemoryTests",
            dependencies: ["SodiumCore", "SodiumMemory"])
    ]
)
