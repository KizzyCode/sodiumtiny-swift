// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "SodiumCrypto",
    products: [
        .library(
            name: "SodiumMemory",
            targets: ["SodiumMemory"]),
        .library(
            name: "SodiumCrypto",
            targets: ["SodiumCrypto"]),
        .library(
            name: "SodiumCombine",
            targets: ["SodiumCombine"])
    ],
    dependencies: [],
    targets: [
        .binaryTarget(
            name: "Clibsodium",
            path: "Clibsodium.xcframework"),
        .target(
            name: "CXchachaSiv",
            dependencies: ["Clibsodium"],
            cSettings: [.headerSearchPath("Clibsodium")]),
        
        .target(
            name: "SodiumMemory",
            dependencies: ["Clibsodium"]),
        .target(
            name: "SodiumCrypto",
            dependencies: ["Clibsodium", "CXchachaSiv", "SodiumMemory"]),
        .target(
            name: "SodiumCombine",
            dependencies: ["SodiumCrypto"]),
        
        .testTarget(
            name: "SodiumCryptoTests",
            dependencies: ["SodiumCrypto", "SodiumMemory"],
            resources: [
                .process("Kdf/HkdfSha512.json"),
                .process("Misc/Padding.json"),
                .process("Cipher/XchachaPoly.json")]),
        .testTarget(
            name: "SodiumMemoryTests",
            dependencies: ["SodiumCrypto", "SodiumMemory"]),
        .testTarget(
            name: "SodiumCombineTests",
            dependencies: ["SodiumCrypto", "SodiumMemory", "SodiumCombine"])
    ]
)
