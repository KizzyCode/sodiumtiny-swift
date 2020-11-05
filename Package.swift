// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "SodiumCrypto",
    products: [
        .library(
            name: "Clibsodium",
            targets: ["Clibsodium"]),
        .library(
            name: "XChaChaSIV",
            targets: ["XChaChaSIV"]),
        .library(
            name: "SodiumCrypto",
            targets: ["SodiumCrypto"])
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
            name: "SodiumCrypto",
            dependencies: ["Clibsodium", "XChaChaSIV"]),
        .testTarget(
            name: "SodiumCryptoTests",
            dependencies: ["SodiumCrypto"],
            resources: [.process("AeadXchachaPolyPredefined.json")])
    ]
)
