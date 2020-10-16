// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "SodiumCrypto",
    products: [
        .library(
            name: "SodiumCrypto",
            targets: ["SodiumCrypto"])
    ],
    dependencies: [
        .package(
            name: "Sodium",
            url: "https://github.com/jedisct1/swift-sodium",
            .exact("0.9.0"))
    ],
    targets: [
        .target(
            name: "SodiumCrypto",
            dependencies: ["Sodium"]),
        .testTarget(
            name: "SodiumCryptoTests",
            dependencies: ["SodiumCrypto"])
    ]
)
