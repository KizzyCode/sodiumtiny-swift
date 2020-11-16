// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "SodiumTiny",
    products: [
        .library(
            name: "SodiumTiny",
            targets: ["SodiumTiny"])
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
            name: "SodiumTiny",
            dependencies: ["Clibsodium", "CXchachaSiv"]),
        
        .testTarget(
            name: "SodiumTinyTests",
            dependencies: ["SodiumTiny"])
    ]
)
