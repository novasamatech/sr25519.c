// swift-tools-version:5.3
import PackageDescription

let name = "sr25519.c"

let package = Package(
    name: name,
    products: [
        .library(
            name: name,
            targets: [name]
        ),
    ],
    targets: [
        .binaryTarget(
            name: name,
            path: "./bindings/xcframework/sr25519.xcframework"
        )
    ]
)