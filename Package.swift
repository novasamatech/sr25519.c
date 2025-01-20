// swift-tools-version: 6.0
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
            path: "./bindings/xcframework/sr25519c.xcframework"
        )
    ]
)
