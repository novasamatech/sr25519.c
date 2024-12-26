// swift-tools-version:5.3
import PackageDescription

let name = "sr25519c"

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
            path: "./bindings/xcframework/\(name).xcframework"
        )
    ]
)