// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "TomCrypt",
    platforms: [
        .macOS(.v10_10), .iOS(.v9), .tvOS(.v9)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "TomCrypt",
            targets: ["TomCrypt"])
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/libtom/libtommath.git", .branch("develop")),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "TomCrypt",
            dependencies: ["TomMath"],
            path: ".",
            sources: ["src"],
            publicHeadersPath: "modulemap",
            cSettings: [
                .headerSearchPath("src/headers"),
                .define("USE_LTM"),
                .define("LTM_DESC"),
                .define("LTC_NO_TEST")
            ]),
        .testTarget(name: "TomCryptTests",
                    dependencies: ["TomCrypt"],
                    path: "demos",
                    sources: ["tomcrypt_tests.swift"])
    ],
    cLanguageStandard: .gnu11,
    cxxLanguageStandard: .gnucxx14
)
