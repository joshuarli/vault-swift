// swift-tools-version: 6.3
import PackageDescription

let swift6Settings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .strictMemorySafety(),
]

let releaseSettings: [SwiftSetting] = [
    // The executable is small and synchronous; whole-module optimization lets
    // the release compiler inline the CLI and Keychain boundary together.
    .unsafeFlags(["-whole-module-optimization"], .when(configuration: .release)),
]

let package = Package(
    name: "vault",
    platforms: [.macOS("26.0")],
    products: [
        .library(name: "VaultCore", targets: ["VaultCore"]),
        .executable(name: "vault", targets: ["vault"]),
    ],
    targets: [
        .target(
            name: "VaultCore",
            path: "Sources/VaultCore",
            swiftSettings: swift6Settings + releaseSettings
        ),
        .executableTarget(
            name: "vault",
            dependencies: ["CSystem"],
            path: "Sources/vault",
            swiftSettings: swift6Settings + releaseSettings,
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedLibrary("iconv"),
                // Match the Rust dist profile: local Swift symbols are not
                // part of the shipped exec-wrapper contract.
                .unsafeFlags(
                    [
                        "-Xlinker", "-S",
                        "-Xlinker", "-x",
                        "-Xlinker", "-dead_strip_dylibs",
                        "-Xlinker", "-exported_symbols_list",
                        "-Xlinker", "/dev/null",
                        "-Xlinker", "-no_function_starts",
                    ],
                    .when(configuration: .release)
                ),
            ]
        ),
        .target(
            name: "CSystem",
            path: "Sources/CSystem"
        ),
        .testTarget(
            name: "VaultCoreTests",
            dependencies: ["VaultCore"],
            path: "Tests/VaultCoreTests",
            swiftSettings: swift6Settings
        ),
    ]
)
