// swift-tools-version: 6.0
//
// Swift Package for Apple platforms. It builds the same C++ sources as CMake (which remains the
// gate for the core, see scripts/check) and adds what an iOS app needs on top:
//   CKetPhone            the core, exposing only include/ketphone/ketphone.h
//   CKetPhoneAppleAudio  VoiceProcessingIO glue in C, so the realtime callbacks never run Swift
//   KetPhone             Swift API: Engine, events as an AsyncStream, audio start/stop
import PackageDescription

let package = Package(
  name: "KetPhone",
  platforms: [
    .iOS(.v17),
    .macOS(.v14),
  ],
  products: [
    .library(name: "KetPhone", targets: ["KetPhone"])
  ],
  targets: [
    .target(
      name: "CKetPhone",
      path: ".",
      sources: ["src"],
      publicHeadersPath: "include",
      cxxSettings: [
        .headerSearchPath("src"),
        .define("KETPHONE_VERSION", to: "\"0.1.0\""),
      ]
    ),
    .target(
      name: "CKetPhoneAppleAudio",
      dependencies: ["CKetPhone"],
      path: "platform/apple/audio",
      linkerSettings: [
        .linkedFramework("AudioToolbox")
      ]
    ),
    .target(
      name: "KetPhone",
      dependencies: ["CKetPhone", "CKetPhoneAppleAudio"],
      path: "platform/apple/swift",
      swiftSettings: [
        .swiftLanguageMode(.v6)
      ]
    ),
    .testTarget(
      name: "KetPhoneTests",
      dependencies: ["KetPhone"],
      path: "platform/apple/tests",
      swiftSettings: [
        .swiftLanguageMode(.v6)
      ]
    ),
  ],
  cxxLanguageStandard: .cxx20
)
