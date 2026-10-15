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
      // libsrtp's C sources are listed one by one, as in CMakeLists.txt: the vendored tree holds
      // a few files that only its test programs use.
      sources: [
        "src",
        "third_party/libsrtp/srtp/srtp.c",
        "third_party/libsrtp/crypto/cipher/aes.c",
        "third_party/libsrtp/crypto/cipher/aes_icm.c",
        "third_party/libsrtp/crypto/cipher/cipher.c",
        "third_party/libsrtp/crypto/cipher/cipher_test_cases.c",
        "third_party/libsrtp/crypto/cipher/null_cipher.c",
        "third_party/libsrtp/crypto/hash/auth.c",
        "third_party/libsrtp/crypto/hash/auth_test_cases.c",
        "third_party/libsrtp/crypto/hash/hmac.c",
        "third_party/libsrtp/crypto/hash/null_auth.c",
        "third_party/libsrtp/crypto/hash/sha1.c",
        "third_party/libsrtp/crypto/kernel/alloc.c",
        "third_party/libsrtp/crypto/kernel/crypto_kernel.c",
        "third_party/libsrtp/crypto/kernel/err.c",
        "third_party/libsrtp/crypto/kernel/key.c",
        "third_party/libsrtp/crypto/math/datatypes.c",
        "third_party/libsrtp/crypto/replay/rdb.c",
        "third_party/libsrtp/crypto/replay/rdbx.c",
      ],
      publicHeadersPath: "include",
      cSettings: [
        .headerSearchPath("third_party/libsrtp/include"),
        .headerSearchPath("third_party/libsrtp/crypto/include"),
        .headerSearchPath("third_party/libsrtp/config"),
        .define("HAVE_CONFIG_H"),
      ],
      cxxSettings: [
        .headerSearchPath("src"),
        .headerSearchPath("third_party/libsrtp/include"),
        .headerSearchPath("third_party/libsrtp/crypto/include"),
        .define("KETPHONE_VERSION", to: "\"0.1.0\""),
        .define("KETPHONE_TLS_APPLE", to: "1"),
      ],
      linkerSettings: [
        .linkedFramework("Network"),
        .linkedFramework("Security"),
        .linkedFramework("CoreFoundation"),
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
