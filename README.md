# KetPhone core

The calling core of KetPhone, written in C++20: SIP signalling, RTP media and G.711. It exposes a single C API in [`include/ketphone/ketphone.h`](include/ketphone/ketphone.h). The iOS app (Swift), the Android app (JNI) and the command-line tool all link this one static library.

The core speaks only standard SIP/RTP and knows nothing about any particular backend: it makes no REST calls and handles neither sign-in nor VoIP push. Everything product-specific lives in the app layer, which fetches the SIP account, receives PushKit and drives CallKit, then passes the settings in `ketphone_config`. The header that ties a call to its push notification (`X-KV-Call-Id` on Két Việt's servers) is a configuration value too.

## Scope of the proof of concept

- One account per engine, one call at a time, over UDP or TLS (see below).
- Every SIP message goes to the configured server. Asterisk acts as a B2BUA, so there is no Record-Route or DNS SRV handling.
- REGISTER uses MD5 digest with `qop=auth` and refreshes at half the granted lifetime.
- INVITE/ACK/BYE/CANCEL/OPTIONS for both outgoing and incoming calls, with the RFC 3261 retransmission timers.
- Single-stream audio SDP: PCMA (payload type 8) and telephone-event 101, ptime 20 ms.
- IPv4 and IPv6 UDP signaling/media; IPv6 literals in SIP URIs and Via use brackets, while SDP uses `IN IP6`.
- Symmetric RTP. Receive statistics follow RFC 3550 (loss, jitter); an adaptive jitter buffer (see below) with simple loss concealment.
- The realtime audio thread touches only two lock-free ring buffers: no allocation, no locks, no logging.

Not in this version: Opus, RTCP, outgoing DTMF, plain TCP, DTLS-SRTP and ICE/STUN. There is no echo cancellation in the core; on iOS the app uses VoiceProcessingIO.

## SIP over TLS with SRTP

`transport = KETPHONE_TRANSPORT_TLS` (Swift: `.tls(trustAnchorsPEM:serverName:)`) carries SIP over TLS 1.2 or later, port 5061 unless given, and always pairs it with SRTP. UDP stays available for a trusted network.

- **TLS.** Network.framework on Apple platforms, so the system does the handshake and no TLS library ships inside the app; OpenSSL elsewhere (`-DKETPHONE_TLS=AUTO|APPLE|OPENSSL|OFF`). `tls_trust_anchors` makes the given PEM certificates the only ones trusted, which is how a private CA is pinned; without it the system trust store applies. The certificate must be for `tls_server_name`, or the server host when that is empty; an IP address is checked against the certificate's IP entries.
- **Connection.** The engine connects as soon as it starts and keeps one connection. Messages are framed by Content-Length (RFC 3261 §18.3). Requests are not retransmitted on it, though their timeouts still run. A double CRLF goes out every 30 s (RFC 5626 §3.5.1). When the connection drops the registration is reported lost (503), pending requests fail, and the engine reconnects after 1 s, doubling up to 30 s, and registers again. A registration that times out on a connection that looks fine also makes it reconnect. An established call keeps its media, which does not use the connection.
- **SRTP.** SDES (RFC 4568) with `AES_CM_128_HMAC_SHA1_80` only, through libsrtp. Each call gets a fresh key from the system's random source. Offers go out as `RTP/SAVP`; offers with keys under `RTP/AVP`, as Asterisk's optimistic SRTP sends them, are answered on the same profile. A far end that offers or answers no usable key gets 488, or a BYE with `KETPHONE_END_MEDIA_FAILED`. Packets that fail authentication or repeat are dropped. A UDP engine refuses `RTP/SAVP` offers and ignores optimistic keys.
- **Compatibility.** `ketphone_config` gained `transport`, `tls_trust_anchors` and `tls_server_name` in API version 2. A caller built against version 1 passes a smaller `struct_size`, and those fields read as zero: UDP, as before.

Apple's trust evaluation has rules for TLS server certificates even under a private CA: subjectAltName with the name (the common name is not checked), extended key usage `serverAuth`, a validity of at most 825 days, and a SHA-2 signature with an RSA key of at least 2048 bits or an ECDSA key. The tests build such a CA and certificate with OpenSSL at run time ([`tests/tls_server.cpp`](tests/tls_server.cpp)).

## Layout

```
include/ketphone/ketphone.h   public C API (stable, C types only)
src/sip/                      message parse/build, digest, MD5, SDP and SDES, base64, stream framing
src/media/                    G.711, RTP, SRTP, jitter buffer, SPSC ring, media session
src/net/                      non-blocking UDP socket, TLS (Network.framework or OpenSSL), PEM
src/core/user_agent.*         SIP state machine: no sockets, no clock, fully testable
src/core/engine.cpp           network thread + C API
tools/ketphone-poc/           measurement tool, uses only the C API
platform/apple/               Swift package: Swift API, VoiceProcessingIO audio (C), tests
tests/                        unit tests, network simulation, C API over loopback UDP and TLS
scripts/                      local gate and network impairment runs
third_party/libsrtp/          libsrtp 2.7.0, the subset this core builds (see its README)
```

## Build and check

Requires CMake ≥ 3.24, Ninja and a C++20 compiler (Apple clang, or clang/gcc on Linux). On Linux, TLS needs OpenSSL 1.1.1 or later (`libssl-dev`). The TLS tests play the server with OpenSSL on every platform; on macOS that means Homebrew's `openssl@3`, and without it they are left out.

```bash
scripts/check
```

`scripts/check` is the local acceptance gate. It builds Debug with `-Werror`, AddressSanitizer and UndefinedBehaviorSanitizer and runs the tests, then builds Release and runs them again. On macOS those builds use Network.framework, so it builds the OpenSSL client a third time, again with the sanitizers, and runs the Swift package tests. There is no hosted CI yet.

### IPv6 and DNS64/NAT64 acceptance

Pass a DNS hostname in `server_host` whenever possible. The resolver uses `AF_UNSPEC` and preserves the system's address order; the engine tries the returned addresses until it can open and connect a socket. On Apple platforms it uses `AI_DEFAULT`, including the system's IPv6 synthesis for IPv4 literals received in SDP. The core does not assume a NAT64 prefix. A UDP `connect` only selects a route, so this does not provide failover when a selected server silently drops packets.

SIP and RTP sockets support IPv4 and IPv6. The media socket follows the signaling socket's family and can send to an IPv4 media peer when signaling uses IPv6 on a dual-stack network. The loopback tests cover IPv6 REGISTER/unregister, outgoing and incoming calls, and non-silent PCMA audio in both directions. These tests do not exercise DNS64, a real NAT64 translator, APNs, CallKit or a production PBX.

Before an App Store submission, test a signed app on an iPhone connected to IPv6-only Wi-Fi with cellular data disabled, against the pilot's IPv4 PBX through DNS64/NAT64. Check sign-in/provisioning, REGISTER, outgoing/incoming calls, background wake-up, actual SDP, two-way audio and hangup. An IPv4 PBX cannot route directly to the client's native IPv6 address advertised in SDP; the deployment needs a working media return path, such as PBX symmetric RTP learned from the translated incoming packets. Confirm this with packet evidence instead of assuming that IPv6 signaling proves audio works. Also retain IPv4 and native IPv6 regression checks. See [Apple's IPv6 requirement](https://developer.apple.com/support/ipv6/) and [system address synthesis guidance](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/NetworkingOverview/UnderstandingandPreparingfortheIPv6Transition/UnderstandingandPreparingfortheIPv6Transition.html).

## Using it from Swift (iOS and macOS)

`Package.swift` builds the same sources for Apple platforms, so an app adds this repository as a Swift package dependency and imports `KetPhone`:

```swift
import KetPhone

let engine = try Engine(configuration: Configuration(
  serverHost: "pbx.example.com", extension: "1001", password: password,
  correlationHeader: "X-KV-Call-Id"))
try engine.register()
for await event in engine.events {
  if case .registration(statusCode: 200) = event { _ = try engine.call("*43") }
}
```

- `Engine.events` is an `AsyncStream` of registration and call events. The engine hangs up and unregisters when it is released.
- `startAudio()` and `stopAudio()` run a VoiceProcessingIO unit at 8 kHz, which gives Apple's echo cancellation, noise suppression and gain control. The audio callbacks are written in C (`platform/apple/audio`) so the realtime thread never enters the Swift runtime.
- The app owns the audio session. With CallKit, configure it as `playAndRecord` with mode `voiceChat`, and call `startAudio()` from `provider(_:didActivate:)`.

```bash
swift test                                                   # macOS
xcodebuild -scheme KetPhone -destination 'generic/platform=iOS' build
```

## Trying it against a local Asterisk

The local Asterisk stack lives in the ketviet repository (`infra/telephony`). Run these in a ketviet checkout:

```bash
pnpm infra:telephony up
pnpm infra:telephony account 1001 'Test 1'
pnpm infra:telephony account 1002 'Test 2'
```

Each password is printed once. The stack's Postgres runs on tmpfs, so accounts must be recreated after every `up`.

Call the `*43` echo test. The tool plays 1 kHz tone bursts, times each one's return and prints media statistics:

```bash
KETPHONE_PASSWORD='...' build/check/ketphone-poc --server 127.0.0.1 --user 1001 --call '*43' --seconds 10
```

Call between two extensions through Asterisk. In one terminal start the callee; it answers by itself and plays back what it receives:

```bash
KETPHONE_PASSWORD='...' build/check/ketphone-poc --server 127.0.0.1 --user 1002 --answer
```

In another terminal start the caller:

```bash
KETPHONE_PASSWORD='...' build/check/ketphone-poc --server 127.0.0.1 --user 1001 --call 1002
```

The password is read only from the environment so that it never shows up in the process list.

Over TLS, add `--tls` with the CA that signed Asterisk's certificate and the name on it; the port defaults to 5061:

```bash
KETPHONE_PASSWORD='...' build/check/ketphone-poc --server 127.0.0.1 --tls --ca ca.pem --server-name localhost \
  --user 1001 --call 1002
```

### When Docker runs on Colima

Colima's port forwarding carries TCP only. UDP sent to `127.0.0.1:5060` never reaches Asterisk and REGISTER reports `timeout`. Build and run the tool in a Linux container attached to the stack's network instead, and use Asterisk's internal address. This also exercises the Linux build. `NET_ADMIN` is needed only for the network impairment runs below.

```bash
docker run -d --name ketphone-linux-poc --cap-add NET_ADMIN --network ketviet-telephony-local -v "$PWD":/src:ro node:24-bookworm-slim sleep 7200
```

Install the toolchain in the container:

```bash
docker exec ketphone-linux-poc sh -c 'apt-get update -qq && apt-get install -y -qq cmake ninja-build g++ iproute2'
```

Build:

```bash
docker exec ketphone-linux-poc sh -c 'cmake -S /src -B /tmp/b -G Ninja -DKETPHONE_WERROR=ON && cmake --build /tmp/b'
```

Call the echo test:

```bash
docker exec -e KETPHONE_PASSWORD ketphone-linux-poc /tmp/b/ketphone-poc --server 172.29.73.10 --user 1001 --call '*43'
```

Results on 24 September 2026 (local Asterisk 20.20, 60 ms jitter buffer, 10 second calls):

| Call | Register | Answer | Lost | Jitter | Round trip |
| --- | --- | --- | --- | --- | --- |
| 1001 → `*43` | 6 ms | 5 ms | 0/500 | 3.0 ms | 100 ms |
| 1001 → 1002 (callee plays back) | 4 ms | 526 ms¹ | 0/499 | 2.7 ms | 180 ms |

¹ Includes 500 ms the callee deliberately waits before answering.

These were measured with the earlier fixed 60 ms jitter buffer. Almost all of the round trip was buffering: 60 ms of jitter buffer, 20 ms of send pacing and the simulated device's 20 ms frame, for each end the audio passes through. The network contributed next to nothing. With the adaptive buffer the echo test's round trip drops to 80 ms.

## Jitter buffer

The buffer ([`src/media/jitter_buffer.hpp`](src/media/jitter_buffer.hpp)) sizes itself from what it measures instead of holding a fixed delay:

- Each frame's transit (arrival time minus the send time implied by its sequence number) goes into a five second window. The target delay is the spread from the fastest transit to the 99th percentile, plus a 10 ms margin, capped at 300 ms. Late frames count too, since they are the evidence that the delay is too short. `jitter_buffer_ms` only sets the delay for the first second, before there is enough to measure.
- Playout moves towards the target one frame at a time. It grows by repeating a frame. It shrinks by passing over a slot whose frame was lost, which costs no audio, or else by discarding one frame at most every 200 ms.
- When the buffer has run dry and a frame arrives after its slot (the path got slower), playout steps back to that frame instead of dropping it. A delay step therefore costs only the frames in the gap.
- Clock drift between the two ends is corrected the same way, by an occasional repeated or skipped frame. Because transit is measured against sequence numbers, drift also widens the measured spread: 0.1% over the window adds 5 ms.

`ketphone_media_stats` reports `frames_expanded`, `frames_dropped` and the current `playout_delay_ms`.

## Simulating a poor network

Two complementary tools.

**Against a real server.** `scripts/netem-matrix` calls the echo test from the container under several `tc netem` profiles. The kernel delays, reorders and drops the container's packets, so SIP and RTP both go through the impaired path with no change to the code. netem shapes egress only, so each profile's delay is paid once per round trip.

```bash
KETPHONE_PASSWORD='...' scripts/netem-matrix
```

Results on 24 September 2026 (20 second calls), first with the earlier fixed 60 ms buffer and then with the adaptive buffer (two runs each; the adaptive runs agreed within the ranges shown):

| Profile (egress) | Lost | Late: fixed → adaptive | Concealed: fixed → adaptive | Adaptive target | Echo median: fixed → adaptive |
| --- | --- | --- | --- | --- | --- |
| clean network | 0 | 0 → 0 | 0 → 0 | 16–19 ms | 100 → 80 ms |
| relay path: 70 ms ±5 | 0 | 0 → 0 | 0 → 0 | 24 ms | 160 → 140–160 ms |
| 4G: 40 ms ±20, 1% loss | 6–10 | 1–28 → 1 | 5–38 → 8–9 | 98 ms | 120–140 → 160 ms |
| poor Wi-Fi: 30 ms ±40 pareto, 3% loss | 32–39 | 24–33 → 4–5 | 49–56 → 40 | 130–150 ms | 120–160 → 260 ms |

- On clean paths the adaptive buffer is 40 ms shorter than the fixed one. On jittery paths it trades latency for completeness: almost everything it conceals is real loss. Pareto jitter has a long tail, so the 99th percentile target gets long; 260 ms round trip is about 130 ms each way, still inside the ITU-T G.114 150 ms guideline.
- The fixed buffer's results varied widely between runs of the same profile (1 or 28 late frames under 4G), because its headroom depended on how fast the first frames happened to arrive. The adaptive buffer's did not.
- Registration costs two round trips (the 401 challenge, then the retry), so a slow path delays the start of every call in proportion.

**Deterministically, in the unit tests.** [`tests/network_simulation_test.cpp`](tests/network_simulation_test.cpp) drives the jitter buffer with a simulated sender and link on a virtual clock, so every scenario is exact and repeatable. The scenarios are constant delay, jitter of 45 and 80 ms with the worst possible start, a delay step up and down, 3% loss, reordering, and clock drift both ways. Among them are the two cases the fixed buffer handled badly:

- It tolerated only about 40 ms of jitter, not 60, because playout started as soon as the third frame was in. The adaptive buffer absorbs 45 ms of jitter with under 1% late frames.
- A delay step larger than that headroom made every frame late until ten had been missed. Now it costs only the frames in the gap.

## Licence

KetPhone core is released under the [MIT licence](LICENSE).

Any third-party library added to the core must be under BSD, MIT or Apache-2.0. GPL and LGPL are excluded because the core is linked statically into apps distributed through the App Store. The one third-party library is libsrtp (BSD-3-Clause, [`third_party/libsrtp/LICENSE`](third_party/libsrtp/LICENSE)), compiled into the core; an app that ships the core must carry its notice. TLS comes from the platform (Network.framework) or from OpenSSL (Apache-2.0) linked by the build that uses it. MD5, G.711, RTP, base64 and the test harness are written here.
