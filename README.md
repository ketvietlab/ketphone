# KetPhone core

The calling core of KetPhone, written in C++20: SIP signalling, RTP media and G.711. It exposes a single C API in [`include/ketphone/ketphone.h`](include/ketphone/ketphone.h). The iOS app (Swift), the Android app (JNI) and the command-line tool all link this one static library.

The core speaks only standard SIP/RTP and knows nothing about any particular backend: it makes no REST calls and handles neither sign-in nor VoIP push. Everything product-specific lives in the app layer, which fetches the SIP account, receives PushKit and drives CallKit, then passes the settings in `ketphone_config`. The header that ties a call to its push notification (`X-KV-Call-Id` on Két Việt's servers) is a configuration value too.

## Scope of the proof of concept

- One account per engine, one call at a time, UDP only.
- Every SIP message goes to the configured server. Asterisk acts as a B2BUA, so there is no Record-Route or DNS SRV handling.
- REGISTER uses MD5 digest with `qop=auth` and refreshes at half the granted lifetime.
- INVITE/ACK/BYE/CANCEL/OPTIONS for both outgoing and incoming calls, with the RFC 3261 retransmission timers.
- Single-stream audio SDP: PCMA (payload type 8) and telephone-event 101, ptime 20 ms.
- Symmetric RTP. Receive statistics follow RFC 3550 (loss, jitter); an adaptive jitter buffer (see below) with simple loss concealment.
- The realtime audio thread touches only two lock-free ring buffers: no allocation, no locks, no logging.

Not in this version: SRTP, Opus, RTCP, outgoing DTMF, TCP/TLS, and ICE/STUN (internal calls run over Tailscale, so they are not needed yet). There is no echo cancellation in the core; on iOS the app uses VoiceProcessingIO.

## Layout

```
include/ketphone/ketphone.h   public C API (stable, C types only)
src/sip/                      message parse/build, digest, MD5, SDP
src/media/                    G.711, RTP, jitter buffer, SPSC ring, media session
src/net/                      non-blocking UDP socket
src/core/user_agent.*         SIP state machine: no sockets, no clock, fully testable
src/core/engine.cpp           network thread + C API
tools/ketphone-poc/           measurement tool, uses only the C API
platform/apple/               Swift package: Swift API, VoiceProcessingIO audio (C), tests
tests/                        unit tests, network simulation, C API over loopback UDP
scripts/                      local gate and network impairment runs
```

## Build and check

Requires CMake ≥ 3.24, Ninja and a C++20 compiler (Apple clang, or clang/gcc on Linux).

```bash
scripts/check
```

`scripts/check` is the local acceptance gate. It builds Debug with `-Werror`, AddressSanitizer and UndefinedBehaviorSanitizer and runs the tests, then builds Release and runs them again. There is no hosted CI yet. On macOS it also runs the Swift package tests.

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

Any third-party library added to the core must be under BSD, MIT or Apache-2.0. GPL and LGPL are excluded because the core is linked statically into apps distributed through the App Store. The current version has no third-party dependencies: MD5, G.711, RTP and the test harness are all written here.
