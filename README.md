# KetPhone core

The calling core of KetPhone, written in C++20: SIP signalling, RTP media and G.711. It exposes a single C API in [`include/ketphone/ketphone.h`](include/ketphone/ketphone.h). The iOS app (Swift), the Android app (JNI) and the command-line tool all link this one static library.

The core speaks only standard SIP/RTP and knows nothing about any particular backend: it makes no REST calls and handles neither sign-in nor VoIP push. Everything product-specific lives in the app layer, which fetches the SIP account, receives PushKit and drives CallKit, then passes the settings in `ketphone_config`. The header that ties a call to its push notification (`X-KV-Call-Id` on Két Việt's servers) is a configuration value too.

## Scope of the proof of concept

- One account per engine, one call at a time, UDP only.
- Every SIP message goes to the configured server. Asterisk acts as a B2BUA, so there is no Record-Route or DNS SRV handling.
- REGISTER uses MD5 digest with `qop=auth` and refreshes at half the granted lifetime.
- INVITE/ACK/BYE/CANCEL/OPTIONS for both outgoing and incoming calls, with the RFC 3261 retransmission timers.
- Single-stream audio SDP: PCMA (payload type 8) and telephone-event 101, ptime 20 ms.
- Symmetric RTP. Receive statistics follow RFC 3550 (loss, jitter); a fixed-delay jitter buffer with simple loss concealment.
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
tests/                        unit tests, network simulation, C API over loopback UDP
scripts/                      local gate and network impairment runs
```

## Build and check

Requires CMake ≥ 3.24, Ninja and a C++20 compiler (Apple clang, or clang/gcc on Linux).

```bash
scripts/check
```

`scripts/check` is the local acceptance gate. It builds Debug with `-Werror`, AddressSanitizer and UndefinedBehaviorSanitizer and runs the tests, then builds Release and runs them again. There is no hosted CI yet.

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

Almost all of the round trip is buffering: 60 ms of jitter buffer, 20 ms of send pacing and the simulated device's 20 ms frame, for each end the audio passes through. The network contributes next to nothing.

## Simulating a poor network

Two complementary tools.

**Against a real server.** `scripts/netem-matrix` calls the echo test from the container under several `tc netem` profiles. The kernel delays, reorders and drops the container's packets, so SIP and RTP both go through the impaired path with no change to the code. netem shapes egress only, so each profile's delay is paid once per round trip.

```bash
KETPHONE_PASSWORD='...' scripts/netem-matrix
```

Results on 24 September 2026 (20 second calls, 60 ms jitter buffer):

| Profile (egress) | Register | Answer | Lost | Late | Concealed | Jitter | Echo median / max |
| --- | --- | --- | --- | --- | --- | --- | --- |
| clean network | 15 ms | 5 ms | 0 | 0 | 0 | 1.5 ms | 100 / 100 ms |
| relay path: 70 ms ±5 | 148 ms | 144 ms | 0 | 0 | 0 | 3.6 ms | 160 / 160 ms |
| 4G: 40 ms ±20, 1% loss | 91 ms | 120 ms | 10 | 28 | 38 (3.8%) | 20.9 ms | 120 / 140 ms |
| poor Wi-Fi: 30 ms ±40 pareto, 3% loss | 69 ms | 12 ms | 32 | 24 | 56 (5.6%) | 29 ms | 160 / 180 ms |

- Registration costs two round trips (the 401 challenge, then the retry), so a slow path delays the start of every call in proportion.
- Late frames can outnumber lost ones. In a second 4G run the same profile produced 1 late frame instead of 28: the fixed buffer's headroom depends on how fast the first frames happened to arrive.
- Concealing 4–6% of frames by repeating the previous one is audible. G.711 copes well up to roughly 1–2%.

**Deterministically, in the unit tests.** [`tests/network_simulation_test.cpp`](tests/network_simulation_test.cpp) drives the jitter buffer with a simulated sender and link on a virtual clock, so every scenario is exact and repeatable. It pins down the current buffer's behaviour, which an adaptive buffer has to improve on:

- The nominal 60 ms buffer (3 frames) tolerates only about 40 ms of jitter plus the wait for the next tick, because playout starts as soon as the third frame is in.
- A delay step larger than that headroom (a route change) makes every frame late until the buffer gives up after ten missing frames and starts over.

## Licence

KetPhone core is released under the [MIT licence](LICENSE).

Any third-party library added to the core must be under BSD, MIT or Apache-2.0. GPL and LGPL are excluded because the core is linked statically into apps distributed through the App Store. The current version has no third-party dependencies: MD5, G.711, RTP and the test harness are all written here.
