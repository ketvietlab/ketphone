# KetPhone core

Lõi gọi thoại của KétPhone, viết bằng C++20: báo hiệu SIP, media RTP và G.711. Lõi đưa ra ngoài một C API duy nhất ở [`include/ketphone/ketphone.h`](include/ketphone/ketphone.h). App iOS (Swift), app Android (JNI) và công cụ dòng lệnh cùng link một static library này.

Lõi chỉ nói SIP/RTP chuẩn và không biết gì về KetSuite: không gọi REST, không quản lý đăng nhập hay VoIP push. Mọi phần riêng của Két Việt nằm ở tầng app. Cụ thể, app lấy tài khoản SIP từ KetSuite, nhận PushKit và xử lý CallKit, rồi truyền cấu hình vào `ketphone_config`. Header ghép cuộc gọi với push (`X-KV-Call-Id` trên server Két Việt) cũng là một tham số cấu hình.

## Phạm vi bản PoC

- Mỗi engine một tài khoản, mỗi lúc một cuộc gọi, chỉ UDP.
- Mọi gói SIP đi tới server đã cấu hình. Asterisk đóng vai B2BUA nên không cần Record-Route hay DNS SRV.
- REGISTER dùng digest MD5, có `qop=auth`, tự làm mới ở nửa thời hạn.
- INVITE/ACK/BYE/CANCEL/OPTIONS cho cả chiều gọi đi lẫn gọi đến, kèm các timer retransmission theo RFC 3261.
- SDP một luồng audio: PCMA (payload type 8) và telephone-event 101, ptime 20 ms.
- RTP symmetric. Có thống kê nhận theo RFC 3550 (mất gói, jitter), jitter buffer trễ cố định kèm che mất gói đơn giản.
- Luồng audio thời gian thực chỉ chạm vào hai ring buffer lock-free: không malloc, không lock, không log.

Chưa có trong bản này: SRTP, Opus, RTCP, DTMF gửi đi, TCP/TLS, và ICE/STUN (mạng nội bộ đi qua Tailscale nên chưa cần). Chưa có AEC: iOS dùng VoiceProcessingIO ở tầng app.

## Cấu trúc

```
include/ketphone/ketphone.h   C API công khai (ổn định, chỉ kiểu C)
src/sip/                      parse/build message, digest, MD5, SDP
src/media/                    G.711, RTP, jitter buffer, ring SPSC, media session
src/net/                      socket UDP không chặn
src/core/user_agent.*         state machine SIP, không socket, không đồng hồ, test được
src/core/engine.cpp           thread mạng + C API
tools/ketphone-poc/           công cụ đo, chỉ dùng C API
tests/                        unit test + test C API qua UDP loopback
```

## Build và kiểm tra

Cần CMake ≥ 3.24, Ninja và một compiler hỗ trợ C++20 (Apple clang hoặc clang/gcc trên Linux).

```bash
scripts/check
```

`scripts/check` là cổng nghiệm thu tại chỗ. Nó build Debug với `-Werror`, ASan và UBSan rồi chạy test; sau đó build Release và chạy test lần nữa. Repo chưa có CI hosted.

## Chạy thử với Asterisk local

Stack Asterisk local nằm trong repo ketviet (`infra/telephony`). Chạy các lệnh sau trong checkout ketviet:

```bash
pnpm infra:telephony up
pnpm infra:telephony account 1001 'Thử 1'
pnpm infra:telephony account 1002 'Thử 2'
```

Mật khẩu chỉ được in ra một lần. Postgres của stack chạy trên tmpfs, nên sau mỗi lần `up` phải tạo lại tài khoản.

Gọi echo test `*43`. Công cụ phát các đợt tone 1 kHz, đo thời gian mỗi đợt quay về và in thống kê media:

```bash
KETPHONE_PASSWORD='...' build/check/ketphone-poc --server 127.0.0.1 --user 1001 --call '*43' --seconds 10
```

Gọi giữa hai máy lẻ qua Asterisk. Ở một terminal, chạy bên nhận: nó tự trả lời và phát lại âm thanh nhận được.

```bash
KETPHONE_PASSWORD='...' build/check/ketphone-poc --server 127.0.0.1 --user 1002 --answer
```

Ở terminal khác, chạy bên gọi:

```bash
KETPHONE_PASSWORD='...' build/check/ketphone-poc --server 127.0.0.1 --user 1001 --call 1002
```

Mật khẩu chỉ đọc từ biến môi trường, để không lộ trong danh sách tiến trình.

### Khi Docker chạy bằng Colima

Port forwarding của Colima chỉ chuyển TCP. Gói UDP gửi tới `127.0.0.1:5060` không bao giờ tới Asterisk, và REGISTER sẽ báo `timeout`. Khi đó hãy build và chạy công cụ trong một container Linux nối vào mạng của stack, rồi dùng địa chỉ nội bộ của Asterisk. Cách này cũng kiểm luôn bản build Linux.

```bash
docker run -d --name ketphone-linux-poc --network ketviet-telephony-local -v "$PWD":/src:ro node:24-bookworm-slim sleep 3600
```

Cài toolchain trong container:

```bash
docker exec ketphone-linux-poc sh -c 'apt-get update -qq && apt-get install -y -qq cmake ninja-build g++'
```

Build:

```bash
docker exec ketphone-linux-poc sh -c 'cmake -S /src -B /tmp/b -G Ninja -DKETPHONE_WERROR=ON && cmake --build /tmp/b'
```

Gọi echo test:

```bash
docker exec -e KETPHONE_PASSWORD ketphone-linux-poc /tmp/b/ketphone-poc --server 172.29.73.10 --user 1001 --call '*43'
```

Kết quả đo ngày 24/09/2026 (Asterisk 20.20 local, jitter buffer 60 ms, chạy 10 giây):

| Cuộc gọi | Đăng ký | Trả lời | Mất gói | Jitter | Trễ khứ hồi |
| --- | --- | --- | --- | --- | --- |
| 1001 → `*43` | 6 ms | 5 ms | 0/500 | 3,0 ms | 100 ms |
| 1001 → 1002 (bên nhận phát lại) | 4 ms | 526 ms¹ | 0/499 | 2,7 ms | 180 ms |

¹ Gồm 500 ms mà bên nhận cố ý chờ trước khi trả lời.

Trễ khứ hồi gần như toàn bộ là do buffer: 60 ms jitter buffer cộng 20 ms nhịp gửi cộng 20 ms frame của thiết bị giả lập, tính cho mỗi đầu đi qua. Mạng không đóng góp đáng kể.

## Giấy phép

Chưa chọn giấy phép cho repo. Mọi thư viện bên thứ ba đưa vào lõi phải dùng giấy phép BSD, MIT hoặc Apache-2.0. Không dùng GPL hay LGPL, vì lõi được link tĩnh vào app phát hành qua App Store. Bản hiện tại không phụ thuộc thư viện ngoài nào: MD5, G.711, RTP và test harness đều tự viết.
