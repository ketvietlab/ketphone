#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ketphone::net {

// An IPv4 or IPv6 address, including the interface scope of a link-local IPv6 address.
struct Endpoint {
  int family = AF_UNSPEC;
  std::array<uint8_t, 16> address{};
  uint32_t scope_id = 0;
  uint16_t port = 0;

  std::string address_string() const;
  sockaddr_storage to_sockaddr() const;
  socklen_t sockaddr_length() const;
  static std::optional<Endpoint> from_sockaddr(const sockaddr* address, socklen_t length);
  bool operator==(const Endpoint&) const = default;
};

// Uses the system resolver's address order and NAT64 synthesis on Apple platforms. Blocks for DNS.
std::vector<Endpoint> resolve_all(const std::string& host, uint16_t port);
std::optional<Endpoint> resolve(const std::string& host, uint16_t port);

// A non-blocking IPv4 or IPv6 UDP socket.
class UdpSocket {
 public:
  UdpSocket() = default;
  ~UdpSocket();
  UdpSocket(UdpSocket&& other) noexcept;
  UdpSocket& operator=(UdpSocket&& other) noexcept;
  UdpSocket(const UdpSocket&) = delete;
  UdpSocket& operator=(const UdpSocket&) = delete;

  // Binds to any local address on an ephemeral port.
  static std::optional<UdpSocket> open(int family = AF_INET);

  // Connects to `remote` so that only its datagrams are received and ICMP errors are reported.
  // Afterwards local() reports the source address the kernel picked for that route.
  bool connect(const Endpoint& remote);

  bool valid() const { return fd_ >= 0; }
  int fd() const { return fd_; }
  int family() const { return family_; }
  std::optional<Endpoint> local() const;

  bool send(std::span<const uint8_t> data);  // connected sockets
  bool send_to(std::span<const uint8_t> data, const Endpoint& remote);

  // Returns the datagram size, 0 when nothing is waiting, or nothing on a socket error.
  std::optional<size_t> receive(std::span<uint8_t> buffer, Endpoint* from = nullptr);

  void close();

 private:
  explicit UdpSocket(int fd, int family) : fd_(fd), family_(family) {}
  std::optional<Endpoint> destination(const Endpoint& remote) const;
  int fd_ = -1;
  int family_ = AF_UNSPEC;
};

}  // namespace ketphone::net
