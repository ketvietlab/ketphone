#pragma once

#include <netinet/in.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace ketphone::net {

// An IPv4 address and port in host byte order.
struct Endpoint {
  uint32_t address = 0;
  uint16_t port = 0;

  std::string address_string() const;
  sockaddr_in to_sockaddr() const;
  static Endpoint from_sockaddr(const sockaddr_in& address);
  bool operator==(const Endpoint&) const = default;
};

// Resolves a host name or dotted IPv4 address. Blocks for DNS.
std::optional<Endpoint> resolve(const std::string& host, uint16_t port);

// A non-blocking IPv4 UDP socket.
class UdpSocket {
 public:
  UdpSocket() = default;
  ~UdpSocket();
  UdpSocket(UdpSocket&& other) noexcept;
  UdpSocket& operator=(UdpSocket&& other) noexcept;
  UdpSocket(const UdpSocket&) = delete;
  UdpSocket& operator=(const UdpSocket&) = delete;

  // Binds to any local address on an ephemeral port.
  static std::optional<UdpSocket> open();

  // Connects to `remote` so that only its datagrams are received and ICMP errors are reported.
  // Afterwards local() reports the source address the kernel picked for that route.
  bool connect(const Endpoint& remote);

  bool valid() const { return fd_ >= 0; }
  int fd() const { return fd_; }
  std::optional<Endpoint> local() const;

  bool send(std::span<const uint8_t> data);  // connected sockets
  bool send_to(std::span<const uint8_t> data, const Endpoint& remote);

  // Returns the datagram size, 0 when nothing is waiting, or nothing on a socket error.
  std::optional<size_t> receive(std::span<uint8_t> buffer, Endpoint* from = nullptr);

  void close();

 private:
  explicit UdpSocket(int fd) : fd_(fd) {}
  int fd_ = -1;
};

}  // namespace ketphone::net
