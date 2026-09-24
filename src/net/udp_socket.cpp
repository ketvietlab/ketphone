#include "net/udp_socket.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace ketphone::net {

std::string Endpoint::address_string() const {
  in_addr raw{};
  raw.s_addr = htonl(address);
  char text[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &raw, text, sizeof(text));
  return text;
}

sockaddr_in Endpoint::to_sockaddr() const {
  sockaddr_in out{};
#ifdef __APPLE__
  out.sin_len = sizeof(out);
#endif
  out.sin_family = AF_INET;
  out.sin_addr.s_addr = htonl(address);
  out.sin_port = htons(port);
  return out;
}

Endpoint Endpoint::from_sockaddr(const sockaddr_in& address) {
  return Endpoint{ntohl(address.sin_addr.s_addr), ntohs(address.sin_port)};
}

std::optional<Endpoint> resolve(const std::string& host, uint16_t port) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  addrinfo* result = nullptr;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || result == nullptr) return std::nullopt;
  sockaddr_in address{};
  std::memcpy(&address, result->ai_addr, sizeof(address));
  freeaddrinfo(result);
  Endpoint endpoint = Endpoint::from_sockaddr(address);
  endpoint.port = port;
  return endpoint;
}

UdpSocket::~UdpSocket() { close(); }

UdpSocket::UdpSocket(UdpSocket&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
  if (this != &other) {
    close();
    fd_ = other.fd_;
    other.fd_ = -1;
  }
  return *this;
}

std::optional<UdpSocket> UdpSocket::open() {
  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return std::nullopt;
  UdpSocket socket(fd);
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return std::nullopt;
  fcntl(fd, F_SETFD, FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
  const int on = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
  const sockaddr_in any = Endpoint{INADDR_ANY, 0}.to_sockaddr();
  if (::bind(fd, reinterpret_cast<const sockaddr*>(&any), sizeof(any)) != 0) return std::nullopt;
  return socket;
}

bool UdpSocket::connect(const Endpoint& remote) {
  const sockaddr_in address = remote.to_sockaddr();
  return ::connect(fd_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0;
}

std::optional<Endpoint> UdpSocket::local() const {
  sockaddr_in address{};
  socklen_t length = sizeof(address);
  if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&address), &length) != 0) return std::nullopt;
  return Endpoint::from_sockaddr(address);
}

bool UdpSocket::send(std::span<const uint8_t> data) {
  return ::send(fd_, data.data(), data.size(), 0) == static_cast<ssize_t>(data.size());
}

bool UdpSocket::send_to(std::span<const uint8_t> data, const Endpoint& remote) {
  const sockaddr_in address = remote.to_sockaddr();
  return ::sendto(fd_, data.data(), data.size(), 0, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) ==
         static_cast<ssize_t>(data.size());
}

std::optional<size_t> UdpSocket::receive(std::span<uint8_t> buffer, Endpoint* from) {
  sockaddr_in address{};
  socklen_t length = sizeof(address);
  const ssize_t received =
      ::recvfrom(fd_, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&address), &length);
  if (received < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return size_t{0};
    return std::nullopt;
  }
  if (from != nullptr) *from = Endpoint::from_sockaddr(address);
  return static_cast<size_t>(received);
}

void UdpSocket::close() {
  if (fd_ >= 0) ::close(fd_);
  fd_ = -1;
}

}  // namespace ketphone::net
