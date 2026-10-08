#include "net/udp_socket.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <algorithm>
#include <cstring>

namespace ketphone::net {

std::string Endpoint::address_string() const {
  char text[INET6_ADDRSTRLEN] = {};
  if (family != AF_INET && family != AF_INET6) return {};
  if (inet_ntop(family, address.data(), text, sizeof(text)) == nullptr) return {};
  std::string out(text);
  if (family == AF_INET6 && scope_id != 0) out += "%" + std::to_string(scope_id);
  return out;
}

sockaddr_storage Endpoint::to_sockaddr() const {
  sockaddr_storage out{};
  if (family == AF_INET) {
    sockaddr_in raw{};
#ifdef __APPLE__
    raw.sin_len = sizeof(raw);
#endif
    raw.sin_family = AF_INET;
    std::memcpy(&raw.sin_addr, address.data(), sizeof(raw.sin_addr));
    raw.sin_port = htons(port);
    std::memcpy(&out, &raw, sizeof(raw));
  } else if (family == AF_INET6) {
    sockaddr_in6 raw{};
#ifdef __APPLE__
    raw.sin6_len = sizeof(raw);
#endif
    raw.sin6_family = AF_INET6;
    std::memcpy(&raw.sin6_addr, address.data(), sizeof(raw.sin6_addr));
    raw.sin6_scope_id = scope_id;
    raw.sin6_port = htons(port);
    std::memcpy(&out, &raw, sizeof(raw));
  }
  return out;
}

socklen_t Endpoint::sockaddr_length() const {
  if (family == AF_INET) return sizeof(sockaddr_in);
  if (family == AF_INET6) return sizeof(sockaddr_in6);
  return 0;
}

std::optional<Endpoint> Endpoint::from_sockaddr(const sockaddr* raw, socklen_t length) {
  if (raw == nullptr || length < sizeof(sockaddr)) return std::nullopt;
  Endpoint out;
  out.family = raw->sa_family;
  if (out.family == AF_INET && length >= sizeof(sockaddr_in)) {
    sockaddr_in ip{};
    std::memcpy(&ip, raw, sizeof(ip));
    std::memcpy(out.address.data(), &ip.sin_addr, sizeof(ip.sin_addr));
    out.port = ntohs(ip.sin_port);
  } else if (out.family == AF_INET6 && length >= sizeof(sockaddr_in6)) {
    sockaddr_in6 ip{};
    std::memcpy(&ip, raw, sizeof(ip));
    std::memcpy(out.address.data(), &ip.sin6_addr, sizeof(ip.sin6_addr));
    out.scope_id = ip.sin6_scope_id;
    out.port = ntohs(ip.sin6_port);
  } else {
    return std::nullopt;
  }
  return out;
}

std::vector<Endpoint> resolve_all(const std::string& host, uint16_t port) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
#ifdef __APPLE__
  // Apple's documented getaddrinfo path also synthesizes addresses for IPv4 literals in
  // SDP on DNS64/NAT64 networks. Never construct a NAT64 prefix in the application.
  hints.ai_flags = AI_DEFAULT;
#endif
  addrinfo* result = nullptr;
  const std::string service = std::to_string(port);
  if (getaddrinfo(host.c_str(), service.c_str(), &hints, &result) != 0) return {};
  std::vector<Endpoint> endpoints;
  for (const addrinfo* item = result; item != nullptr; item = item->ai_next) {
    if (const auto endpoint = Endpoint::from_sockaddr(item->ai_addr, static_cast<socklen_t>(item->ai_addrlen))) {
      if (std::find(endpoints.begin(), endpoints.end(), *endpoint) == endpoints.end()) endpoints.push_back(*endpoint);
    }
  }
  freeaddrinfo(result);
  return endpoints;
}

std::optional<Endpoint> resolve(const std::string& host, uint16_t port) {
  const auto endpoints = resolve_all(host, port);
  if (endpoints.empty()) return std::nullopt;
  return endpoints.front();
}

UdpSocket::~UdpSocket() { close(); }

UdpSocket::UdpSocket(UdpSocket&& other) noexcept : fd_(other.fd_), family_(other.family_) {
  other.fd_ = -1;
  other.family_ = AF_UNSPEC;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
  if (this != &other) {
    close();
    fd_ = other.fd_;
    family_ = other.family_;
    other.fd_ = -1;
    other.family_ = AF_UNSPEC;
  }
  return *this;
}

std::optional<UdpSocket> UdpSocket::open(int family) {
  if (family != AF_INET && family != AF_INET6) return std::nullopt;
  const int fd = ::socket(family, SOCK_DGRAM, 0);
  if (fd < 0) return std::nullopt;
  UdpSocket socket(fd, family);
  if (family == AF_INET6) {
    // Media may be IPv4 even when signaling uses IPv6 on a dual-stack network.
    const int off = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)) != 0) return std::nullopt;
  }
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return std::nullopt;
  fcntl(fd, F_SETFD, FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
  const int on = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
  Endpoint endpoint;
  endpoint.family = family;
  const sockaddr_storage any = endpoint.to_sockaddr();
  if (::bind(fd, reinterpret_cast<const sockaddr*>(&any), endpoint.sockaddr_length()) != 0) return std::nullopt;
  return socket;
}

std::optional<Endpoint> UdpSocket::destination(const Endpoint& remote) const {
  if (remote.family == family_) return remote;
  if (family_ != AF_INET6 || remote.family != AF_INET) return std::nullopt;
  // IPv4-mapped IPv6 is the socket API's dual-stack representation, not NAT64 synthesis.
  Endpoint mapped;
  mapped.family = AF_INET6;
  mapped.port = remote.port;
  mapped.address[10] = 0xff;
  mapped.address[11] = 0xff;
  std::copy_n(remote.address.begin(), 4, mapped.address.begin() + 12);
  return mapped;
}

bool UdpSocket::connect(const Endpoint& remote) {
  const auto endpoint = destination(remote);
  if (!endpoint) return false;
  const sockaddr_storage address = endpoint->to_sockaddr();
  return ::connect(fd_, reinterpret_cast<const sockaddr*>(&address), endpoint->sockaddr_length()) == 0;
}

std::optional<Endpoint> UdpSocket::local() const {
  sockaddr_storage address{};
  socklen_t length = sizeof(address);
  if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&address), &length) != 0) return std::nullopt;
  return Endpoint::from_sockaddr(reinterpret_cast<const sockaddr*>(&address), length);
}

bool UdpSocket::send(std::span<const uint8_t> data) {
  return ::send(fd_, data.data(), data.size(), 0) == static_cast<ssize_t>(data.size());
}

bool UdpSocket::send_to(std::span<const uint8_t> data, const Endpoint& remote) {
  const auto endpoint = destination(remote);
  if (!endpoint) return false;
  const sockaddr_storage address = endpoint->to_sockaddr();
  return ::sendto(fd_, data.data(), data.size(), 0, reinterpret_cast<const sockaddr*>(&address), endpoint->sockaddr_length()) ==
         static_cast<ssize_t>(data.size());
}

std::optional<size_t> UdpSocket::receive(std::span<uint8_t> buffer, Endpoint* from) {
  sockaddr_storage address{};
  socklen_t length = sizeof(address);
  const ssize_t received =
      ::recvfrom(fd_, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&address), &length);
  if (received < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return size_t{0};
    return std::nullopt;
  }
  if (from != nullptr) {
    const auto endpoint = Endpoint::from_sockaddr(reinterpret_cast<const sockaddr*>(&address), length);
    if (!endpoint) return std::nullopt;
    *from = *endpoint;
  }
  return static_cast<size_t>(received);
}

void UdpSocket::close() {
  if (fd_ >= 0) ::close(fd_);
  fd_ = -1;
  family_ = AF_UNSPEC;
}

}  // namespace ketphone::net
