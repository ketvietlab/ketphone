import Darwin
import Foundation
import KetPhone
import Testing

// Waiting on `events` never ends if the core stops reporting, so a lost event must fail, not hang.
@Suite(.timeLimit(.minutes(1))) struct EngineTests {
  @Test func rejectsAnIncompleteConfiguration() {
    #expect(throws: KetPhoneError.invalidConfiguration) {
      _ = try Engine(configuration: Configuration(serverHost: "127.0.0.1", extension: "", password: "x"))
    }
  }

  @Test func reportsTheVersion() {
    #expect(!Engine.version.isEmpty)
  }

  /// Events cross from the core's thread into the stream, with strings and codes intact.
  @Test func registersAndReportsARejectedCall() async throws {
    let server = try ScriptedServer()
    defer { server.stop() }
    let engine = try Engine(
      configuration: Configuration(serverHost: "127.0.0.1", serverPort: server.port, extension: "1001", password: "secret")
    )
    var events = engine.events.makeAsyncIterator()

    try engine.register()
    #expect(await events.next() == .registration(statusCode: 200))

    let call = try engine.call("1002")
    #expect(call != 0)
    #expect(await events.next() == .ended(call, reason: .rejected, statusCode: 486))
    #expect(server.methods().contains("INVITE"))

    #expect(throws: KetPhoneError.notFound) { try engine.hangUp(call + 1000) }
  }

  /// A refused REGISTER reaches the app with the server's code, so it can tell bad credentials apart.
  @Test func reportsARefusedRegistration() async throws {
    let server = try ScriptedServer(registerStatus: "403 Forbidden")
    defer { server.stop() }
    let engine = try Engine(
      configuration: Configuration(serverHost: "127.0.0.1", serverPort: server.port, extension: "1001", password: "wrong")
    )
    var events = engine.events.makeAsyncIterator()

    try engine.register()
    #expect(await events.next() == .registration(statusCode: 403))
  }
}

/// A loopback SIP server that answers every REGISTER with `registerStatus` and every INVITE with
/// 486 Busy Here.
private final class ScriptedServer: @unchecked Sendable {
  let port: UInt16
  private let registerStatus: String
  private let fd: Int32
  private let lock = NSLock()
  private var seen: [String] = []
  private var running = true
  private var thread: Thread?

  init(registerStatus: String = "200 OK") throws {
    self.registerStatus = registerStatus
    let fd = socket(AF_INET, SOCK_DGRAM, 0)
    self.fd = fd
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    let bound = withUnsafeMutablePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
        bind(fd, raw, length) == 0 && getsockname(fd, raw, &length) == 0
      }
    }
    guard fd >= 0, bound else { throw POSIXError(.EADDRNOTAVAIL) }
    port = UInt16(bigEndian: address.sin_port)
    var timeout = timeval(tv_sec: 0, tv_usec: 100_000)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    let thread = Thread { [self] in run() }
    self.thread = thread
    thread.start()
  }

  func methods() -> [String] { lock.withLock { seen } }

  func stop() {
    lock.withLock { running = false }
    // The receive loop wakes at least every 100 ms; give it that long to notice before closing.
    Thread.sleep(forTimeInterval: 0.2)
    close(fd)
  }

  private func isRunning() -> Bool { lock.withLock { running } }

  private func run() {
    var buffer = [UInt8](repeating: 0, count: 65536)
    while isRunning() {
      var from = sockaddr_storage()
      var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
      let size = withUnsafeMutablePointer(to: &from) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buffer, buffer.count, 0, $0, &length) }
      }
      guard size > 0, let text = String(bytes: buffer[0..<size], encoding: .utf8) else { continue }
      let lines = text.components(separatedBy: "\r\n")
      guard let method = lines.first?.split(separator: " ").first.map(String.init), method != "SIP/2.0" else { continue }
      lock.withLock { seen.append(method) }
      let status: String
      switch method {
      case "REGISTER": status = registerStatus
      case "INVITE": status = "486 Busy Here"
      default: continue  // ACK needs no reply
      }
      var reply = "SIP/2.0 \(status)\r\n"
      for line in lines {
        let lowered = line.lowercased()
        if lowered.hasPrefix("via:") || lowered.hasPrefix("from:") || lowered.hasPrefix("call-id:")
          || lowered.hasPrefix("cseq:") || lowered.hasPrefix("expires:")
        {
          reply += line + "\r\n"
        } else if lowered.hasPrefix("to:") {
          reply += line + ";tag=server\r\n"
        }
      }
      reply += "Content-Length: 0\r\n\r\n"
      let bytes = Array(reply.utf8)
      _ = withUnsafePointer(to: &from) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, bytes, bytes.count, 0, $0, length) }
      }
    }
  }
}
