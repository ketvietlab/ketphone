import CKetPhone
import Foundation
import CKetPhoneAppleAudio

/// Identifies a call for the lifetime of an engine. Never reused.
public typealias CallID = Int32

public struct Configuration: Sendable, Equatable {
  /// Host name or IPv4 address of the SIP server, also used as the SIP domain.
  public var serverHost: String
  public var serverPort: UInt16
  public var `extension`: String
  public var password: String
  /// Seconds to ask for in REGISTER; nil means the core's default of 300.
  public var registerExpires: UInt32?
  /// Playout delay before the jitter buffer has measured the network; nil means 60 ms.
  public var initialJitterBufferMilliseconds: UInt32?
  /// Sent as User-Agent; nil means "KetPhone/<version>".
  public var userAgent: String?
  /// Header on incoming INVITEs that ties the call to the push that woke the app.
  public var correlationHeader: String?

  public init(
    serverHost: String,
    serverPort: UInt16 = 5060,
    extension: String,
    password: String,
    registerExpires: UInt32? = nil,
    initialJitterBufferMilliseconds: UInt32? = nil,
    userAgent: String? = nil,
    correlationHeader: String? = nil
  ) {
    self.serverHost = serverHost
    self.serverPort = serverPort
    self.extension = `extension`
    self.password = password
    self.registerExpires = registerExpires
    self.initialJitterBufferMilliseconds = initialJitterBufferMilliseconds
    self.userAgent = userAgent
    self.correlationHeader = correlationHeader
  }
}

public enum EndReason: Sendable, Equatable {
  /// This side hung up, cancelled or rejected.
  case local
  /// The other side hung up after the call connected.
  case remoteHangUp
  /// The caller gave up before this side answered.
  case remoteCancelled
  /// The server refused the call; the event's status code says why.
  case rejected
  case timeout
  case mediaFailed
  case shutdown
  case unknown(Int32)

  init(_ reason: ketphone_end_reason) {
    switch reason {
    case KETPHONE_END_LOCAL: self = .local
    case KETPHONE_END_REMOTE_HANGUP: self = .remoteHangUp
    case KETPHONE_END_REMOTE_CANCELLED: self = .remoteCancelled
    case KETPHONE_END_REJECTED: self = .rejected
    case KETPHONE_END_TIMEOUT: self = .timeout
    case KETPHONE_END_MEDIA_FAILED: self = .mediaFailed
    case KETPHONE_END_SHUTDOWN: self = .shutdown
    default: self = .unknown(Int32(bitPattern: reason.rawValue))
    }
  }
}

public enum Event: Sendable, Equatable {
  /// A REGISTER finished; 200 means registered.
  case registration(statusCode: Int32)
  case incoming(CallID, remote: String, displayName: String, correlationID: String)
  /// The far end is ringing (180) or sent early media (183).
  case progress(CallID, statusCode: Int32)
  case answered(CallID)
  case ended(CallID, reason: EndReason, statusCode: Int32)
}

public enum KetPhoneError: Error, Sendable, Equatable {
  /// The configuration was rejected or the server name did not resolve.
  case invalidConfiguration
  case invalidArgument
  /// Not allowed in the current state, e.g. a second call while one is active.
  case state
  case network
  case notFound
  case `internal`
  /// Core Audio refused to set up or start the voice processing unit.
  case audio(status: Int32)

  static func check(_ result: ketphone_result) throws {
    switch result {
    case KETPHONE_OK: return
    case KETPHONE_ERROR_INVALID_ARGUMENT: throw KetPhoneError.invalidArgument
    case KETPHONE_ERROR_STATE: throw KetPhoneError.state
    case KETPHONE_ERROR_NETWORK: throw KetPhoneError.network
    case KETPHONE_ERROR_NOT_FOUND: throw KetPhoneError.notFound
    default: throw KetPhoneError.internal
    }
  }
}

public struct MediaStats: Sendable, Equatable {
  public var packetsSent: UInt64
  public var packetsReceived: UInt64
  public var packetsLost: UInt64
  public var packetsLate: UInt64
  public var framesConcealed: UInt64
  public var jitterMilliseconds: Double
  public var playoutDelayMilliseconds: Double
}

/// One SIP account and at most one call, backed by the C++ core's network thread.
///
/// Every method is thread safe and returns once the core has acted. Destroying the engine hangs up,
/// unregisters (waiting up to about two seconds) and finishes `events`.
public final class Engine: @unchecked Sendable {
  public static var version: String { String(cString: ketphone_version()) }

  /// Everything the core reports, in order. Consume it from a single task.
  public let events: AsyncStream<Event>

  private let handle: OpaquePointer
  private let sink: Unmanaged<EventSink>
  // Guarded by `audioLock`: set up lazily because creating the unit touches the audio hardware.
  private let audioLock = NSLock()
  private var audio: OpaquePointer?

  public init(configuration: Configuration) throws {
    let (stream, continuation) = AsyncStream.makeStream(of: Event.self, bufferingPolicy: .unbounded)
    let sink = Unmanaged.passRetained(EventSink(continuation))
    let created = configuration.withCConfig { config in
      withUnsafePointer(to: config) { ketphone_engine_create($0, onEvent, sink.toOpaque()) }
    }
    guard let created else {
      continuation.finish()
      sink.release()
      throw KetPhoneError.invalidConfiguration
    }
    self.events = stream
    self.handle = created
    self.sink = sink
  }

  deinit {
    audioLock.withLock {
      ketphone_apple_audio_destroy(audio)
      audio = nil
    }
    ketphone_engine_destroy(handle)
    sink.takeUnretainedValue().continuation.finish()
    sink.release()
  }

  public func register() throws { try KetPhoneError.check(ketphone_register(handle)) }
  public func unregister() throws { try KetPhoneError.check(ketphone_unregister(handle)) }

  /// Calls an extension such as "1001" or a service number such as "*43" (echo test).
  public func call(_ target: String) throws -> CallID {
    var id: CallID = 0
    try KetPhoneError.check(ketphone_call(handle, target, &id))
    return id
  }

  public func answer(_ call: CallID) throws { try KetPhoneError.check(ketphone_answer(handle, call)) }

  /// Declines an unanswered incoming call; 486 means busy, 603 declined.
  public func reject(_ call: CallID, statusCode: Int32 = 603) throws {
    try KetPhoneError.check(ketphone_reject(handle, call, statusCode))
  }

  public func hangUp(_ call: CallID) throws { try KetPhoneError.check(ketphone_hangup(handle, call)) }

  public func mediaStats() throws -> MediaStats {
    var stats = ketphone_media_stats()
    try KetPhoneError.check(ketphone_media_stats_get(handle, &stats))
    return MediaStats(
      packetsSent: stats.packets_sent,
      packetsReceived: stats.packets_received,
      packetsLost: stats.packets_lost,
      packetsLate: stats.packets_late,
      framesConcealed: stats.frames_concealed,
      jitterMilliseconds: stats.jitter_ms,
      playoutDelayMilliseconds: stats.playout_delay_ms
    )
  }

  /// Starts microphone and speaker through VoiceProcessingIO. On iOS, configure and activate the
  /// audio session first; with CallKit that means from `provider(_:didActivate:)`.
  public func startAudio() throws {
    try audioLock.withLock {
      if audio == nil {
        var status: Int32 = 0
        guard let created = ketphone_apple_audio_create(handle, &status) else {
          throw KetPhoneError.audio(status: status)
        }
        audio = created
      }
      let status = ketphone_apple_audio_start(audio)
      if status != 0 { throw KetPhoneError.audio(status: status) }
    }
  }

  public func stopAudio() {
    audioLock.withLock { _ = ketphone_apple_audio_stop(audio) }
  }

  /// While muted the far end hears silence; the call and the speaker keep going.
  public func setMuted(_ muted: Bool) {
    audioLock.withLock { ketphone_apple_audio_set_muted(audio, muted) }
  }
}

/// Owns the stream's continuation; the core holds an unretained pointer to it as its context.
private final class EventSink: Sendable {
  let continuation: AsyncStream<Event>.Continuation
  init(_ continuation: AsyncStream<Event>.Continuation) { self.continuation = continuation }
}

/// Runs on the core's network thread: copy what is needed (the strings live only during the call)
/// and hand the event over.
private func onEvent(_ event: UnsafePointer<ketphone_event>?, _ context: UnsafeMutableRawPointer?) {
  guard let event = event?.pointee, let context else { return }
  let sink = Unmanaged<EventSink>.fromOpaque(context).takeUnretainedValue()
  let converted: Event?
  switch event.kind {
  case KETPHONE_EVENT_REGISTRATION:
    converted = .registration(statusCode: event.status_code)
  case KETPHONE_EVENT_CALL_INCOMING:
    converted = .incoming(
      event.call_id,
      remote: string(event.remote),
      displayName: string(event.remote_display_name),
      correlationID: string(event.correlation_id)
    )
  case KETPHONE_EVENT_CALL_PROGRESS:
    converted = .progress(event.call_id, statusCode: event.status_code)
  case KETPHONE_EVENT_CALL_ANSWERED:
    converted = .answered(event.call_id)
  case KETPHONE_EVENT_CALL_ENDED:
    converted = .ended(event.call_id, reason: EndReason(event.end_reason), statusCode: event.status_code)
  default:
    converted = nil
  }
  if let converted { sink.continuation.yield(converted) }
}

private func string(_ pointer: UnsafePointer<CChar>?) -> String {
  pointer.map { String(cString: $0) } ?? ""
}

extension Configuration {
  /// Calls `body` with a C configuration whose strings stay valid for the duration of the call.
  fileprivate func withCConfig<R>(_ body: (ketphone_config) -> R) -> R {
    serverHost.withCString { host in
      self.extension.withCString { ext in
        password.withCString { password in
          withOptionalCString(userAgent) { userAgent in
            withOptionalCString(correlationHeader) { header in
              var config = ketphone_config()
              config.struct_size = UInt32(MemoryLayout<ketphone_config>.size)
              config.server_host = host
              config.server_port = serverPort
              config.extension = ext
              config.password = password
              config.register_expires = registerExpires ?? 0
              config.jitter_buffer_ms = initialJitterBufferMilliseconds ?? 0
              config.user_agent = userAgent
              config.correlation_header = header
              return body(config)
            }
          }
        }
      }
    }
  }
}

private func withOptionalCString<R>(_ value: String?, _ body: (UnsafePointer<CChar>?) -> R) -> R {
  guard let value else { return body(nil) }
  return value.withCString { body($0) }
}
