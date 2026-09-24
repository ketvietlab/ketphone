/*
 * KetPhone core: SIP signalling and RTP media for internal calls between Két Việt staff.
 *
 * This header is the whole public surface. It is plain C so that Swift (iOS), Kotlin through JNI
 * (Android) and command-line tools link the same static library without seeing C++.
 *
 * Threading
 *   - Every engine owns one network thread. Events are delivered on that thread; keep the
 *     callback short and hand work off to your own queue. Calling any function below from the
 *     callback is allowed, except ketphone_engine_destroy.
 *   - ketphone_audio_capture and ketphone_audio_playout are the only functions meant for the
 *     realtime audio thread. They never allocate, lock or log.
 *   - All other functions may be called from any thread. They run on the network thread and wait
 *     for it (briefly: no network round trip), so their result is final when they return.
 *
 * Scope of this version: one account per engine, one call at a time, UDP only, G.711 A-law at
 * 8 kHz, all SIP traffic sent to the configured server (Asterisk acts as a B2BUA).
 */
#ifndef KETPHONE_KETPHONE_H
#define KETPHONE_KETPHONE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KETPHONE_API_VERSION 1

/* Audio frames crossing the API are signed 16-bit mono PCM at this rate. */
#define KETPHONE_SAMPLE_RATE 8000

typedef struct ketphone_engine ketphone_engine;

/* Identifies a call for the lifetime of the engine; never reused. 0 is never a valid id. */
typedef int32_t ketphone_call_id;

typedef enum ketphone_result {
  KETPHONE_OK = 0,
  KETPHONE_ERROR_INVALID_ARGUMENT = -1,
  /* The engine is not in a state that allows the request, e.g. a second call while one is active. */
  KETPHONE_ERROR_STATE = -2,
  KETPHONE_ERROR_NETWORK = -3,
  KETPHONE_ERROR_NOT_FOUND = -4,
  KETPHONE_ERROR_INTERNAL = -5
} ketphone_result;

typedef enum ketphone_event_kind {
  /* A REGISTER finished. status_code 200 means registered; anything else means not registered. */
  KETPHONE_EVENT_REGISTRATION = 1,
  /* Someone is calling. remote and correlation_id are set; answer or reject by call_id. */
  KETPHONE_EVENT_CALL_INCOMING = 2,
  /* The far end is ringing (status_code 180) or sent early media (183). Outgoing calls only. */
  KETPHONE_EVENT_CALL_PROGRESS = 3,
  /* The call is connected and media is flowing. */
  KETPHONE_EVENT_CALL_ANSWERED = 4,
  /* The call is over. end_reason says why; status_code carries the SIP status when there was one. */
  KETPHONE_EVENT_CALL_ENDED = 5
} ketphone_event_kind;

typedef enum ketphone_end_reason {
  KETPHONE_END_NONE = 0,
  /* This side hung up, cancelled or rejected. */
  KETPHONE_END_LOCAL = 1,
  /* The other side hung up after the call connected. */
  KETPHONE_END_REMOTE_HANGUP = 2,
  /* The caller gave up before this side answered. */
  KETPHONE_END_REMOTE_CANCELLED = 3,
  /* The server refused the call; status_code has the reason (486 busy, 603 declined, 480 absent,
   * 404 unknown extension, 488 no common codec). */
  KETPHONE_END_REJECTED = 4,
  /* No response from the server in time (status_code 408). */
  KETPHONE_END_TIMEOUT = 5,
  /* Media could not be set up (no usable codec or no socket). */
  KETPHONE_END_MEDIA_FAILED = 6,
  /* The engine is shutting down. */
  KETPHONE_END_SHUTDOWN = 7
} ketphone_end_reason;

typedef struct ketphone_event {
  ketphone_event_kind kind;
  ketphone_call_id call_id;
  int32_t status_code;
  ketphone_end_reason end_reason;
  /* The other party's SIP URI, e.g. "sip:1001@ketviet". Valid only during the callback. */
  const char *remote;
  /* The other party's display name, or "" when none. Valid only during the callback. */
  const char *remote_display_name;
  /* Value of the configured correlation header on incoming calls, which the app matches to the
   * VoIP push that woke it. "" when absent or not configured. Valid only during the callback. */
  const char *correlation_id;
} ketphone_event;

typedef void (*ketphone_event_callback)(const ketphone_event *event, void *context);

typedef struct ketphone_config {
  /* Set to sizeof(ketphone_config); lets later versions add fields without breaking callers. */
  uint32_t struct_size;
  /* Host name or IPv4 address of the SIP server. Also used as the SIP domain. */
  const char *server_host;
  /* 0 means 5060. */
  uint16_t server_port;
  const char *extension;
  const char *password;
  /* Seconds to ask for in REGISTER; 0 means 300. */
  uint32_t register_expires;
  /* Target playout delay of the jitter buffer; 0 means 60 ms. Rounded to 20 ms frames. */
  uint32_t jitter_buffer_ms;
  /* Sent as User-Agent; NULL means "KetPhone/<version>". */
  const char *user_agent;
  /* Header on incoming INVITEs that correlates the call with a push notification, e.g.
   * "X-KV-Call-Id" for the Két Việt server. NULL or "" disables it. */
  const char *correlation_header;
} ketphone_config;

typedef struct ketphone_media_stats {
  uint64_t packets_sent;
  uint64_t packets_received;
  /* Packets that never arrived, from sequence number gaps. */
  uint64_t packets_lost;
  /* Packets that arrived after their playout slot and were dropped. */
  uint64_t packets_late;
  /* 20 ms frames played as concealment because nothing was there to play. */
  uint64_t frames_concealed;
  /* RFC 3550 interarrival jitter. */
  double jitter_ms;
} ketphone_media_stats;

/* Library version, e.g. "0.1.0". */
const char *ketphone_version(void);

/* Creates an engine and starts its network thread. Does not register; call ketphone_register.
 * Returns NULL when the configuration is invalid or the server cannot be resolved. */
ketphone_engine *ketphone_engine_create(const ketphone_config *config,
                                        ketphone_event_callback callback, void *context);

/* Hangs up any call, unregisters (waiting up to about two seconds), stops the thread and frees
 * the engine. No events are delivered after it returns. Must not be called from the callback. */
void ketphone_engine_destroy(ketphone_engine *engine);

/* Registers now and keeps the registration refreshed until ketphone_unregister. */
ketphone_result ketphone_register(ketphone_engine *engine);
ketphone_result ketphone_unregister(ketphone_engine *engine);

/* Calls an extension (e.g. "1001") or a service number (e.g. "*43", the echo test).
 * On success *call_id identifies the call in later events. */
ketphone_result ketphone_call(ketphone_engine *engine, const char *target, ketphone_call_id *call_id);

ketphone_result ketphone_answer(ketphone_engine *engine, ketphone_call_id call_id);

/* Declines an incoming call that has not been answered. status_code is the SIP final response,
 * normally 486 (busy) or 603 (declined). */
ketphone_result ketphone_reject(ketphone_engine *engine, ketphone_call_id call_id, int32_t status_code);

/* Ends a call in any state: cancels an unanswered outgoing call, declines an unanswered incoming
 * call with 603, or sends BYE to a connected one. */
ketphone_result ketphone_hangup(ketphone_engine *engine, ketphone_call_id call_id);

/* Realtime audio thread only. Hands microphone samples to the engine. Returns how many were
 * accepted; the rest are dropped when the engine is not keeping up. */
size_t ketphone_audio_capture(ketphone_engine *engine, const int16_t *samples, size_t count);

/* Realtime audio thread only. Fills samples with audio to play, padding with silence when the
 * engine has nothing. Returns how many samples were real audio. */
size_t ketphone_audio_playout(ketphone_engine *engine, int16_t *samples, size_t count);

/* Statistics of the current call's media, or of the last call once it ended. */
ketphone_result ketphone_media_stats_get(ketphone_engine *engine, ketphone_media_stats *stats);

#ifdef __cplusplus
}
#endif

#endif /* KETPHONE_KETPHONE_H */
