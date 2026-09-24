/*
 * Audio for Apple platforms: a VoiceProcessingIO unit wired to an engine's audio functions.
 *
 * VoiceProcessingIO is Apple's echo canceller, noise suppressor and gain control for calls, which
 * is why the core carries none on iOS. The unit runs at the core's 8 kHz mono 16-bit format and
 * converts to the hardware rate itself.
 *
 * Written in C so that the realtime callbacks never enter the Swift runtime. On iOS the caller
 * owns the audio session: with CallKit, start only after the provider activates it.
 */
#ifndef KETPHONE_APPLE_AUDIO_H
#define KETPHONE_APPLE_AUDIO_H

#include <stdbool.h>
#include <stdint.h>

#include "ketphone/ketphone.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ketphone_apple_audio ketphone_apple_audio;

/* Creates and initialises the unit without starting it. The engine must outlive the audio object.
 * Returns NULL and sets *status (when not NULL) to the Core Audio error on failure. */
ketphone_apple_audio *ketphone_apple_audio_create(ketphone_engine *engine, int32_t *status);

/* Starts or stops microphone and speaker. Both return a Core Audio status, 0 on success. */
int32_t ketphone_apple_audio_start(ketphone_apple_audio *audio);
int32_t ketphone_apple_audio_stop(ketphone_apple_audio *audio);

/* While muted the engine receives silence, so the far end hears nothing but the call stays up. */
void ketphone_apple_audio_set_muted(ketphone_apple_audio *audio, bool muted);

/* Stops the unit if needed and frees everything. */
void ketphone_apple_audio_destroy(ketphone_apple_audio *audio);

#ifdef __cplusplus
}
#endif

#endif /* KETPHONE_APPLE_AUDIO_H */
