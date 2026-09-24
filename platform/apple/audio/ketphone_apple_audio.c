#include "ketphone_apple_audio.h"

#include <AudioToolbox/AudioToolbox.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* Element numbers of an I/O unit: 1 is the microphone side, 0 the speaker side. */
enum { kInputElement = 1, kOutputElement = 0 };

/* Largest slice the unit may ask for. At 8 kHz even a 0.5 s slice fits; the unit is told so,
 * and a larger request is refused rather than overflowing the buffer. */
enum { kMaxFrames = 4096 };

struct ketphone_apple_audio {
  AudioUnit unit;
  ketphone_engine *engine;
  atomic_bool muted;
  bool running;
  int16_t input[kMaxFrames];
};

static OSStatus on_input(void *context, AudioUnitRenderActionFlags *flags, const AudioTimeStamp *time,
                         UInt32 bus, UInt32 frames, AudioBufferList *unused) {
  (void)unused;
  ketphone_apple_audio *audio = context;
  if (frames > kMaxFrames) return kAudioUnitErr_TooManyFramesToProcess;
  AudioBufferList list;
  list.mNumberBuffers = 1;
  list.mBuffers[0].mNumberChannels = 1;
  list.mBuffers[0].mDataByteSize = frames * sizeof(int16_t);
  list.mBuffers[0].mData = audio->input;
  const OSStatus status = AudioUnitRender(audio->unit, flags, time, bus, frames, &list);
  if (status != noErr) return status;
  if (atomic_load_explicit(&audio->muted, memory_order_relaxed)) memset(audio->input, 0, frames * sizeof(int16_t));
  ketphone_audio_capture(audio->engine, audio->input, frames);
  return noErr;
}

static OSStatus on_output(void *context, AudioUnitRenderActionFlags *flags, const AudioTimeStamp *time,
                          UInt32 bus, UInt32 frames, AudioBufferList *data) {
  (void)time;
  (void)bus;
  ketphone_apple_audio *audio = context;
  int16_t *samples = data->mBuffers[0].mData;
  const size_t count = data->mBuffers[0].mDataByteSize / sizeof(int16_t);
  (void)frames;
  if (ketphone_audio_playout(audio->engine, samples, count) == 0) *flags |= kAudioUnitRenderAction_OutputIsSilence;
  return noErr;
}

static OSStatus configure(ketphone_apple_audio *audio) {
  AudioComponentDescription description = {
      .componentType = kAudioUnitType_Output,
      .componentSubType = kAudioUnitSubType_VoiceProcessingIO,
      .componentManufacturer = kAudioUnitManufacturer_Apple,
  };
  AudioComponent component = AudioComponentFindNext(NULL, &description);
  if (component == NULL) return kAudioUnitErr_InvalidElement;
  OSStatus status = AudioComponentInstanceNew(component, &audio->unit);
  if (status != noErr) return status;

  const UInt32 on = 1;
  status = AudioUnitSetProperty(audio->unit, kAudioOutputUnitProperty_EnableIO, kAudioUnitScope_Input,
                                kInputElement, &on, sizeof(on));
  if (status != noErr) return status;

  const AudioStreamBasicDescription format = {
      .mSampleRate = KETPHONE_SAMPLE_RATE,
      .mFormatID = kAudioFormatLinearPCM,
      .mFormatFlags = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked,
      .mBytesPerPacket = sizeof(int16_t),
      .mFramesPerPacket = 1,
      .mBytesPerFrame = sizeof(int16_t),
      .mChannelsPerFrame = 1,
      .mBitsPerChannel = 16,
  };
  /* What the unit hands us from the microphone, and what we hand it for the speaker. */
  status = AudioUnitSetProperty(audio->unit, kAudioUnitProperty_StreamFormat, kAudioUnitScope_Output,
                                kInputElement, &format, sizeof(format));
  if (status != noErr) return status;
  status = AudioUnitSetProperty(audio->unit, kAudioUnitProperty_StreamFormat, kAudioUnitScope_Input,
                                kOutputElement, &format, sizeof(format));
  if (status != noErr) return status;

  const UInt32 max_frames = kMaxFrames;
  status = AudioUnitSetProperty(audio->unit, kAudioUnitProperty_MaximumFramesPerSlice, kAudioUnitScope_Global, 0,
                                &max_frames, sizeof(max_frames));
  if (status != noErr) return status;

  const AURenderCallbackStruct input = {.inputProc = on_input, .inputProcRefCon = audio};
  status = AudioUnitSetProperty(audio->unit, kAudioOutputUnitProperty_SetInputCallback, kAudioUnitScope_Global,
                                kInputElement, &input, sizeof(input));
  if (status != noErr) return status;
  const AURenderCallbackStruct output = {.inputProc = on_output, .inputProcRefCon = audio};
  status = AudioUnitSetProperty(audio->unit, kAudioUnitProperty_SetRenderCallback, kAudioUnitScope_Input,
                                kOutputElement, &output, sizeof(output));
  if (status != noErr) return status;

  return AudioUnitInitialize(audio->unit);
}

ketphone_apple_audio *ketphone_apple_audio_create(ketphone_engine *engine, int32_t *status) {
  if (status != NULL) *status = noErr;
  if (engine == NULL) {
    if (status != NULL) *status = kAudio_ParamError;
    return NULL;
  }
  ketphone_apple_audio *audio = calloc(1, sizeof(*audio));
  if (audio == NULL) {
    if (status != NULL) *status = kAudio_MemFullError;
    return NULL;
  }
  audio->engine = engine;
  atomic_init(&audio->muted, false);
  const OSStatus result = configure(audio);
  if (result != noErr) {
    if (status != NULL) *status = result;
    ketphone_apple_audio_destroy(audio);
    return NULL;
  }
  return audio;
}

int32_t ketphone_apple_audio_start(ketphone_apple_audio *audio) {
  if (audio == NULL) return kAudio_ParamError;
  if (audio->running) return noErr;
  const OSStatus status = AudioOutputUnitStart(audio->unit);
  if (status == noErr) audio->running = true;
  return status;
}

int32_t ketphone_apple_audio_stop(ketphone_apple_audio *audio) {
  if (audio == NULL) return kAudio_ParamError;
  if (!audio->running) return noErr;
  const OSStatus status = AudioOutputUnitStop(audio->unit);
  if (status == noErr) audio->running = false;
  return status;
}

void ketphone_apple_audio_set_muted(ketphone_apple_audio *audio, bool muted) {
  if (audio != NULL) atomic_store_explicit(&audio->muted, muted, memory_order_relaxed);
}

void ketphone_apple_audio_destroy(ketphone_apple_audio *audio) {
  if (audio == NULL) return;
  if (audio->unit != NULL) {
    ketphone_apple_audio_stop(audio);
    AudioUnitUninitialize(audio->unit);
    AudioComponentInstanceDispose(audio->unit);
  }
  free(audio);
}
