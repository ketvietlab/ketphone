#pragma once

#include <cstddef>
#include <cstdint>

namespace ketphone::media {

// G.711 A-law (ITU-T G.711), the only codec the telephony server allows today.
uint8_t alaw_encode(int16_t sample);
int16_t alaw_decode(uint8_t code);

void alaw_encode(const int16_t* samples, size_t count, uint8_t* out);
void alaw_decode(const uint8_t* codes, size_t count, int16_t* out);

}  // namespace ketphone::media
