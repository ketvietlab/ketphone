#pragma once

#include <cstdint>
#include <span>
#include <string>

namespace ketphone::sip {

// Random lowercase hex of `bytes` bytes, for tags, branches, Call-IDs and cnonces. These must be
// unique, not secret, so a seeded Mersenne Twister is enough.
std::string random_hex(size_t bytes);

uint32_t random_u32();

// Fills `out` from the operating system's cryptographic generator, for secrets such as SRTP master
// keys. Returns false only if the system generator fails, which callers must treat as fatal.
bool secure_random(std::span<uint8_t> out);

}  // namespace ketphone::sip
