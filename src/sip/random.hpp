#pragma once

#include <cstdint>
#include <string>

namespace ketphone::sip {

// Random lowercase hex of `bytes` bytes, for tags, branches, Call-IDs and cnonces. These must be
// unique, not secret, so a seeded Mersenne Twister is enough.
std::string random_hex(size_t bytes);

uint32_t random_u32();

}  // namespace ketphone::sip
