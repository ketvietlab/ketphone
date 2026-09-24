#include <thread>
#include <vector>

#include "check.hpp"
#include "media/spsc_ring.hpp"

using ketphone::media::SpscRing;

TEST(ring_reports_partial_writes_when_full) {
  SpscRing<int> ring(4);
  const int values[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  CHECK(ring.capacity() >= 4 && ring.capacity() < 16);
  const size_t written = ring.push(values, 16);
  CHECK_EQ(written, ring.capacity());
  int out[8] = {};
  CHECK_EQ(ring.pop(out, 8), written);
  CHECK_EQ(out[0], 1);
  CHECK_EQ(ring.pop(out, 8), size_t{0});
  ring.push(values, 2);
  ring.discard();
  CHECK_EQ(ring.size(), size_t{0});
}

// One producer and one consumer thread move a counting sequence through a small ring; any lost,
// duplicated or reordered value breaks the count.
TEST(ring_transfers_in_order_between_threads) {
  SpscRing<uint32_t> ring(64);
  constexpr uint32_t kTotal = 200000;
  std::thread producer([&ring] {
    uint32_t next = 0;
    std::vector<uint32_t> chunk(17);
    while (next < kTotal) {
      const size_t n = std::min<size_t>(chunk.size(), kTotal - next);
      for (size_t i = 0; i < n; ++i) chunk[i] = next + static_cast<uint32_t>(i);
      const size_t written = ring.push(chunk.data(), n);
      next += static_cast<uint32_t>(written);
      if (written == 0) std::this_thread::yield();
    }
  });
  uint32_t expected = 0;
  bool ordered = true;
  std::vector<uint32_t> chunk(23);
  while (expected < kTotal) {
    const size_t n = ring.pop(chunk.data(), chunk.size());
    for (size_t i = 0; i < n; ++i) ordered = ordered && chunk[i] == expected++;
    if (n == 0) std::this_thread::yield();
  }
  producer.join();
  CHECK(ordered);
  CHECK_EQ(ring.size(), size_t{0});
}
