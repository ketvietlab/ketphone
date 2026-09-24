#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <memory>

namespace ketphone::media {

// Single-producer single-consumer ring of trivially copyable values. push and pop never
// allocate or block, so the realtime audio thread can use either end. Exactly one thread may
// push and exactly one other thread may pop (or discard).
template <typename T>
class SpscRing {
 public:
  explicit SpscRing(size_t minimum_capacity) {
    size_t capacity = 1;
    while (capacity < minimum_capacity + 1) capacity <<= 1;
    mask_ = capacity - 1;
    buffer_ = std::make_unique<T[]>(capacity);
  }

  size_t capacity() const { return mask_; }

  // Producer side. Returns how many values were written; the rest did not fit.
  size_t push(const T* values, size_t count) {
    const size_t write = write_.load(std::memory_order_relaxed);
    const size_t read = read_.load(std::memory_order_acquire);
    const size_t space = mask_ - ((write - read) & mask_);
    const size_t n = std::min(count, space);
    for (size_t i = 0; i < n; ++i) buffer_[(write + i) & mask_] = values[i];
    write_.store(write + n, std::memory_order_release);
    return n;
  }

  // Consumer side. Returns how many values were read.
  size_t pop(T* values, size_t count) {
    const size_t read = read_.load(std::memory_order_relaxed);
    const size_t write = write_.load(std::memory_order_acquire);
    const size_t n = std::min(count, (write - read) & mask_);
    for (size_t i = 0; i < n; ++i) values[i] = buffer_[(read + i) & mask_];
    read_.store(read + n, std::memory_order_release);
    return n;
  }

  // Consumer side. Drops everything currently readable.
  void discard() { read_.store(write_.load(std::memory_order_acquire), std::memory_order_release); }

  // Either side; the value may be stale by the time it is used.
  size_t size() const {
    return (write_.load(std::memory_order_acquire) - read_.load(std::memory_order_acquire)) & mask_;
  }

 private:
  std::unique_ptr<T[]> buffer_;
  size_t mask_ = 0;
  // Indices grow without bound and are masked on use; separate cache lines avoid false sharing.
  alignas(64) std::atomic<size_t> write_{0};
  alignas(64) std::atomic<size_t> read_{0};
};

}  // namespace ketphone::media
