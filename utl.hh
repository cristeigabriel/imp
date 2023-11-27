#pragma once

#include <utility>
#include <type_traits>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <functional>

namespace utl {
  template <size_t N>
  struct maxN {
    static constexpr uint32_t s = (1 << (N - 1)) - 1;
    static constexpr uint32_t u = (1 << (N - 1)) + s;
  };

  static void delim() noexcept {
    printf("=================================================\n");
  }

  ///
  /// Note: check for machine endianness, if mismatched then
  /// swap
  ///

  static const uint8_t readU8(const uint8_t *p) {
    uint8_t s;
    memcpy((void *)&s, (const void *)p, 1);
    return s;
  }

  static const uint16_t readU16(const uint8_t *p) {
    uint16_t s;
    memcpy((void *)&s, (const void *)p, 2);
    return s;
  }

  static const uint32_t readU32(const uint8_t *p) {
    uint32_t s;
    memcpy((void *)&s, (const void *)p, 4);
    return s;
  }

  ///

  template <typename T>
  inline bool within(T value, std::type_identity_t<T> low, std::type_identity_t<T> high) noexcept {
    return (value >= low && value <= high);
  }

  struct defer {
    defer(std::function<void()> &&func) : func(std::move(func)) {
    }
    ~defer() {
      if (func) func();
    }

    std::function<void()> func;
  };
} // namespace utl
