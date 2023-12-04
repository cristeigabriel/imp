#include "utl.hh"
#include "disasm.hh"

#define __IMP_CONCAT(x, y)  __IMP_CONCAT2(x, y)
#define __IMP_CONCAT2(x, y) x##y
#ifdef defer
#error "imp uses defer"
#else
#define defer ::utl::defer __IMP_CONCAT(__, __LINE__)
#endif

using namespace disasm;

ret disassembler::consume() {
#define CANT_HAVE_PREFIX()                                                                                             \
  if (operandSizePrefix || addressSizePrefix) return none;
  code       = code.subspan(lastLength);
  lastLength = 0;
  if (code.empty()) return none {};

  // cursor
  const uint8_t* c = &code[(operandSizePrefix || addressSizePrefix) ? 1 : 0];

  auto dist = [&](const void* p) -> uintptr_t {
    return (uintptr_t)(p) - (uintptr_t)(&code[0]);
  };

  auto setLen = [&](uint32_t used = 0) {
    auto nextDist = dist(c) + used + 1;
    lastLength    = nextDist;
  };

  auto tryEnsureAndSetLen = [&]<typename T>(bool check, T t, T f) {
    auto nextDist = dist(c) + 1;
    if (code.subspan(nextDist).size() < (check ? t : f)) return false; // could not ensure enough bytes

    setLen(check ? t : f);
    return true;
  };
#define ENSURE_AND_SET_LEN$(c, t, f)                                                                                   \
  if (!tryEnsureAndSetLen(c, t, f)) return none {};
#define ENSURE_AND_SET_LEN2$(n)                                                                                        \
  if (!tryEnsureAndSetLen(true, n, 0)) return none {};

  // non-instructions
  if (*c == 0x66) {
    if (operandSizePrefix) return none {};

    operandSizePrefix = true;
    return consume();
  } else if (*c == 0x67) {
    if (addressSizePrefix) return none {};

    addressSizePrefix = true;
    return consume();
  }
  //

  // reset after applying...
  defer {[&] {
    operandSizePrefix = addressSizePrefix = false;
  }};

  auto handleSizeWraparound = [&]<typename T>(T n) -> T {
    auto space = utl::maxN<sizeof(T) * 8>::u - n;
    if (space < lastLength) return (lastLength - space) - 1;
    return n + lastLength;
  };

  if (*c == 0x6a) {
    // push imm8, extended to imm16 if prefix

    // operand
    ENSURE_AND_SET_LEN2$(1);
    c++;

    if (operandSizePrefix) return pushImm16From8 {(uint16_t)utl::readU8(c)};
    return pushImm8 {utl::readU8(c)};
  } else if (*c == 0x68) {
    // push imm32/imm16 if prefix

    // operand
    ENSURE_AND_SET_LEN$(operandSizePrefix, 2, 4);
    c++;

    if (operandSizePrefix) return pushImm16 {utl::readU16(c)};
    return pushImm32 {utl::readU32(c)};
  } else if (auto r = proc::utl::within(*c, 0x40, 0x47)) {
    // inc reg32/reg16 if prefix

    setLen();

    if (operandSizePrefix) return incReg16 {*r};
    return incReg32 {*r};
  } else if (auto r = proc::utl::within(*c, 0x48, 0x4f)) {
    // dec reg32/reg16 if prefix

    setLen();

    if (operandSizePrefix) return decReg16 {*r};
    return decReg32 {*r};
  } else if (auto r = proc::utl::within(*c, 0x50, 0x57)) {
    // push reg32/reg16 if prefix

    setLen();

    if (operandSizePrefix) return pushReg16 {*r};
    return pushReg32 {*r};
  } else if (auto r = proc::utl::within(*c, 0x58, 0x5f)) {
    // pop reg32/reg16 if prefix

    setLen();

    if (operandSizePrefix) return popReg16 {*r};
    return popReg32 {*r};
  } else if (auto r = proc::utl::within(*c, 0xb8, 0xbf)) {
    // mov reg32/reg16 if prefix, imm32/imm16 if prefix

    // operand
    ENSURE_AND_SET_LEN$(operandSizePrefix, 2, 4);
    c++;

    if (operandSizePrefix) return movReg16 {*r, utl::readU16(c)};
    return movReg32 {*r, utl::readU32(c)};
  } else if (*c == 0x83) {
    // Following machine code byte, operand
    ENSURE_AND_SET_LEN2$(2);
    c++;

    // add reg32/reg16 if prefix, imm8
    if (auto r = proc::utl::within(*c, 0xc0, 0xc7)) {
      c++;

      if (operandSizePrefix) return addReg16Imm8 {*r, utl::readU8(c)};
      return addReg32Imm8 {*r, utl::readU8(c)};
    } // adc reg32/reg16 if prefix, imm8
    else if (auto r = proc::utl::within(*c, 0xd0, 0xd7)) {
      c++;

      if (operandSizePrefix) return adcReg16Imm8 {*r, utl::readU8(c)};
      return adcReg32Imm8 {*r, utl::readU8(c)};
    } // and reg32/reg16 if prefix, imm8
    else if (auto r = proc::utl::within(*c, 0xe0, 0xe7)) {
      c++;

      if (operandSizePrefix) return andReg16Imm8 {*r, utl::readU8(c)};
      return andReg32Imm8 {*r, utl::readU8(c)};
    }
  } else if (*c == 0x81) {
    // Following machine code byte, operand
    ENSURE_AND_SET_LEN$(operandSizePrefix, 3, 5);
    c++;

    // add reg32/reg16 if prefix, imm32/imm16 if prefix
    if (auto r = proc::utl::within(*c, 0xc0, 0xc7)) {
      c++;

      if (operandSizePrefix) return addReg16Imm16 {*r, utl::readU16(c)};
      return addReg32Imm32 {*r, utl::readU32(c)};
    }
  } else if (*c == 0x05) {
    // operand
    ENSURE_AND_SET_LEN$(operandSizePrefix, 2, 4);
    c++;

    // add eax/ax if prefix, imm32/imm16 if prefix
    if (operandSizePrefix) return addAxImm16 {utl::readU16(c)};
    return addEaxImm32 {utl::readU32(c)};
  } else if (*c == 0x85) {
    ENSURE_AND_SET_LEN2$(1);
    c++;

    // test reg32/reg16 if prefix, reg32/reg16 if prefix
    if (auto rs = proc::utl::within2(*c, 0xc0, 0xff)) {
      auto [r1, r2] = *rs;
      if (operandSizePrefix) return testReg16Reg16 {r1, r2};
      return testReg32Reg32 {r1, r2};
    }
  } else if (*c == 0xe8) {
    // operand
    ENSURE_AND_SET_LEN$(operandSizePrefix, 2, 4);
    c++;

    if (operandSizePrefix) return callNear16 {handleSizeWraparound(utl::readU16(c))};
    return callNear32 {handleSizeWraparound(utl::readU32(c))};
  } else if (*c == 0xe9) {
    ENSURE_AND_SET_LEN$(operandSizePrefix, 2, 4);
    c++;

    if (operandSizePrefix) return jmpNear16 {handleSizeWraparound(utl::readU16(c))};
    return jmpNear32 {handleSizeWraparound(utl::readU32(c))};
  }

  return none {};
#undef ENSURE_AND_SET_LEN$
#undef CANT_HAVE_PREFIX
}

#undef defer
#undef __IMP_CONCAT2
#undef __IMP_CONCAT
