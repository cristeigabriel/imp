#pragma once

#include "proc.hh"
#include "disasm.hh"
#include <cstdint>
#include <memory>
#include <array>
#include <assert.h>

struct emu {
  emu() = delete;
  emu(disasm::memoryViewType code, uint32_t ep) : cpu(code, ep), increaseEip(true) {
  }

  emu& operator=(const emu&) = delete;
  emu(const emu&)            = delete;
  emu& operator=(emu&&)      = delete;
  emu(emu&&)                 = delete;

  disasm::ret exec();

  bool execBool() {
    auto insn = exec();
    return !std::holds_alternative<disasm::none>(insn);
  }

  struct softCPU {
    softCPU();
    softCPU(disasm::memoryViewType code, uint32_t ep);

    softCPU& operator=(const softCPU&) = delete;
    softCPU(const softCPU&)            = delete;

    softCPU& operator=(softCPU&& other) noexcept {
      eip      = other.eip;
      gprs     = other.gprs;
      flags    = other.flags;
      ram.ptr  = std::move(other.ram.ptr);
      ram.size = other.ram.size;
    }

    softCPU(softCPU&& other) noexcept {
      (*this) = std::move(other);
    }

    inline disasm::memoryViewType memory() const noexcept {
      return disasm::memoryViewType {(const uint8_t*)ram.ptr.get(), ram.size};
    }

    inline uint32_t usedStack() const noexcept {
      return 0xffffffff - gprs[proc::gpr::esp];
    }

    inline void* stackToRam() noexcept {
      return &(ram.ptr.get()[ram.size - usedStack()]);
    }

    inline void dump() const noexcept {
      ::utl::delim();

      auto print = [](const char* str, uintptr_t n) {
        printf("%24s: %08x\n", str, n);
      };

      for (size_t i = 0; i < (size_t)proc::gpr::GPR_MAX; i++) {
        print(gprToStr((proc::gpr)i), gprs[(proc::gpr)i]);
      }

      ::utl::delim();

      print("eip", eip);
      print("flags", flags);
      print("ram.ptr", (size_t)ram.ptr.get());
      print("ram.size", ram.size);

      ::utl::delim();
      printf("\n");
    }

    /// Instruction pointer/program counter/...
    uint32_t eip = 0;

    /// The general purpose registers
    std::array<uint32_t, proc::gpr::GPR_MAX> gprs = {0};

    /// Eflags are the most significant 16 bits,
    /// flags are the least significant 16 bits,
    /// having been there before the extension.
    /// The second least significant bit is always
    /// 1, and is reserved.
    uint32_t flags = 0b10;

    /// Virtual RAM
    struct {
      std::unique_ptr<uint8_t[]> ptr;
      size_t                     size;
    } ram;
  } cpu;

	///
	/// Probably should be moved to CPU eventually
	///
	bool increaseEip = true;

  ///
  /// Operation helpers
  ///
  private:
  template <typename T, typename T2>
    requires(std::is_unsigned_v<T> && sizeof(T2) <= sizeof(T))
  bool willOverflow(T dst, T2 n) noexcept {
    if (std::is_signed_v<T2> && n < 0 && dst < std::labs(n)) return true;
    if (dst <= utl::maxN<sizeof(T) * 8>::s) {
      if ((dst + n) > utl::maxN<sizeof(T) * 8>::s) return true;
    }

    return false;
  }

  template <typename T, typename T2>
    requires(std::is_unsigned_v<T> && sizeof(T2) <= sizeof(T))
  void updateOverflowFlag(T dst, T2 n) noexcept {
    if (willOverflow<T, T2>(dst, n)) cpu.flags |= proc::flags::overflowFlag;
    else
      cpu.flags &= ~proc::flags::overflowFlag;
  }

  template <typename T>
    requires(std::is_unsigned_v<T>)
  void updateSignFlag(T n) noexcept {
    if (n & (1 << ((sizeof(T) * 8) - 1))) cpu.flags |= proc::flags::signFlag;
    else
      cpu.flags &= ~proc::flags::signFlag;
  }

  template <typename T>
    requires(std::is_unsigned_v<T>)
  void updateZeroFlag(T n) noexcept {
    if (n == 0) cpu.flags |= proc::flags::zeroFlag;
    else
      cpu.flags &= ~proc::flags::zeroFlag;
  }

  template <typename T>
    requires(std::is_unsigned_v<T>)
  void updateParityFlag(T n) noexcept {
    uint8_t paritysub = n & 0b11111111;
    int     setbits   = 0;
    for (size_t i = 0; i < 8; i++) {
      if (paritysub & 1) setbits++;
      paritysub >>= 1;
    }

    if (setbits & 1) cpu.flags &= ~proc::flags::parityFlag;
    else
      cpu.flags |= proc::flags::parityFlag;
  }

  ///
  /// Operations
  ///
  private:
  template <typename T>
    requires(std::is_unsigned_v<T> && (sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4))
  void pushImm(T n) noexcept {
    // make space
    cpu.gprs[proc::gpr::esp] -= sizeof(T);
    // write
    *(T*)cpu.stackToRam() = n;
  }

  template <typename T>
    requires(std::is_unsigned_v<T> && (sizeof(T) == 2 || sizeof(T) == 4))
  void pushReg(proc::gpr r) noexcept {
    // make space
    cpu.gprs[proc::gpr::esp] -= sizeof(T);
    // write
    (*(T*)cpu.stackToRam()) = cpu.gprs[r] & utl::maxN<sizeof(T) * 8>::u;
  }

  template <typename T>
    requires(std::is_unsigned_v<T> && (sizeof(T) == 2 || sizeof(T) == 4))
  void popReg(proc::gpr r) noexcept {
    // check if there's something to pop
    assert(cpu.usedStack() >= sizeof(T));

    // write
    (*(T*)&cpu.gprs[r]) = *(T*)cpu.stackToRam();

    // reallocate space
    cpu.gprs[proc::gpr::esp] += sizeof(T);
  }

  template <typename T>
    requires(std::is_unsigned_v<T> && (sizeof(T) == 2 || sizeof(T) == 4))
  void movReg(proc::gpr r, T n) noexcept {
    // write
    (*(T*)&cpu.gprs[r]) = n;
  }

  template <typename T, typename T2>
    requires(std::is_unsigned_v<T> && std::is_unsigned_v<T2> && (sizeof(T) == 2 || sizeof(T) == 4)
             && sizeof(T2) <= sizeof(T))
  void addOp(T& dst, T2 n) noexcept {
    updateOverflowFlag<T, T2>(dst, n);

    // Carry flag and addition
    T space = utl::maxN<sizeof(T) * 8>::u - dst;

    // holy fuck, refactor this!!!!!!!!!!! written at 3:33am

    // NOTE: the comment above is from earlyh november, it's late
    // november now, and it's 5:50AM, so it survived a port, so
    // I guess it's staying for now

    // carry flag is only applied when you wrap around
    // at register size
    if (n > 0) {
      if (space == 0) {
        if constexpr (sizeof(T) == 4) cpu.flags |= proc::flags::carryFlag;
        dst = n - 1;
      } else if (n > space) {
        if constexpr (sizeof(T) == 4) cpu.flags |= proc::flags::carryFlag;
        dst = (n - space) - 1;
      } else {
        cpu.flags &= ~proc::flags::carryFlag;
        dst += n;
      }
    } else
      cpu.flags &= ~proc::flags::carryFlag;

    updateSignFlag(dst);
    updateZeroFlag(dst);
    updateParityFlag(dst);
  }

  template <typename T, typename T2>
    requires(std::is_unsigned_v<T> && std::is_unsigned_v<T2> && (sizeof(T) == 2 || sizeof(T) == 4)
             && sizeof(T2) <= sizeof(T))
  void addOp(proc::gpr r, T2 n) noexcept {
    addOp<T, T2>(*(T*)&cpu.gprs[r], n);
  }

  template <typename T, typename T2>
    requires(std::is_unsigned_v<T> && std::is_unsigned_v<T2> && (sizeof(T) == 2 || sizeof(T) == 4)
             && sizeof(T2) <= sizeof(T))
  void adcOp(T& dst, T2 n) noexcept {
    // TODO: handle overflowing with n here
    addOp<T, T2>(dst, n + (T2)(cpu.flags & proc::flags::carryFlag ? 1 : 0));
  }

  template <typename T, typename T2>
    requires(std::is_unsigned_v<T> && std::is_unsigned_v<T2> && (sizeof(T) == 2 || sizeof(T) == 4)
             && sizeof(T2) <= sizeof(T))
  void adcOp(proc::gpr r, T2 n) noexcept {
    adcOp(*(T*)&cpu.gprs[r], n);
  }

  template <typename T, typename T2>
    requires(std::is_unsigned_v<T> && std::is_unsigned_v<T2> && (sizeof(T) == 2 || sizeof(T) == 4)
             && sizeof(T2) <= sizeof(T))
  void andOp(T& dst, T2 n) noexcept {
    dst &= n;

    cpu.flags &= ~proc::flags::carryFlag;
    cpu.flags &= ~proc::flags::overflowFlag;
    updateSignFlag(dst);
    updateZeroFlag(dst);
    updateParityFlag(dst);
  }

  template <typename T, typename T2>
    requires(std::is_unsigned_v<T> && std::is_unsigned_v<T2> && (sizeof(T) == 2 || sizeof(T) == 4)
             && sizeof(T2) <= sizeof(T))
  void andOp(proc::gpr r, T2 n) noexcept {
    andOp(*(T*)&cpu.gprs[r], n);
  }

  template <typename T>
    requires(std::is_unsigned_v<T> && (sizeof(T) == 2 || sizeof(T) == 4))
  void incOp(T& dst) noexcept {
    updateOverflowFlag<T, T>(dst, 1);

    if ((dst - utl::maxN<sizeof(T) * 8>::u) > 0) dst += 1;
    else
      dst = 0;

    updateSignFlag(dst);
    updateZeroFlag(dst);
    updateParityFlag(dst);
  }

  template <typename T>
    requires(std::is_unsigned_v<T> && (sizeof(T) == 2 || sizeof(T) == 4))
  void incOp(proc::gpr r) noexcept {
    incOp<T>(*(T*)&cpu.gprs[r]);
  }

  template <typename T>
    requires(std::is_unsigned_v<T> && (sizeof(T) == 2 || sizeof(T) == 4))
  void decOp(T& dst) noexcept {
    updateOverflowFlag<T, std::make_signed_t<T>>(dst, -1);

    if (dst == 0) dst = utl::maxN<sizeof(T) * 8>::u;
    else
      dst -= 1;

    updateSignFlag(dst);
    updateZeroFlag(dst);
    updateParityFlag(dst);
  }

  template <typename T>
    requires(std::is_unsigned_v<T> && (sizeof(T) == 2 || sizeof(T) == 4))
  void decOp(proc::gpr r) noexcept {
    decOp<T>(*(T*)&cpu.gprs[r]);
  }

  ///
  /// Note: basically AND with auxiliary state
  ///
  template <typename T>
    requires(std::is_unsigned_v<T> && (sizeof(T) == 2 || sizeof(T) == 4))
  void testOp(proc::gpr r, proc::gpr r2) noexcept {
    T n = (T)((*(T*)&cpu.gprs[r]) & (*(T*)&cpu.gprs[r2]));

    cpu.flags &= ~proc::flags::carryFlag;
    cpu.flags &= ~proc::flags::overflowFlag;
    updateSignFlag(n);
    updateZeroFlag(n);
    updateParityFlag(n);
  }

  template <typename T>
    requires(std::is_unsigned_v<T> && (sizeof(T) == 2 || sizeof(T) == 4))
  void jmpAbs(T n) noexcept {
		increaseEip  = false;
    uint32_t eip = n;
    cpu.eip      = eip;
  }

  template <typename T>
    requires(std::is_unsigned_v<T> && (sizeof(T) == 2 || sizeof(T) == 4))
  void callAbs(T n, size_t lastLength) noexcept {
    uint32_t ret = cpu.eip + lastLength;
    // set up return address
    // will be at ebp+4
    pushImm(ret); // push the would-be eip
                  // (once the instruction is fetched, it starts
                  // executing, and fetching should continue.
                  //
                  // - does this imply some logical error in the
                  //   emulator?
    // set up ebp
    pushImm(cpu.gprs[proc::gpr::ebp]);
    // logically, if we dereference ebp now, we get the contents
    // at ebp, which is the previous stack frame
    cpu.gprs[proc::gpr::ebp] = cpu.gprs[proc::gpr::esp];
    // actually go where we decided to go
		// is also responsible for preventing eip increase
    jmpAbs(n);
  }
};
