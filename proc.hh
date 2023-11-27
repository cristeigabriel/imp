#pragma once

#include "utl.hh"
#include <utility>
#include <optional>
#include <type_traits>

namespace proc {
	/// Entries are ordered in the way the i386 ISA uses them,
	/// this allows us to decode instructions
	/// which take a register operand very easily, as it's formulaic.
	enum gpr {
		eax = 0,
		ebx = 3,
		ecx = 1,
		edx = 2,
		esi = 6,
		edi = 7,
		esp = 4,
		ebp = 5,
		GPR_MAX = 8
	};

	namespace utl {
		template <typename T>
		static std::optional<proc::gpr> within(T value,
			std::type_identity_t<T> low,
			std::type_identity_t<T> high,
			size_t skip = 0) noexcept {
			if (::utl::within(value, low, high) && (high - low) <= 
				(7 - skip)) {
				auto n = ((value - low) + skip) % 8;
				return (proc::gpr)n;
			}

			return {};
		}	

		template <typename T>
		static std::optional<std::pair<proc::gpr, proc::gpr>> within2(T value,
			std::type_identity_t<T> low,
			std::type_identity_t<T> high) noexcept {
			if (::utl::within(value, low, high)) {
				auto n = (value - low) % 8;
				auto n2 = (value - low) / 8;
				return std::pair<proc::gpr, proc::gpr>
					{ (proc::gpr)n, (proc::gpr)n2 };
			}

			return std::nullopt;
		}	
	}

	static constexpr const char* gprToStr(gpr r, bool prefix = false) noexcept {
		auto name = ([r] { 
			switch (r) {
				case gpr::eax: return "eax";
				case gpr::ebx: return "ebx";
				case gpr::ecx: return "ecx";
				case gpr::edx: return "edx";
				case gpr::esi: return "esi";
				case gpr::edi: return "edi";
				case gpr::esp: return "esp";
				case gpr::ebp: return "ebp";
			}
		})();

		if (prefix) return &name[1];
		return name;
	}

	/// Explainations for flags are taken from external sources
	/// for educational purposes.
	enum flags {
		/* CF
		The carry flag has several purposes. First, it denotes an unsigned
	overflow (much like the overflow flag detects a signed overflow). You will also
	use it during multiprecision arithmetic and logical operations. Certain bit
	test, set, clear, and invert instructions on the 80386 directly affect this
	flag. Finally, since you can easily clear, set, invert, and test it, it is
	useful for various boolean operations. The carry flag has many purposes and
	knowing when to use it, and for what purpose, can confuse beginning assembly
	language program- mers. Fortunately, for any given instruction, the meaning of
	the carry flag is clear */
		carryFlag = (1 << 0),
		/* PF
		The parity flag is set according to the parity of the L.O. eight bits of any
	data operation. If an operation produces an even number of one bits, the CPU
	sets this flag. It clears this flag if the operation yields an odd number of one
	bits. This flag is useful in certain data communications programs, however,
	Intel provided it mainly to provide some compati- bility with the older 8080
	μP.*/
		parityFlag = (1 << 2),
		/* AF
		The auxiliary carry flag supports special binary coded decimal (BCD)
	operations. Since most programs don’t deal with BCD numbers, you’ll rarely use
	this flag and even then you’ll not access it directly. The 80x86 CPUs do not
	provide any instructions that let you directly test, set, or clear this flag.
	Only the add, adc, sub, sbb, mul, imul, div, idiv, and BCD instructions
	manipulate this flag.
		*/
		auxiliaryCarryFlag = (1 << 4),
		/* ZF
		Various instructions set the zero flag when they generate a zero result.
	You’ll often use this flag to see if two values are equal (e.g., after
	subtracting two numbers, they are equal if the result is zero). This flag is
	also useful after various logical operations to see if a spe- cific bit in a
	register or memory location contains zero or one */
		zeroFlag = (1 << 6),
		/* SF
		If the result of some computation is negative, the 80x86 sets the sign flag.
	You can test this flag after an arithmetic operation to check for a negative
	result. Remember, a value is negative if its H.O. bit is one. Therefore,
	operations on unsigned values will set the sign flag if the result has a one in
	the H.O. position. */
		signFlag = (1 << 7),
		/* TF
		A trap flag permits operation of a processor in single-step mode. If such a
		flag is available, debuggers can use it to step through the execution of a
		computer program. */
		trapFlag = (1 << 8),
		/* IF
		The interrupt enable/disable flag controls the 80x86’s ability to respond to
	external events known as interrupt requests. Some programs contain certain
	instruction sequences that the CPU must not interrupt. The interrupt
	enable/disable flag turns interrupts on or off to guarantee that the CPU does
	not interrupt those critical sections of code. */
		interruptEnableFlag = (1 << 9),
		/* DF
		The 80x86 string instructions use the direction flag. When the direction flag
	is clear, the 80x86 processes string elements from low addresses to high
	addresses; when set, the CPU processes strings in the opposite direction. */
		directionFlag = (1 << 10),
		/* OF
		Various arithmetic, logical, and miscellaneous instructions affect the
	overflow flag. After an arithmetic operation, this flag contains a one if the
	result does not fit in the signed destination operand. For example, if you
	attempt to add the 16 bit signed numbers 7FFFh and 0001h the result is too large
	so the CPU sets the overflow flag. If the result of the arith- metic operation
	does not produce a signed overflow, then the CPU clears this flag. */
		overflowFlag = (1 << 11),
		/* IOPL
		The IOPL (I/O Privilege level) flag is a flag found on all IA-32 compatible
		x86 CPUs. It occupies bits 12 and 13 in the FLAGS register. In protected mode
		and long mode, it shows the I/O privilege level of the current program or
		task. The Current Privilege Level (CPL) (CPL0, CPL1, CPL2, CPL3) of the task
		or program must be less than or equal to the IOPL in order for the task or
		program to access I/O ports. */
		ioPrivilegeLevelFlagLow = (1 << 12),
		ioPrivilegeLevelFlagHigh = (1 << 13),
		/* NT
		Indicates that the current task is nested within another task in protected
		mode operation. */
		nestedTaskFlag = (1 << 14),
		/* MD */
		modeFlag = (1 << 15),
		/* RF */
		resumeFlag = (1 << 16),
		/* VM */
		virtualModeFlag = (1 << 17),
		/* AF */
		alignmentCheckFlag = (1 << 18),
		/* VIF */
		virtualInterruptFlag = (1 << 19),
		/* VIP */
		virtualInterruptPendingFlag = (1 << 20),
		/* ID */
		ableToUseCpuidFlag = (1 << 21),
	};
}

