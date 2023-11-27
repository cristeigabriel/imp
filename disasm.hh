#pragma once

#include "proc.hh"
#include <cstdint>
#include <variant>
#include <span>

namespace disasm {
	enum instructionType {
		MOV,
		TEST,
		ADD,
		ADC,
		AND,
		INC,
		DEC,
		PUSH,
		POP,
	};

	struct none {};

	struct pushImm8 {
		static constexpr auto type = instructionType::PUSH;
		uint8_t imm;
	};

	struct pushImm16From8 {
		static constexpr auto type = instructionType::PUSH;
		uint16_t imm;
	};

	struct pushImm16 {
		static constexpr auto type = instructionType::PUSH;
		uint16_t imm;
	};

	struct pushImm32 {
		static constexpr auto type = instructionType::PUSH;
		uint32_t imm;
	};

	struct pushReg16 {
		static constexpr auto type = instructionType::PUSH;
		proc::gpr gpr;
	};

	struct pushReg32 {
		static constexpr auto type = instructionType::PUSH;
		proc::gpr gpr;
	};

	struct popReg16 {
		static constexpr auto type = instructionType::POP;
		proc::gpr gpr;
	};

	struct popReg32 {
		static constexpr auto type = instructionType::POP;
		proc::gpr gpr;
	};

	struct movReg16 {
		static constexpr auto type = instructionType::MOV;
		proc::gpr gpr;
		uint16_t imm;
	};

	struct movReg32 {
		static constexpr auto type = instructionType::MOV;
		proc::gpr gpr;
		uint32_t imm;
	};

	struct addReg16Imm8 {
		static constexpr auto type = instructionType::ADD;
		proc::gpr gpr;
		uint8_t imm;
	};

	struct addReg32Imm8 {
		static constexpr auto type = instructionType::ADD;
		proc::gpr gpr;
		uint8_t imm;
	};

	struct adcReg16Imm8 {
		static constexpr auto type = instructionType::ADC;
		proc::gpr gpr;
		uint8_t imm;
	};

	struct addReg16Imm16 {
		static constexpr auto type = instructionType::ADD;
		proc::gpr gpr;
		uint16_t imm;
	};

	struct addReg32Imm32 {
		static constexpr auto type = instructionType::ADD;
		proc::gpr gpr;
		uint32_t imm;
	};

	struct addAxImm16 {
		static constexpr auto type = instructionType::ADD;
		uint16_t imm;
	};

	struct addEaxImm32 {
		static constexpr auto type = instructionType::ADD;
		uint32_t imm;
	};

	struct adcReg32Imm8 {
		static constexpr auto type = instructionType::ADC;
		proc::gpr gpr;
		uint8_t imm;
	};

	struct andReg16Imm8 {
		static constexpr auto type = instructionType::AND;
		proc::gpr gpr;
		uint8_t imm;
	};

	struct andReg32Imm8 {
		static constexpr auto type = instructionType::AND;
		proc::gpr gpr;
		uint8_t imm;
	};

	struct incReg16 {
		static constexpr auto type = instructionType::INC;
		proc::gpr gpr;
	};

	struct incReg32 {
		static constexpr auto type = instructionType::INC;
		proc::gpr gpr;
	};

	struct decReg16 {
		static constexpr auto type = instructionType::DEC;
		proc::gpr gpr;
	};

	struct decReg32 {
		static constexpr auto type = instructionType::DEC;
		proc::gpr gpr;
	};

	struct testReg16Reg16 {
		static constexpr auto type = instructionType::TEST;
		proc::gpr gpr;
		proc::gpr gpr2;
	};

	struct testReg32Reg32 {
		static constexpr auto type = instructionType::TEST;
		proc::gpr gpr;
		proc::gpr gpr2;
	};

	using memoryViewType = std::span<const uint8_t>;

	using ret = std::variant<none, pushImm8, pushImm16From8, pushImm16, pushImm32, 
		pushReg16, pushReg32, popReg16, popReg32, movReg16, movReg32,
		addReg16Imm8, addReg32Imm8, adcReg16Imm8, adcReg32Imm8,
		andReg16Imm8, andReg32Imm8, addReg16Imm16,
		addReg32Imm32, addAxImm16, addEaxImm32, incReg16,
		incReg32, decReg16, decReg32, testReg16Reg16, testReg32Reg32>;

	struct disassembler {
		disassembler() = default;
		disassembler(memoryViewType code) : code(code) { }

		ret consume();

		size_t length() const noexcept {
			return lastLength;
		}

	  private: 
		 memoryViewType code;
		 size_t lastLength = 0;
		 bool operandSizePrefix = false;
		 bool addressSizePrefix = false;
	};
}
