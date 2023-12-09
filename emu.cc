#include "emu.hh"

emu::softCPU::softCPU() {
  ram.size = 0x1000000;
  ram.ptr  = std::move(std::unique_ptr<uint8_t[]>(new uint8_t[ram.size] {0}));
  // stack grows downward, artificially descends
  // from 0xffffffff
  gprs[proc::gpr::esp] = gprs[proc::gpr::ebp] = 0xffffffff;
}

emu::softCPU::softCPU(disasm::memoryViewType code, uint32_t ep) : emu::softCPU() {
  // copy code to virtual ram, at the beginning
  memcpy((void *)ram.ptr.get(), (const void *)code.data(), code.size());
  // set entry point
  eip = ep;
}

disasm::ret emu::exec() {
  disasm::disassembler ds(cpu.memory().subspan(cpu.eip));
  auto                 insn = ds.consume();

  // note: it would probably be faster to switch by idx
  if (std::holds_alternative<disasm::none>(insn)) return insn;

  if (auto *pushimm8 = std::get_if<disasm::pushImm8>(&insn)) pushImm(pushimm8->imm);
  else if (auto *pushimm16from8 = std::get_if<disasm::pushImm16From8>(&insn))
    pushImm(pushimm16from8->imm);
  else if (auto *pushimm16 = std::get_if<disasm::pushImm16>(&insn))
    pushImm(pushimm16->imm);
  else if (auto *pushimm32 = std::get_if<disasm::pushImm32>(&insn))
    pushImm(pushimm32->imm);
  else if (auto *pushreg16 = std::get_if<disasm::pushReg16>(&insn))
    pushReg<uint16_t>(pushreg16->gpr);
  else if (auto *pushreg32 = std::get_if<disasm::pushReg32>(&insn))
    pushReg<uint32_t>(pushreg32->gpr);
  else if (auto *popreg16 = std::get_if<disasm::popReg16>(&insn))
    popReg<uint16_t>(popreg16->gpr);
  else if (auto *popreg32 = std::get_if<disasm::popReg32>(&insn))
    popReg<uint32_t>(popreg32->gpr);
  else if (auto *movreg16 = std::get_if<disasm::movReg16>(&insn))
    movReg<uint16_t>(movreg16->gpr, movreg16->imm);
  else if (auto *movreg32 = std::get_if<disasm::movReg32>(&insn))
    movReg<uint32_t>(movreg32->gpr, movreg32->imm);
  else if (auto *addreg16imm8 = std::get_if<disasm::addReg16Imm8>(&insn))
    addOp<uint16_t>(addreg16imm8->gpr, addreg16imm8->imm);
  else if (auto *addreg32imm8 = std::get_if<disasm::addReg32Imm8>(&insn))
    addOp<uint32_t>(addreg32imm8->gpr, addreg32imm8->imm);
  else if (auto *adcreg16imm8 = std::get_if<disasm::adcReg16Imm8>(&insn))
    adcOp<uint16_t>(adcreg16imm8->gpr, adcreg16imm8->imm);
  else if (auto *adcreg32imm8 = std::get_if<disasm::adcReg32Imm8>(&insn))
    adcOp<uint32_t>(adcreg32imm8->gpr, adcreg32imm8->imm);
  else if (auto *andreg16imm8 = std::get_if<disasm::andReg16Imm8>(&insn))
    andOp<uint16_t>(andreg16imm8->gpr, andreg16imm8->imm);
  else if (auto *andreg32imm8 = std::get_if<disasm::andReg32Imm8>(&insn))
    andOp<uint32_t>(andreg32imm8->gpr, andreg32imm8->imm);
  else if (auto *addreg16imm16 = std::get_if<disasm::addReg16Imm16>(&insn))
    addOp<uint16_t>(addreg16imm16->gpr, addreg16imm16->imm);
  else if (auto *addreg32imm32 = std::get_if<disasm::addReg32Imm32>(&insn))
    addOp<uint32_t>(addreg32imm32->gpr, addreg32imm32->imm);
  else if (auto *addaximm16 = std::get_if<disasm::addAxImm16>(&insn))
    addOp<uint16_t>(proc::gpr::eax, addaximm16->imm);
  else if (auto *addeaximm32 = std::get_if<disasm::addEaxImm32>(&insn))
    addOp<uint32_t>(proc::gpr::eax, addeaximm32->imm);
  else if (auto *increg16 = std::get_if<disasm::incReg16>(&insn))
    incOp<uint16_t>(increg16->gpr);
  else if (auto *increg32 = std::get_if<disasm::incReg32>(&insn))
    incOp<uint32_t>(increg32->gpr);
  else if (auto *decreg16 = std::get_if<disasm::decReg16>(&insn))
    decOp<uint16_t>(decreg16->gpr);
  else if (auto *decreg32 = std::get_if<disasm::decReg32>(&insn))
    decOp<uint32_t>(decreg32->gpr);
  else if (auto *testreg16reg16 = std::get_if<disasm::testReg16Reg16>(&insn))
    testOp<uint16_t>(testreg16reg16->gpr, testreg16reg16->gpr2);
  else if (auto *testreg32reg32 = std::get_if<disasm::testReg32Reg32>(&insn))
    testOp<uint32_t>(testreg32reg32->gpr, testreg32reg32->gpr2);
  else if (auto *callnear16 = std::get_if<disasm::callNear16>(&insn))
    callAbs<uint16_t>(callnear16->addr,
                      ds.length()); // already handled disp on addr for us
  else if (auto *callnear32 = std::get_if<disasm::callNear32>(&insn))
    callAbs<uint32_t>(callnear32->addr, ds.length()); // ditto
  else if (auto *jmpnear16 = std::get_if<disasm::jmpNear16>(&insn))
    jmpAbs<uint16_t>(jmpnear16->addr); // already handled disp for us
  else if (auto *jmpnear32 = std::get_if<disasm::jmpNear32>(&insn))
    jmpAbs<uint32_t>(jmpnear32->addr); // ditto

  // eip increase may be disabled (e.g.) just call/jmp-ed
  // and this has changed eip. make increase eip true (default)
  // again afterward, as it should be unless is explicitly told not to
  if (increaseEip) cpu.eip += ds.length();
  increaseEip = true;
  return insn;
}
