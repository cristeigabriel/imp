#include "utl.hh"
#include "proc.hh"
#include "disasm.hh"
#include "emu.hh"
#include <cstdio>
#include <string>
#include <source_location>
#include <assert.h>

namespace test {
  inline void announce(const char* s, std::source_location S = std::source_location::current()) {
    auto fn = std::string_view(S.function_name());
    printf("%s\n", fn.data());
    printf("==== %s:%s:%d: %s\n", fn.data(), S.file_name(), S.line(), s);
  }

  inline void fail(std::source_location S = std::source_location::current()) {
    auto fn = std::string_view(S.function_name());
    fprintf(stderr, "%s:%s:%d: failed test\n", fn.data(), S.file_name(), S.line());
    assert("fail!");
#ifndef DEBUG
    exit(1);
#endif
  }
#define TEST(x)                                                                                                        \
  if (x) {                                                                                                             \
    printf("\"" #x "\" succeeded\n");                                                                                  \
  } else {                                                                                                             \
    fail();                                                                                                            \
  }

  namespace disasm {
    void testGprMapping() {
      announce("testGprMapping");

      for (size_t i = 0; i < (int)proc::gpr::GPR_MAX; i++) {
        const uint8_t opcode = 0xb8 + i;
        const uint8_t code[] = {
            opcode, 0x11, 0x22, 0x33, 0x44, // mov <reg32>, 0x44332211
        };

        ::disasm::disassembler d(code);
        auto                   v = d.consume();
        auto                   x = std::get_if<::disasm::movReg32>(&v);
        TEST(x);
        TEST(x->gpr == (proc::gpr)i);
        auto v2 = d.consume();
        TEST(std::holds_alternative<::disasm::none>(v2));
      }

      announce("testGprMapping finished");
    }

    void testMov() {
      announce("testMov");

      const uint8_t code[] = {
          0x66, 0xb8, 0x11, 0x22,       // mov ax, 0x2211
          0xb9, 0x11, 0x22, 0x33, 0x44, // mvo ecx, 0x44332211
      };

      ::disasm::disassembler d(code);
      auto                   v = d.consume();
      TEST(std::holds_alternative<::disasm::movReg16>(v));
      auto x = std::get_if<::disasm::movReg16>(&v);
      TEST(x);
      TEST(x->gpr == proc::gpr::eax);
      TEST(x->imm == 0x2211);
      auto v2 = d.consume();
      TEST(std::holds_alternative<::disasm::movReg32>(v2));
      auto x2 = std::get_if<::disasm::movReg32>(&v2);
      TEST(x2);
      TEST(x2->gpr == proc::gpr::ecx);
      TEST(x2->imm == 0x44332211);
      auto v3 = d.consume();
      TEST(std::holds_alternative<::disasm::none>(v3));

      announce("testMov finished");
    }

    void testPushPop1() {
      announce("testPushPop1");

      const uint8_t code[] = {
          0x68, 0x11, 0x22, 0x33, 0x44, // push 0x44332211 <imm32>
          0x68, 0x11, 0x22, 0x33, 0x44, // push 0x44332211 <imm32>
          0x66, 0x58,                   // pop ax
          0x66, 0x59,                   // pop cx
          0x5a,                         // pop edx
      };

      ::disasm::disassembler d(code);
      auto                   v = d.consume();
      TEST(std::holds_alternative<::disasm::pushImm32>(v));
      TEST(d.length() == 5);
      auto v2 = d.consume();
      TEST(std::holds_alternative<::disasm::pushImm32>(v2));
      TEST(d.length() == 5);
      auto v3 = d.consume();
      TEST(std::holds_alternative<::disasm::popReg16>(v3));
      TEST(d.length() == 2);
      auto v4 = d.consume();
      TEST(std::holds_alternative<::disasm::popReg16>(v4));
      TEST(d.length() == 2);
      auto v5 = d.consume();
      TEST(std::holds_alternative<::disasm::popReg32>(v5));
      TEST(d.length() == 1);
      auto v6 = d.consume();
      TEST(std::holds_alternative<::disasm::none>(v6));

      announce("testPushPop1 finished");
    }

    void testPushPop2() {
      announce("testPushPop2");

      const uint8_t code[] = {
          0x6a, 0x01,      // push  0x01
          0x66, 0x6a, 0x01 // pushw 0x0001
      };

      ::disasm::disassembler d(code);
      auto                   v = d.consume();
      auto                   x = std::get_if<::disasm::pushImm8>(&v);
      TEST(x);
      TEST(x->imm == 1);
      auto v2 = d.consume();
      auto x2 = std::get_if<::disasm::pushImm16From8>(&v2);
      TEST(x2);
      TEST(x2->imm == 1);
      auto v3 = d.consume();
      TEST(std::holds_alternative<::disasm::none>(v3));

      announce("testPushPop2 finished");
    }

    void testAdd1() {
      announce("testAdd1");

      const uint8_t code[] = {
          0x83, 0xc0, 0x69,       // add eax, 0x69
          0x66, 0x83, 0xc0, 0x69, // add ax, 0x69
      };

      ::disasm::disassembler d(code);
      auto                   v = d.consume();
      auto                   x = std::get_if<::disasm::addReg32Imm8>(&v);
      TEST(x);
      TEST(x->gpr == proc::gpr::eax);
      TEST(x->imm == 0x69);
      auto v2 = d.consume();
      auto x2 = std::get_if<::disasm::addReg16Imm8>(&v2);
      TEST(x2);
      TEST(x2->gpr == proc::gpr::eax);
      TEST(x2->imm == 0x69);
      auto v3 = d.consume();
      TEST(std::holds_alternative<::disasm::none>(v3));

      announce("testAdd1 finished");
    }

    void testAdd2() {
      announce("testAdd2");

      const uint8_t code[] = {
          0x81, 0xc0, 0x11, 0x22, 0x33, 0x44, // add eax, 0x44332211
          0x66, 0x81, 0xc0, 0x11, 0x22,       // add ax, 0x2211
          0x05, 0x11, 0x22, 0x33, 0x44,       // add eax, 0x44332211
          0x66, 0x05, 0x11, 0x22,             // add ax, 0x2211
      };

      ::disasm::disassembler d(code);
      auto                   v = d.consume();
      auto                   x = std::get_if<::disasm::addReg32Imm32>(&v);
      TEST(x);
      TEST(x->gpr == proc::gpr::eax);
      TEST(x->imm == 0x44332211);
      auto v2 = d.consume();
      auto x2 = std::get_if<::disasm::addReg16Imm16>(&v2);
      TEST(x2);
      TEST(x2->gpr == proc::gpr::eax);
      TEST(x2->imm == 0x2211);
      auto v3 = d.consume();
      auto x3 = std::get_if<::disasm::addEaxImm32>(&v3);
      TEST(x3);
      TEST(x3->imm == 0x44332211);
      auto v4 = d.consume();
      auto x4 = std::get_if<::disasm::addAxImm16>(&v4);
      TEST(x4);
      TEST(x4->imm == 0x2211);
      auto v5 = d.consume();
      TEST(std::holds_alternative<::disasm::none>(v5));

      announce("testAdd2 finished");
    }

    void testInc() {
      announce("testInc");

      const uint8_t code[] = {
          0xb8, 0xff, 0xff, 0xff, 0xff, // mov eax, 0xffffffff
          0x40,                         // inc eax
      };

      ::disasm::disassembler d(code);
      auto                   v = d.consume();
      auto                   x = std::get_if<::disasm::movReg32>(&v);
      TEST(x->gpr == proc::gpr::eax);
      TEST(x->imm == 0xffffffff);
      auto v2 = d.consume();
      auto x2 = std::get_if<::disasm::incReg32>(&v2);
      TEST(x2->gpr == proc::gpr::eax);
      auto v3 = d.consume();
      TEST(std::holds_alternative<::disasm::none>(v3));

      announce("testInc finished");
    }

    void testDec() {
      announce("testDec");

      const uint8_t code[] = {
          0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
          0x48,                         // dex eax
      };

      ::disasm::disassembler d(code);
      auto                   v = d.consume();
      auto                   x = std::get_if<::disasm::movReg32>(&v);
      TEST(x->gpr == proc::gpr::eax);
      TEST(x->imm == 0);
      auto v2 = d.consume();
      auto x2 = std::get_if<::disasm::decReg32>(&v2);
      TEST(x2->gpr == proc::gpr::eax);
      auto v3 = d.consume();
      TEST(std::holds_alternative<::disasm::none>(v3));

      announce("testDec finished");
    }

    void testTest() {
      announce("testTest");

      const uint8_t code[] = {
          0x85, 0xc0,       // test eax, eax
          0x66, 0x85, 0xc1, // test cx,  ax
      };

      ::disasm::disassembler d(code);
      auto                   v = d.consume();
      auto                   x = std::get_if<::disasm::testReg32Reg32>(&v);
      TEST(x);
      TEST(x->gpr == proc::gpr::eax);
      TEST(x->gpr2 == proc::gpr::eax);
      auto v2 = d.consume();
      auto x2 = std::get_if<::disasm::testReg16Reg16>(&v2);
      TEST(x2);
      TEST(x2->gpr == proc::gpr::ecx);
      TEST(x2->gpr2 == proc::gpr::eax);
      auto v3 = d.consume();
      TEST(std::holds_alternative<::disasm::none>(v3));

      announce("testTest finished");
    }
  } // namespace disasm

  namespace emu {
    void testGprMapping() {
      announce("testGprMapping");

      for (size_t i = 0; i < (int)proc::gpr::GPR_MAX; i++) {
        const uint8_t opcode = 0xb8 + i;
        const uint8_t code[] = {
            opcode, 0x11, 0x22, 0x33, 0x44, // mov <reg32>, 0x44332211
        };

        ::emu e(code, 0);
        bool  running = true;
        while (running) {
          e.cpu.dump();
          running = e.execBool();
        }

        TEST(e.cpu.gprs[(proc::gpr)i] == 0x44332211);
      }

      announce("testGprMapping finished");
    }

    void testAdd1() {
      announce("testAdd1");

      const uint8_t code[] = {
          0xb8, 0xff, 0xff, 0xff, 0xff, // mov eax, 0xffffffff
          0x83, 0xc0, 0x1,              // add eax, 1
      };

      ::emu e(code, 0);
      bool  running = true;
      while (running) {
        e.cpu.dump();
        running = e.execBool();
      }

      TEST(e.cpu.gprs[proc::gpr::eax] == 0);
      TEST(e.cpu.flags & proc::flags::carryFlag);

      announce("testAdd1 finished");
    }

    void testAdd2() {
      announce("testAdd2");

      const uint8_t code[] = {
          0xb8, 0xff, 0xff, 0xff, 0xff, // mov eax, 0xffffffff
          0x83, 0xc0, 0x1,              // add eax, 1
          0x83, 0xd0, 0x0,              // adc eax, 0
      };

      ::emu e(code, 0);
      bool  running = true;
      while (running) {
        e.cpu.dump();
        running = e.execBool();
      }

      TEST(e.cpu.gprs[proc::gpr::eax] == 1);
      TEST(!(e.cpu.flags & proc::flags::carryFlag));

      announce("testAdd2 finished");
    }

    void testAdd3() {
      announce("testAdd3");

      const uint8_t code[] = {
          0xb8, 0xfe, 0xff, 0xff, 0xff, // mov eax, 0xfffffffe
          0x83, 0xc0, 0x2,              // add eax, 2
          0x83, 0xd0, 0x0,              // adc eax, 0
      };

      ::emu e(code, 0);
      bool  running = true;
      while (running) {
        e.cpu.dump();
        running = e.execBool();
      }

      TEST(e.cpu.gprs[proc::gpr::eax] == 1);
      TEST(!(e.cpu.flags & proc::flags::carryFlag));

      announce("testAdd3 finished");
    }

    void testAdd4() {
      announce("testAdd4");

      const uint8_t code[] = {
          0xb8, 0xff, 0xff, 0xff, 0xff, // mov eax, 0xffffffff
          0x66, 0x83, 0xc0, 0x1,        // add ax, 1
      };

      ::emu e(code, 0);
      bool  running = true;
      while (running) {
        e.cpu.dump();
        running = e.execBool();
      }

      TEST(e.cpu.gprs[proc::gpr::eax] == 0xffff0000);
      TEST(!(e.cpu.flags & proc::flags::carryFlag));

      announce("testAdd4 finished");
    }

    void testAdd5() {
      announce("testAdd5");

      const uint8_t code[] = {
          0xb8, 0x0,  0x0,  0x0,  0x0,        // mov eax, 0x0
          0x66, 0x83, 0xc0, 0x1,              // add ax, 1
          0x81, 0xc0, 0x01, 0x00, 0x00, 0x00, // add eax, 1
          0x66, 0x81, 0xc0, 0x01, 0x00,       // add ax, 1
          0x05, 0x01, 0x00, 0x00, 0x00,       // add eax, 1
      };

      ::emu e(code, 0);
      bool  running = true;
      while (running) {
        e.cpu.dump();
        running = e.execBool();
      }

      TEST(e.cpu.gprs[proc::gpr::eax] == 0x4);

      announce("testAdd5 finished");
    }

    void testInc() {
      announce("testInc");

      const uint8_t code[] = {
          0xb8, 0xff, 0xff, 0xff, 0xff, // mov eax, 0xffffffff
          0x40,                         // inc eax
      };

      ::emu e(code, 0);
      bool  running = true;
      while (running) {
        e.cpu.dump();
        running = e.execBool();
      }

      TEST(e.cpu.gprs[proc::gpr::eax] == 0);
      TEST(!(e.cpu.flags & proc::flags::carryFlag));
      TEST(e.cpu.flags & proc::flags::zeroFlag);

      announce("testInc finished");
    }

    void testDec() {
      announce("testDec");

      const uint8_t code[] = {
          0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
          0x48,                         // dec eax
      };

      ::emu e(code, 0);
      bool  running = true;
      while (running) {
        e.cpu.dump();
        running = e.execBool();
      }

      TEST(e.cpu.gprs[proc::gpr::eax] == 0xffffffff);
      TEST(e.cpu.flags & proc::flags::signFlag);

      announce("testDec finished");
    }

    void testPushPop1() {
      announce("testPushPop1");

      const uint8_t code[] = {
          0x68, 0x11, 0x22, 0x33, 0x44, // push 0x44332211 <imm32>
          0x68, 0x11, 0x22, 0x33, 0x44, // push 0x44332211 <imm32>
          0x66, 0x58,                   // pop ax
          0x66, 0x59,                   // pop cx
          0x5a,                         // pop edx
      };

      ::emu e(code, 0);
      bool  running = true;
      while (running) {
        e.cpu.dump();
        running = e.execBool();
      }

      TEST((e.cpu.gprs[proc::gpr::eax] & 0xffff) == 0x2211);
      TEST((e.cpu.gprs[proc::gpr::ecx] & 0xffff) == 0x4433);
      TEST(e.cpu.gprs[proc::gpr::edx] == 0x44332211);

      announce("testPushPop1 finished");
    }

    void testPushPop2() {
      announce("testPushPop2");

      const uint8_t code[] = {
          0x66, 0x6a, 0x10, // pushw 0x0010
          0x6a, 0x20,       // push  0x20
          0x6a, 0x30,       // push  0x30
          0x58,             // pop eax
      };

      ::emu e(code, 0);
      bool  running = true;
      while (running) {
        e.cpu.dump();
        running = e.execBool();
      }

      TEST(e.cpu.gprs[proc::gpr::eax] == 0x102030);

      announce("testPushPop2 finished");
    }

    void testTest() {
      announce("testTest");

      const uint8_t code[] = {
          0xb9, 0xff, 0xff, 0xff, 0xff, // mov ecx, 0xffffffff
          0x85, 0xc1,                   // test ecx, eax
      };

      ::emu e(code, 0);
      bool  running = true;
      while (running) {
        e.cpu.dump();
        running = e.execBool();
      }

      TEST(e.cpu.flags & proc::flags::zeroFlag);

      announce("testTest finished");
    }
  } // namespace emu

#undef TEST
} // namespace test

int main() {
  test::disasm::testGprMapping();
  test::disasm::testMov();
  test::disasm::testPushPop1();
  test::disasm::testPushPop2();
  test::disasm::testAdd1();
  test::disasm::testAdd2();
  test::disasm::testInc();
  test::disasm::testDec();
  test::disasm::testTest();
  test::emu::testGprMapping();
  test::emu::testAdd1();
  test::emu::testAdd2();
  test::emu::testAdd3();
  test::emu::testAdd4();
  test::emu::testAdd5();
  test::emu::testInc();
  test::emu::testDec();
  test::emu::testPushPop1();
  test::emu::testPushPop2();
  test::emu::testTest();
  return 0;
}
