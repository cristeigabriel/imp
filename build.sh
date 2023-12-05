clang-format -i *.cc
clang-format -i *.hh
clang++ main.cc disasm.cc emu.cc -std=c++2b -lm
