clang-format.exe -i *.cc
clang-format.exe -i *.hh
cl.exe main.cc disasm.cc emu.cc /std:c++latest

