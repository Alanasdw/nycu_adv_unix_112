from pwn import *
elf = ELF('./maze')
print("main =", hex(elf.symbols['main']))
print("{:<12s} {:<10s} {:<10s} {:<10s}".format("Func", "GOT Offset", "Symbol Offset", "Location"))
# fixed the range from 1200
for s in [ f"move_{i}" for i in range(1201)]:
   if s in elf.got:
      loc = elf.symbols['main'] - elf.got[s] + elf.symbols[s]
      print("{:<12s} {:<10x} {:<13x} {:<10s}".format(s, elf.got[s], elf.symbols[s], hex(loc)))