from pwn import *
elf = ELF('./lab03_dist/maze')
print("main =", hex(elf.symbols['main']))
print("{:<12s} {:<10s} {:<10s} {:<10s}".format("Func", "GOT Offset", "Symbol Offset", "Location"))
offsets = []
# fixed the range from 1200
for s in [ f"move_{i}" for i in range(1201)]:
   if s in elf.got:
      loc = elf.got[s] - elf.symbols['main']
      print("{:<12s} {:<10x} {:<13x} {:<10s}".format(s, elf.got[s], elf.symbols[s], hex( loc)))
      offsets.append( hex( loc))

print("\tint move_target[] = { ", end="")
for i in range( len( offsets)):
   pre = ", "
   if ( i == 0):
      pre = ""
   print( pre + offsets[ i], end="")
print("};")
