#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from pwn import *

def f1( ptr):
    asm = """
    mov eax, """ + ptr[ 0] + """
    add eax, """ + ptr[ 1] + """
    sub eax, """ + ptr[ 2] + """
    """
    # print("f1:")
    # print(asm)
    return asm

def f2( ptr):
    asm = """
    mov eax, [""" + ptr[ 0] + """]
    add eax, [""" + ptr[ 1] + """]
    sub eax, [""" + ptr[ 2] + """]
    mov [""" + ptr[ 3] + """], eax
    """
    # print("f2:")
    # print(asm)
    return asm

def f3( ptr):
    # print( ptr)
    asm = """
    mov edi, """ + ptr[ 0] + """
    mov esi, """ + ptr[ 8] + """
L1:
    mov ecx, edi

    L2:
        mov eax, [ecx]
        mov ebx, [ecx + 4]
        cmp eax, ebx
        jl next
        xchg eax, ebx
    next:
        mov [ecx], eax
        mov [ecx + 4], ebx

        add ecx, 4
        cmp ecx, esi
        jle L2

    sub esi, 4
    cmp edi, esi
    jle L1
    """
    # print("f3: skip this")
    # print(asm)
    return asm

def f4( ptr):
    asm = """
    and eax, 0xfffdffff
    """
    return asm

def f5( ptr):
    asm = """
    add al, '0'
    """
    return asm

def f6( ptr):
    # print( ptr)
    asm = """
    mov edi, """ + ptr[ 1] + """
    mov ecx, 16
L1:
    mov bx, 0x1
    and bx, ax
    add bx, '0'
    mov [ edi + ecx - 1], bl
    ror ax, 1
    loop L1
    """
    # print("f3: skip this")
    # print(asm)
    return asm

def f7( ptr):
    asm = """
    mov eax, [""" + ptr[ 1] + """]
    sub eax, [""" + ptr[ 2] + """]
    sub eax, [""" + ptr[ 0] + """]
    mov [""" + ptr[ 3] + """], eax
    """
    return asm

def f8( ptr):
    asm = """
    and ax, 0xfe0
    ror ax, 5
    mov [""" + ptr[ 0] + """], al
    """
    return asm

def f9( ptr):
    asm = """
    lea eax, [edi * 2]
    lea ebx, [edi + eax]
    lea ecx, [eax * 2 + edi]
    lea edx, [edi * 4 + ecx]
    """
    return asm

def f10( ptr):
    asm = """
    mov ecx, 15
L1:
    """ + """
    mov al, [""" + ptr[ 0] + """ + ecx - 1]
    cmp al, 'Z'
    jg LOWER
    or al, 0x20
LOWER:
    """ + """
    mov [""" + ptr[ 1] + """ + ecx - 1], al
    loop L1
    """
    return asm

def f11( ptr):
    asm = """
    mov eax, [""" + ptr[ 0] + """]
    add eax, [""" + ptr[ 1] + """]
    mul DWORD PTR [""" + ptr[ 2] + """]
    mov [""" + ptr[ 3] +"""], eax
    """
    return asm

def f12( ptr):
    asm = """
    mov eax, [""" + ptr[ 0] + """]
    neg eax
    mul DWORD PTR [""" + ptr[ 1] + """]
    add eax, [""" + ptr[ 2] + """]
    """
    return asm

# CPU exception boi > unsigned does not use edx series, just clear them
def f13( ptr):
    asm = """
    mov eax, [""" + ptr[ 0] + """]
    mov ebx, 5
    mul ebx
    mov ebx, [""" + ptr[ 1] + """]
    sub ebx, 3
    xor edx, edx
    div ebx
    mov [""" + ptr[ 2] + """], eax
    """
    return asm

def f14( ptr):
    asm = """
    mov eax, [""" + ptr[ 0] + """]
    mov ebx, -5
    mul ebx
    mov ebx, eax

    mov eax, [""" + ptr[ 1] + """]
    neg eax
    mov ecx, [""" + ptr[ 2] + """]
    cdq
    idiv ecx
    mov ecx, edx
    
    mov eax, ebx
    cdq
    idiv ecx
    mov [""" + ptr[ 3] + """], eax
    """
    return asm

def f15( ptr):
    asm = """
    mov eax, [""" + ptr[ 1] + """]
    neg eax
    mul DWORD PTR [""" + ptr[ 0] + """]

    mov ecx, [""" + ptr[ 2] + """]
    sub ecx, ebx
    cdq
    idiv ecx
    mov [""" + ptr[ 2] + """], eax
    """
    return asm

def f16( ptr):
    asm = """
    call L1
L1:
    pop rax
    """
    return asm

def f17( ptr):
    asm = """
    mov eax, [""" + ptr[ 0] + """]
    mov ebx, 26
    mul ebx
    mov [""" + ptr[ 1] + """], eax
    """
    return asm

def f18( ptr):
    asm = """
    mov edi, 1
    cmp eax, 0
    jge L1
    neg edi
L1:
    mov [""" + ptr[ 0] + """], edi

    mov edi, 1
    cmp ebx, 0
    jge L2
    neg edi
L2:
    mov [""" + ptr[ 1] + """], edi

    mov edi, 1
    cmp ecx, 0
    jge L3
    neg edi
L3:
    mov [""" + ptr[ 2] + """], edi

    mov edi, 1
    cmp edx, 0
    jge L4
    neg edi
L4:
    mov [""" + ptr[ 3] + """], edi
    """
    return asm

# recursive boi
def f19( ptr):
    # the things in this ptr is the call number, not address
    asm = """
    mov rdi, """ + ptr[ 0]+ """
    call r
    jmp finish

r:
    cmp rdi, 1
    jl ZERO
    je ONE
    ; other recurisve

    dec rdi
    push rdi
    call r
    pop rdi
    mov rcx, 2
    mul rcx
    mov rcx, rax

    dec rdi
    push rdi
    push rcx
    call r
    pop rcx
    pop rdi
    mov rbx, 3
    mul rbx
    
    add rax, rcx
    jmp END
ZERO:
    mov rax, 0
    jmp END
ONE:
    mov rax, 1
END:
    ret

finish:

    """
    return asm

def f20( ptr):
    asm = """
    mov rax, [""" + ptr[ 0] + """]
    mov rbx, [""" + ptr[ 1] + """]
    xchg rax, rbx
    mov [""" + ptr[ 0] + """], rax
    mov [""" + ptr[ 1] + """], rbx
    """
    return asm

def f21( ptr):
    asm = """
    xchg rax, rbx
    """
    return asm

def f22( ptr):
    asm = """
    mov al, [""" + ptr[ 0] + """]
    xor al, 0x20
    mov [""" + ptr[ 1] + """], al
    """
    return asm

def f23( ptr):
    asm = """
    xor ch, 0x20
    """
    return asm

if __name__ == "__main__":
    # nc up.zoolab.org ** : fp
    functions = {
        f'{2500 + i}': eval(f'f{i + 1}')
        for i in range(23)
    }

    # functions = {
    #     "2500": f1,
    #     "2501": f2,
    #     "2502": f3,
    #     "2503": f4,
    #     "2504": f5,
    #     "2505": f6,
    #     "2506": f7,
    #     "2507": f8,
    #     "2508": f9,
    #     "2509": f10,
    #     "2510": f11,
    #     "2511": f12,
    #     "2512": f13,
    #     "2513": f14,
    #     "2514": f15,
    #     "2515": f16,
    #     "2516": f17,
    #     "2517": f18,
    #     "2518": f19,
    #     "2519": f20,
    #     "2520": f21,
    #     "2521": f22,
    #     "2522": f23,
    # }

    flags = []

    for port, solver in functions.items():
        r = remote( 'up.zoolab.org', int( port))
        given = r.recvuntil( b'Enter').decode()

        # print( given)
        # find all 0x* addresses since they move all the time
        ptr = []
        for line in given.split("\n"):
            if line.find('0x') != -1:
                found = re.findall(r'0x[0-9A-F]+', line, re.I)
                # print( found)
                for item in found:
                    ptr.append( item)
        
        # get recusive call number
        if port == "2518":
            call_number = 0
            for line in given.split("\n"):
                if line.find("please call") != -1:
                    # call_number = re.findall(r'^.*?\([^\d]*(\d+)[^\d]*\).*', line, re.I)[ 0]
                    # print( re.findall(r'\d+', line)[0])
                    call_number = re.findall(r'\d+', line)[0]
                    break
            # print( call_number, type( call_number))
            ptr.append( call_number)
        
        # print( ptr)
        asm = solver( ptr)
        # print( "current asm: " + asm)

        payload = asm.encode() + b'done:'
        r.sendlineafter(b'done)', payload)

        given = r.recvall().decode()
        # if port == "2512":
        #     print( given)
        start_index = given.find("FLAG: ")
        end_index = given.find("}\n")
        flag = given[ start_index: end_index + 1]
        # print( port + ": " + flag)
        flags.append( port + ": " + flag)
        r.close()

    for item in flags:
        if item.find("FLAG") == -1:
            exit( -1)
        print( item)
        