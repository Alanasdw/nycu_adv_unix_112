#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import time
from pwn import *

# given by the professor
def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1];
    print(time.time(), "solving pow ...");
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest();
        if h[:6] == '000000':
            solved = str(i).encode();
            print("solved =", solved);
            break;
    print(time.time(), "done.");
    r.sendlineafter(b'string S: ', base64.b64encode(solved));

def decode( given):

    # find operation
    op = ""
    if given.find('╳') != -1 :
        op = "*"
    elif given.find('•') != -1 :
        op = "//"
    elif given.find('┼') != -1 :
        op = "+"
    # print( 'op= ' + op)


    # remove the weird delims
    given = given.replace('\r','')
    given = given.replace('\n','')

    split = [ given[ j: j + 7] for j in range( 0, 7 * 7 * 5, 7)]
    # print("spliting:>")
    # print( split)
    # print( len(split))

    numbers = [ ""] * 7

    # split the graphical characters
    for i in range( len( split)):
        numbers[ i % 7] += split[ i]

    # just match the numbers by striped state
    one =   '  ─┐      │      │      │     ─┴─  '
    two =   ' ┌───┐      │  ┌───┘  │      └───┘ '
    three = ' ┌───┐      │   ───┤      │  └───┘ '
    four =  ' │   │  │   │  └───┤      │      │ '
    five =  ' ┌────  │      └───┐      │  └───┘ '
    six =   ' ┌───┐  │      ├───┐  │   │  └───┘ '
    seven = ' ┌───┐  │   │      │      │      │ '
    eight = ' ┌───┐  │   │  ├───┤  │   │  └───┘ '
    nine =  ' ┌───┐  │   │  └───┤      │  └───┘ '
    zero =  ' ┌───┐  │   │  │   │  │   │  └───┘ '
    refernces = [ one, two, three, four, five, six, seven, eight, nine, zero]

    number_res = [ 0, 0]
    change = 0

    # resolve the numbers
    for i in range( len( numbers)):
        if numbers[ i].find('╳') != -1 or numbers[ i].find('•') != -1 or numbers[ i].find('┼') != -1:
            change = 1
            continue
        else:
            # start getting number
            new_num = -1
            for j in range( len( refernces)):
                if numbers[ i] == refernces[ j]:
                    new_num = j + 1
                    new_num = new_num % 10
                    break
            if new_num == -1:
                print( "error")
            number_res[ change] = number_res[ change] * 10 + new_num

    # concatnate and evaluate the expression
    output = str( number_res[ 0]) + str(op) + str( number_res[ 1])
    print( output)
    return eval( output)

if __name__ == "__main__":
    r = remote('up.zoolab.org', 10681)
    solve_pow(r)

    challange_instruction = r.recvuntil(b'Please complete the ')

    loop_count = int( r.recvuntil(b'challenges').decode().split(' ', 1)[0])
    print( "loop count given: " + str( loop_count))


    for i in range( loop_count):
        challange_instruction = r.recvuntil(b': ')
        # print( challange_instruction)
        given = r.recvuntil(b' = ')
        given = base64.b64decode( given.decode()[:-3]).decode()
        print( given + str('<'))
        value = decode( given)
        value = int( value)
        # print( decode( given))
        r.sendline( str( value).encode())


    print("simple ---------------------------------------------")

    r.interactive()
    r.close()


    # only X: "╳", /: "─" or search for "•", +: "┼" or the left overs

    # examples of the input
#  ┌───┐  ┌───┐  ┌───┐         ┌────  ┌───┐   ─┐   <
#  │      │   │  │   │    │    │      │   │    │   
#  ├───┐  └───┤      │  ──┼──  └───┐      │    │   <
#  │   │      │      │    │        │      │    │   
#  └───┘  └───┘      │         └───┘      │   ─┴─  <
# blank 6 blank 6 ....
#  ┌───┐  ┌───┐  ┌────         │   │  ┌───┐  ┌───┐ <
#  │   │  │   │  │       ╲ ╱   │   │  │   │      │ 
#  └───┤  └───┤  └───┐    ╳    └───┤  ├───┤  ┌───┘ <
#      │      │      │   ╱ ╲       │  │   │  │     
#  └───┘  └───┘  └───┘             │  └───┘  └───┘ <

#  ┌───┐  ┌───┐  ┌───┐   ─┐           ┌───┐  │   │ <
#  │          │  │   │    │      •        │  │   │ 
#  ├───┐  ┌───┘  └───┤    │    ─────   ───┤  └───┤ <
#  │   │  │          │    │      •        │      │ 
#  └───┘  └───┘  └───┘   ─┴─          └───┘      │ <
