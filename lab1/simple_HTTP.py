#!/usr/bin/env python3

from pwn import *

if __name__ == "__main__":

    # the given string
    # """
    #     GET /ip HTTP/1.1\r
    #     Host: ipinfo.io\r
    #     User-Agent: curl/7.88.1\r
    #     Accept: */*\r
    # """

    r = remote('ipinfo.io', 80)
    r.sendline(b'GET /ip HTTP/1.1')
    r.sendline(b'Host: ipinfo.io')
    r.sendline(b'User-Agent: curl/7.88.1')
    r.sendline(b'Accept: */*')
    r.sendline(b'')

    given = r.recvuntil( b'includeSubDomains\r\n\r\n')

    # need to decode to a string instead of a byte string
    given = r.recv()
    print( given.decode())

    # slightly cheating??
    # r = wget( 'http://ipinfo.io/ip')
    # print( str(r) )
