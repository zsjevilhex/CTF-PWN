
from pwn import *
context.log_level="debug"
context.terminal=["tmux","splitw","-h"]

p=process("./aegis")
def debug():
    base=0x555555554000+0x114a25
    gdb.attach(p,"b *0x555555668a25")

def ADD(size,content,id):
    p.recvuntil("Choice: ")
    p.sendline(str(1))
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Content: ")
    p.sendline(content)
    p.recvuntil("ID: ")
    p.sendline(str(id))
                                                        
print "xxxx"
ADD(0x20,"a"*10,1)
ADD(0x20,"a"*10,2)
debug()
ADD(0x20,"a"*10,3)
raw_input()
p.recvuntil("Choice: ")
p.interactive()
