from pwn import *

context.log_level="debug"
context.terminal=["tmux","splitw","-h"]

p=process("./silent")

p.recvuntil("123456789\\n")
p.sendline(str(1))
p.sendline(str(0x18))
p.send("a"*0x18)
gdb.attach(p)
p.sendline(str(1))
p.sendline(0x18)
p.send("a"*0x18)
p.interactive()