from pwn import *
import time

context.log_level="debug"
context.terminal=["tmux","splitv","-h"]
libc=ELF("./libc.so")
libc=cdll.srand(time(0))

def func():
    print a

func()


# from pwn import *
def add(index,content):
    p.recvuntil("chioce: ")
    p.sendline(str(index))
    p.recvuntil("leng:")
    p.sendline("content")

p.interactive()

