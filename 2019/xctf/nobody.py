import os 
helloctf=[0x34, 0x33, 0x37, 0x32, 0x36, 0x31, 0x36, 0x33, 0x36, 0x62, 0x34, 0x64, 0x36, 0x35, 0x34, 0x61, 0x37, 0x35, 0x37, 0x33, 0x37, 0x34, 0x34, 0x36, 0x36, 0x66, 0x37, 0x32, 0x34, 0x36, 0x37, 0x35, 0x36, 0x65, 0x00]
flag="437261636b4d654a757374466f7246756e\x00"
print len(helloctf)
print len(flag)

# for i in helloctf:
#     printf chr(i)
