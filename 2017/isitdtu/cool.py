#!/usr/bin/env python
# coding=utf-8

import hashlib

md5=hashlib.md5('123'.encode('utf-8')).hexdigest()
print md5


i=13
j=0
strflag='fl4g_i5_h3r3!'
for i in xrange(len(strflag)):
    print '\'%c\','%(strflag[i])


flag=[]


for i in xrange(len(strflag)):
    flag.append(ord(strflag[i]))
    print "%x"%flag[i]

str6=[0x7D, 0x4D, 0x23, 0x44, 0x36, 0x02, 0x76, 0x03, 0x6F, 0x5B, 0x2F, 0x46, 0x76, 0x18, 0x39]

for i in xrange(len(str6)):
    print "%x"%(str6[i])
    flag.append(str6[i])

print "%d"%(len(flag))

for i in xrange(28):
    if i<13:
        print "%d %x %c"%(i,flag[i],flag[i])
    test=0
    if i>=13:
        for j in xrange(i):
            test=test ^ flag[j]
            #print "****%x****%x"%(test,flag[j])
        for k in xrange(0xff):
            if k^test==flag[i]:
                #print "%d %x"%(i,flag[i])
                flag[i]=k
                print "%d %x %c"%(i,k,k)
                break
print(''.join(map(str,flag)))
print(''.join(map(chr,flag)))
flagchr=[]
for i in flag:
    flagchr.append(chr(i))
print flagchr
print(''.join(flagchr)) 
#for i in xrange(len(str)):
#    print str[i]
#    flag[i+13]=str[i]
#    print "%x"%flag[i+13]
#for i in xrange(15):
#    print "%d"%(i)
#    flag[i+13]=str[i]
#    for j in xrange(i+13):
#        flag[i+13] ^= flag[j]
#    print "%c"%(flag[i])

