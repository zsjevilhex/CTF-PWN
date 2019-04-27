#!/usr/bin/env python
# encoding: utf-8
# 如果觉得不错，可以推荐给你的朋友！http://tool.lu/pyc
import base64

def encode(message):
    s = ''
    for i in message:
        x = ord(i) ^ 32
        x = x + 16
        s += chr(x)
    
    return base64.b64encode(s)

correct = 'XlNkVmtUI1MgXWBZXCFeKY+AaXNt'

flag=base64.b64decode(correct)
s=''
for i in flag:
    x=ord(i)-16
    x ^= 32
    s+=chr(x)
print s
print flag
# flag = ''
# print 'Input flag:'
# flag = raw_input()
# if encode(flag) == correct:
#     print 'correct'
# else:
#     print 'wrong'