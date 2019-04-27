#!/usr/bin/env python
# coding=utf-8
import hashlib
import os





srand(10)
print rand()
m2 = hashlib.md5()   
m2.update("123")   
#m2.update(src．encode('utf-8'))
result_src=m2.hexdigest()

print len(result_src)
print result_src

result_dst="5eba99aff105c9ff6a1a913e343fec67"
print len(result_dst)

print 17^27
