#!/usr/bin/python
# -*- coding: UTF-8 -*-
# @File    : 4.10.hash加密算法.py
# @Software: PyCharm

import hashlib
import base64


flag="OTA0ZDQyZWIxN2YzMjQxNDc2NzVkYjg3YWYzOWU0ZmU5MTlhNTQxN2I5NGExNzhhNzFlODU1ZjViMzhhZjA5ZA=="
a = base64.b64encode(flag)
b = base64.b64decode(a)
c=  base64.b64decode(b)
print b
print c
# 1.将字符串，通过加密算法，变成固定长度的输出
s = 'abc'
print(len(str(hash(s)))*4, hash(s))

# 2.生成md5数字指纹。
# 第1种写法：
s2 = flag  # 定义字节型字符串
md = hashlib.md5()  # 导入md5算法
md.update(s2)  # 把值传给md5算法

print(md.digest())  # 生成一个128位的2进制数
print("1111111111111111111111111111111")
print('MD5', '长度:', len(md.hexdigest())*4, md.hexdigest())
# 第2种写法：
print(hashlib.md5("!@abc".encode("utf-8")).hexdigest())

# 3.SHA-1

hash = hashlib.sha1()
hash.update('admin'.encode('utf-8'))
print('SHA-1', '长度:', len(hash.hexdigest())*4, hash.hexdigest())

# 4.SHA-256

hash = hashlib.sha256()
hash.update('admin'.encode('utf-8'))
print('SHA-256', '长度:', len(hash.hexdigest())*4, hash.hexdigest())

# 5.SHA-384

hash = hashlib.sha384()
hash.update('admin'.encode('utf-8'))
print('SHA-384', '长度:', len(hash.hexdigest())*4, hash.hexdigest())

# 5.SHA-512

hash = hashlib.sha512()
hash.update('admin'.encode('utf-8'))
print('SHA-384', '长度:', len(hash.hexdigest())*4, hash.hexdigest())