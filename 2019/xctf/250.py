#!/usr/bin/env python
# coding=utf-8
from pwn import *

p=process("./250")

def func():
    print "2345"
print "xxxxxxx"

func()
func()
func()
func()

print "xxxxxx"
