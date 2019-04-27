#!/usr/bin/env python
# coding=utf-8

from pwn import *
import ctypes

LIBC=ctypes.cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
# LIBC=cdll.LoadLibrary("/lib/i386-linux-gnu/libc.so.6")
print LIBC.srand(LIBC.time(0))

print LIBC.rand()


