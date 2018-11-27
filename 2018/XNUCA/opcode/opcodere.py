#!/usr/bin/env python
#coding: utf-8

from z3 import *
import struct
import IPython

data = open('code', 'rb').read()

def parse_code(code):
	i = 0
	while i < len(code):
		opcode = ord(code[i])
		i += 1
		if opcode == 0:
			print('hlt')
		elif opcode == 1:
			dword = struct.unpack('<I', code[i:i+4])[0]
			print('push {:#x}'.format(dword))
			i += 4
		elif opcode == 2:
			print('pop')
		elif opcode == 3:
			dst = ord(code[i])
			i += 1
			src = ord(code[i])
			i += 1
			print('add ${},${}'.format(dst, src))
		elif opcode == 4:
			dst = ord(code[i])
			i += 1
			src = ord(code[i])
			i += 1
			print('sub ${},${}'.format(dst, src))
		elif opcode == 5:
			reg = ord(code[i])
			i += 1
			imm = ord(code[i])
			i += 1
			print('mul ${},{:#x}'.format(reg, imm))
		elif opcode == 6:
			reg = ord(code[i])
			i += 1
			imm = ord(code[i])
			i += 1
			print('shr ${},{:#x}'.format(reg, imm))
		elif opcode == 7:
			dst = ord(code[i])
			i += 1
			src = ord(code[i])
			i += 1
			print('mov ${},${}'.format(dst, src))
		elif opcode == 8:
			reg = ord(code[i])
			i += 1
			imm = ord(code[i])
			i += 1
			print('mov ${},[fp+{:#x}]'.format(reg, imm))
		elif opcode == 9:
			dst = ord(code[i])
			i += 1
			src = ord(code[i])
			i += 1
			print('xor ${},${}'.format(dst, src))
		elif opcode == 10:
			dst = ord(code[i])
			i += 1
			src = ord(code[i])
			i += 1
			print('or ${},${}'.format(dst, src))
def solution():
	first = BitVec('first', 32)
	second = BitVec('second', 32)
	third = BitVec('third', 32)
	solver = Solver()

	solver.add(first & 0xFF == 0x5E)
	solver.add(third & 0xFF == 0x5E)
	solver.add(second & 0xFF0000 == 0x5E0000)

	solver.add((first >> 4) * 0x15 - third == 0x1d7ecc6b)
	solver.add((third >> 8) * 0x3 + second == 0x6079797c)
	solver.add((first >> 8) + second == 0x5fbcbdbd)

	print(solver.check())
	print(solver.model())

parse_code(data)
solution()