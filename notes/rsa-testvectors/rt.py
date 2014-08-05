#!/usr/bin/env python

import sys
import os
import hashlib

def md5_for_file(path, block_size=256*128):
	'''
	Block size directly depends on the block size of your filesystem
	to avoid performances issues
	Here I have blocks of 4096 octets (Default NTFS)
	'''
	md5 = hashlib.md5()
	with open(path,'rb') as f:
		for chunk in iter(lambda: f.read(block_size), b''):
			md5.update(chunk)
	f.close()
	return md5.hexdigest()

def read_until_eq(f, s):
	while True:
		l = f.readline()
		if l.strip() == s:
			break
	return l

def read_until_start(f, s):
	while True:
		l = f.readline()
		if l.startswith(s):
			break
	return l

def read_hex(f):
	t = []
	while True:
		l = f.readline()
		if l.strip() == '':
			break
		t.extend(l.strip().split(' '))
	return t

class NamedData(object):
	def __init__(self, name, data):
		self.name = name
		self.data = data

	def __str__(self):
		return "  /* {0} */\n  {1},\n  {{ {2} }}\n".format(self.name, len(self.data), ', '.join('0x' + x for x in self.data))

def read_part(f, s):
	name = read_until_start(f, s).strip().lstrip('# ').rstrip(':')
	data = read_hex(f)
	e = NamedData(name, data)
	return e

class RsaKey(object):
	def __init__(self, n, e, d, p, q, dP, dQ, qInv):
		self.n = n
		self.e = e
		self.d = d
		self.p = p
		self.q = q
		self.dP = dP
		self.dQ = dQ
		self.qInv = qInv

	def __str__(self):
		return "{{\n{0},\n{1},\n{2},\n{3},\n{4},\n{5},\n{6},\n{7}\n}}\n".format(self.n, self.e, self.d, self.p, self.q, self.dP, self.dQ, self.qInv)

def read_key(f):
	n = read_part(f, ftype.n)
	e = read_part(f, ftype.e)
	d = read_part(f, ftype.d)
	p = read_part(f, ftype.p)
	q = read_part(f, ftype.q)
	dP = read_part(f, ftype.dP)
	dQ = read_part(f, ftype.dQ)
	qInv = read_part(f, ftype.qInv)
	k = RsaKey(n, e, d, p, q, dP, dQ, qInv)
	return k

class Data(object):
	def __init__(self, name, obj1, obj2, obj3):
		self.name = name
		self.obj1 = obj1
		self.obj2 = obj2
		self.obj3 = obj3

	def __str__(self):
		return "{{\n  \"{0}\",\n{1},\n{2},\n{3}\n}}\n,".format(self.name, self.obj1, self.obj2, self.obj3)

def read_data(f):
	name = read_until_start(f, ftype.o).strip().lstrip('# ')
	obj1 = read_part(f, ftype.o1)
	obj2 = read_part(f, ftype.o2)
	obj3 = read_part(f, ftype.o3)
	s = Data(name, obj1, obj2, obj3)
	return s

class Example(object):
	def __init__(self, name, key, data):
		self.name = name
		self.key = key
		self.data = data

	def __str__(self):
		res = "{{\n  \"{0}\",\n{1},\n{{".format(self.name, str(self.key))
		for i in self.data:
			res += str(i) + '\n'
		res += '}\n},'
		return res

def read_example(f):
	name = read_until_start(f, '# Example').strip().lstrip('# ')
	key = read_key(f)
	l = read_until_start(f, '#')
	d = []
	while l.strip().startswith('# --------------------------------'):
		data = read_data(f)
		d.append(data)
		l = read_until_start(f, '#')

	e = Example(name, key, d)
	f.seek(-len(l), os.SEEK_CUR)
	return e


class PkcsType(object):
	def __init__(self, name):
		if name == 'pss':
			self.o = '# RSASSA-PSS Signature Example'
			self.o1 = '# Message to be signed'
			self.o2 = '# Salt'
			self.o3 = '# Signature'
		elif name == 'oaep':
			self.o = '# RSAES-OAEP Encryption Example'
			self.o1 = '# Message to be encrypted'
			self.o2 = '# Seed'
			self.o3 = '# Encryption'
		else:
			raise ValueError('Type unknown: ' + name)
		if name == 'pss' or name == 'oaep':
			self.n = '# RSA modulus n'
			self.e = '# RSA public exponent e'
			self.d = '# RSA private exponent d'
			self.p = '# Prime p'
			self.q = '# Prime q'
			self.dP = '# p\'s CRT exponent dP'
			self.dQ = '# q\'s CRT exponent dQ'
			self.qInv = '# CRT coefficient qInv'
		self.name = name

ftype = PkcsType(sys.argv[2])

print('/* Generated from file: %s\n * with md5 hash: %s\n */\n' % (sys.argv[1], md5_for_file(sys.argv[1])))
print('''
typedef struct rsaKey {
  int n_l;
  unsigned char n[256];
  int e_l;
  unsigned char e[256];
  int d_l;
  unsigned char d[256];
  int p_l;
  unsigned char p[256];
  int q_l;
  unsigned char q[256];
  int dP_l;
  unsigned char dP[256];
  int dQ_l;
  unsigned char dQ[256];
  int qInv_l;
  unsigned char qInv[256];
} rsaKey_t;

typedef struct rsaData {
  const char* name;
  int o1_l;
  unsigned char o1[256];
  int o2_l;
  unsigned char o2[256];
  int o3_l;
  unsigned char o3[256];
} rsaData_t;

typedef struct testcase {
  const char* name;
  rsaKey_t rsa;
  rsaData_t data[6];
} testcase_t;

testcase_t testcases_%s[] =
    {''' % sys.argv[2])

with open(sys.argv[1], 'rb') as f:
	ex = []
	while read_until_eq(f, '# ============================================='):
		if f.tell() == os.path.getsize(sys.argv[1]):
			break
		ex.append(read_example(f))

	for i in ex:
		print(i)
f.close()
print('};\n')
