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
	def __init__(self, n, e, d, q, p, dP, dQ, qInv):
		self.n = n
		self.e = e
		self.d = d
		self.q = q
		self.p = p
		self.dP = dP
		self.dQ = dQ
		self.qInv = qInv

	def __str__(self):
		return "{{\n{0},\n{1},\n{2},\n{3},\n{4},\n{5},\n{6},\n{7}\n}}\n".format(self.n, self.e, self.d, self.q, self.p, self.dP, self.dQ, self.qInv)

def read_key(f):
	n = read_part(f, '# RSA modulus n')
	e = read_part(f, '# RSA public exponent e')
	d = read_part(f, '# RSA private exponent d')
	q = read_part(f, '# Prime p')
	p = read_part(f, '# Prime q')
	dP = read_part(f, '# p\'s CRT exponent dP')
	dQ = read_part(f, '# q\'s CRT exponent dQ')
	qInv = read_part(f, '# CRT coefficient qInv')
	k = RsaKey(n, e, d, q, p, dP, dQ, qInv)
	return k

class Signature(object):
	def __init__(self, name, msg, salt, sig):
		self.name = name
		self.msg = msg
		self.salt = salt
		self.sig = sig

	def __str__(self):
		return "{{\n  \"{0}\",\n{1},\n{2},\n{3}\n}}\n,".format(self.name, self.msg, self.salt, self.sig)

def read_sig(f):
	name = read_until_start(f, '# RSASSA-PSS Signature Example').strip().lstrip('# ')
	msg = read_part(f, '# Message to be signed')
	salt = read_part(f, '# Salt')
	sig = read_part(f, '# Signature')
	s = Signature(name, msg, salt, sig)
	return s

class Example(object):
	def __init__(self, name, key, s):
		self.name = name
		self.key = key
		self.s = s

	def __str__(self):
		res = "{{\n  \"{0}\",\n{1},\n{{".format(self.name, str(self.key))
		for i in self.s:
			res += str(i) + '\n'
		res += '}\n},'
		return res

def read_example(f):
	name = read_until_start(f, '# Example').strip().lstrip('# ')
	key = read_key(f)
	l = read_until_start(f, '#')
	s = []
	while l.strip().startswith('# --------------------------------'):
		sig = read_sig(f)
		s.append(sig)
		l = read_until_start(f, '#')

	e = Example(name, key, s)
	f.seek(-len(l), os.SEEK_CUR)
	return e

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

typedef struct rsaSig {
  const char* name;
  int msg_l;
  unsigned char msg[256];
  int salt_l;
  unsigned char salt[256];
  int sig_l;
  unsigned char sig[256];
} rsaSig_t;

typedef struct testcase {
  const char* name;
  rsaKey_t rsa;
  rsaSig_t sig[6];
} testcase_t;

testcase_t testcases[] =
    {''')

with open(sys.argv[1], 'rb') as f:
	ex = []
	while read_until_eq(f, '# ============================================='):
		if f.tell() == os.path.getsize(sys.argv[1]):
			break
		e = read_example(f)
#		print e
		ex.append(e)

	for i in ex:
		print(i)
f.close()
print('};\n')
