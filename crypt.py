#!/usr/bin/env python
#coding=utf-8


import sys
import os
import json
import shutil
import subprocess
import argparse

############################################################
#http://www.coolcode.org/archives/?article-307.html
############################################################

import struct

_DELTA = 0x9E3779B9

def _long2str(v, w):
    n = (len(v) - 1) << 2
    if w:
        m = v[-1]
        if (m < n - 3) or (m > n): return ''
        n = m
    s = struct.pack('<%iL' % len(v), *v)
    return s[0:n] if w else s

def _str2long(s, w):
    n = len(s)
    m = (4 - (n & 3) & 3) + n
    s = s.ljust(m, "\0")
    v = list(struct.unpack('<%iL' % (m >> 2), s))
    if w: v.append(n)
    return v

def xxtea_encrypt(str, key):
    if str == '': return str
    v = _str2long(str, True)
    k = _str2long(key.ljust(16, "\0"), False)
    n = len(v) - 1
    z = v[n]
    y = v[0]
    sum = 0
    q = 6 + 52 // (n + 1)
    while q > 0:
        sum = (sum + _DELTA) & 0xffffffff
        e = sum >> 2 & 3
        for p in xrange(n):
            y = v[p + 1]
            v[p] = (v[p] + ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))) & 0xffffffff
            z = v[p]
        y = v[0]
        v[n] = (v[n] + ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[n & 3 ^ e] ^ z))) & 0xffffffff
        z = v[n]
        q -= 1
    return _long2str(v, False)

def xxtea_decrypt(str, key):
    if str == '': return str
    v = _str2long(str, False)
    k = _str2long(key.ljust(16, "\0"), False)
    n = len(v) - 1
    z = v[n]
    y = v[0]
    q = 6 + 52 // (n + 1)
    sum = (q * _DELTA) & 0xffffffff
    while (sum != 0):
        e = sum >> 2 & 3
        for p in xrange(n, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))) & 0xffffffff
            y = v[p]
        z = v[n]
        v[0] = (v[0] - ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[0 & 3 ^ e] ^ z))) & 0xffffffff
        y = v[0]
        sum = (sum - _DELTA) & 0xffffffff
    return _long2str(v, True)

def fread(file):
  with open(file, 'rb') as f:
    return f.read()

def encrypt_file(file, key, sign):
  data = fread(file)
  if not data.startswith(sign):
    codeded = xxtea_encrypt(data, key)

    with open(file, 'wb') as f:
      f.write(sign)
      f.write(codeded)

def decrypt_file(file, key, sign):
  data = fread(file)
  if data.startswith(sign):
    decoded = xxtea_decrypt(data[len(sign):], key)
    if len(decoded):
      with open(file, 'wb') as f:
        f.write(decoded)

def scan(*dirs, **kwargs):
  files = []
  extensions = kwargs['extensions'] if kwargs.has_key('extensions') else None
  excludes = kwargs['excludes'] if kwargs.has_key('excludes') else []
  for top in dirs:
    for root, dirnames, filenames in os.walk(top):
      dirnames = [i for i in dirnames if i in excludes]
      for f in filenames:
        if f in excludes:
          continue
        ext = os.path.splitext(f)[1].lower()
        if extensions is None or ext in extensions:
          files.append(os.path.join(root, f))
  return files

def prepare():
  #extensions = ['.ExportJson', '.plist', '.json', '.animation', '.fnt', '.md', '.xml', '.tmx', '.png', '.lua']
  extensions = ['.json', '.png', '.lua']

  sources = scan('src', 'res', extensions=extensions, excludes=['Backup', 'README.md'])
  return sources

def decrypt(key, sign, sources):
  print('decrypt %d files...' % len(sources))
  for f in sources:
    decrypt_file(f, key, sign)
  print('OK')
