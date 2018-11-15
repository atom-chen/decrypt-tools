#!/usr/bin/env python
# coding=utf-8

# http://cdn.xiaohoutiaotiao.com/1.8.0/fangzhijianghu_1.8.0.apk
# MD5 (/Users/z/Downloads/fangzhijianghu_1.8.0.apk) = f151d4fbeadd373485ce14d5a8426560

import sys
sys.dont_write_bytecode = True # avoid .pyc

import crypt

if __name__ == '__main__':
    # key in libcocos2dlua.so
    key = 'witu_xxWEM'
    sign = 'FF98392D'

    # execute ./decrypt-fzjh.py on /path/to/fangzhijianghu_1.8.0/assets/
    crypt.decrypt(key, sign, crypt.prepare())
