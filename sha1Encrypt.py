# -*- coding: utf-8 -*-
# __author__ = "saltedFish"  334862132@qq.com@qq.com


''' 注：SH1是一种单向加密方式，每次加密结果相同,通常情况下可加密不可解密，用于密码两个密码加密后对比'''
import hashlib

def sha1Encrypt(s):
    sha = hashlib.sha1(s.encode())
    encrypts = sha.hexdigest()
    return encrypts


if __name__ == '__main__':
    s = 'hello world'
    ret = sha1Encrypt(s)
    print(ret)