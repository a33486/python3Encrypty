# -*- coding: utf-8 -*-
# __author__ = "saltedFish"  334862132@qq.com@qq.com

''' 注：SH256是一种单向加密方式，每次加密结果相同,通常情况下可加密不可解密，用于密码两个密码加密后对比
    在目前sha1 和MD5都已经被破解的情况下  sha256已成目前最流行的单向加密手段
'''

import hashlib

def sha256Encrypt(s):
    sha256 = hashlib.sha256()
    sha256.update(s.encode())
    return sha256.hexdigest()


if __name__ == '__main__':
    s = 'hello world'
    ret = sha256Encrypt(s)
    print(ret)