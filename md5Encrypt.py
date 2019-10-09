# -*- coding: utf-8 -*-
# __author__ = "saltedFish"  334862132@qq.com@qq.com


''' 注：MD5是一种单向加密方式，每次加密结果相同,通常情况下可加密不可解密，用于密码两个密码加密后对比'''
import hashlib

def md5Encrypt(s):  # MD5加密
    m = hashlib.md5()
    m.update(s.encode("utf8"))
    return m.hexdigest()


if __name__ == '__main__':
    s = 'hello world'
    ret = md5Encrypt(s)
    print(ret)
