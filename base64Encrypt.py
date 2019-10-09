# -*- coding: utf-8 -*-
# __author__ = "saltedFish"  334862132@qq.com@qq.com

import base64

# base64加密
def encryp(s):
    return base64.b64encode(s.encode())

# base64解密
def decrypt(s):
    return base64.b64decode(s).decode()


if __name__ == '__main__':
    s = 'hello world'
    res1 = encryp(s)
    print(res1)
    res2 = decrypt(res1)
    print(res2)