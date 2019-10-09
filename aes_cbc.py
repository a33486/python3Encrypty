# -*- coding: utf-8 -*-
# __author__ = "saltedFish"  334862132@qq.com@qq.com


# window = pip install pycryptodome
# linux = pip install pycrypto

'''
aes为可解密加密，cbc需要偏移量，ebc不需要
ebc 是把被加密文件分割后用统一密钥进行加密，如果有一个模块被破解后，所有的模块都将被破解
cbc 是把被加密文件分割后用密钥加偏移量进行加密,，如果有一个模块被破解后，无法破解其他模块 
因此cbc相对ebc更流行
'''

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex


# 如果text不足16位的倍数就用空格补足为16位
def addTo16(text):
    add = 16 - (len(text.encode('utf-8')) % 16) if len(text.encode('utf-8')) % 16 else 0
    text = text + ('\0' * add)
    return text.encode()


# 加密函数
def encrypt(text,key,iv):
    mode = AES.MODE_CBC
    text = addTo16(text)
    cryptos = AES.new(key.encode(), mode, iv.encode())
    cipher_text = cryptos.encrypt(text)
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
    return b2a_hex(cipher_text).decode()


# 解密后，去掉补足的空格用strip() 去掉
def decrypt(text,key,iv):
    mode = AES.MODE_CBC
    cryptos = AES.new(key.encode(), mode, iv.encode())
    plain_text = cryptos.decrypt(a2b_hex(text.encode()))
    return bytes.decode(plain_text).rstrip('\0')


if __name__ == '__main__':
    key = '0123456789123456'  # ※ key的长度必须为 16, 24, 32位长的密码
    iv = '9876543210123456'  # 偏移量
    text = "hello world"  # 被加密文本
    e = encrypt(text,key,iv)  # 加密
    d = decrypt(e,key,iv)  # 解密
    print("AES_CBC加密:", e)
    print("AES_CBC解密:", d)