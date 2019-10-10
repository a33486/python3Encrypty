# -*- coding: utf-8 -*-
# __author__ = "saltedFish"  334862132@qq.com@qq.com
import base64
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

'''
支付接口最常用的加密解密方式  公钥加密 私钥解密
因为RSA为非对称加密，每一次加密出来的值都是不一样的，但是解密出来的值是一样的
如果想加密出来的值一样需要选择rsa.nopadding加密
'''

# 私钥
privateKey = '-----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALVbcqb7lll83jntI5LAd8minceYNkJqvE9+m1iRyMRYZ8Cxf3g5c4+U9EE6euaOLFmg6du0LDeHelqQoKhQom3SlwtosI3cpiXlyg0SqmWMleJKwwqBxvfBFrR8gJ3s7j2MnTOymLcg/ZCGxvCJt5tMYmKmckZ2407BYxsu2ZxZAgMBAAECgYBlaJs1sBykMWR585YeqyzQPPQI9Z3xiYl+0ga/gdVHpT9uylHCwi1SLjJefvrWDM3T2FysE5Vd/411MsYDGAOagE5Q4nJwrvrpeRzm+s2WjO4ehlUIGWSYGkFcKUOvpHYrYEEkK4wiWT17/76N73Pk1JMWs85G1jrFvQarB9RDAQJBANwqxbc+wLpAmonvosT6WyQXdFl68cpS2tAZZLxTUlj8/FYERh7ILeJCWkUmQLGe7WGVkyzZccXqhPZiPfrF4UkCQQDS36sps7mXntafh0/iqXNbygFTJ7i3JC+A6e4dCFy4TC62R4bshID+BDRVa+QKqRZAzymno+fe4ou7ocJ1XvKRAkB7CE/qod+zdUymzkooRztNROoY4tJhXMG4TqhzcSBwaBdevg6tPvIdITUutTyrxYMj6CERjAW/MtnQkX/PNms5AkEAqtLqM1QWio7vyjexLSqb+sV/oT9SUXoMyV+3tukpQ1rjlGIJGNyWKjB5vKE0ELa9Ai9PzS/oDBR1ob/+aVpLIQJADSlH/V21ZtIkG7uJy+xabAbvDuVDRpT4lyzaaFfNFYcXRAvXirfmvfZS4MoVwctKKye7RbXA0frzb9+zWA6kAg==\n-----END PRIVATE KEY-----'
# 公钥
publicKey = '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1W3Km+5ZZfN457SOSwHfJop3HmDZCarxPfptYkcjEWGfAsX94OXOPlPRBOnrmjixZoOnbtCw3h3pakKCoUKJt0pcLaLCN3KYl5coNEqpljJXiSsMKgcb3wRa0fICd7O49jJ0zspi3IP2QhsbwibebTGJipnJGduNOwWMbLtmcWQIDAQAB\n-----END PUBLIC KEY-----'


# 公钥加密
def publicEncrypt(data):
    rsakey = RSA.importKey(publicKey)
    cipher = PKCS1_v1_5.new(rsakey)
    cipher_text = base64.b64encode(cipher.encrypt(data.encode())).decode()
    return cipher_text


# 私钥解密
def privateDecrypt(data):
    cipher_text = data.encode()
    rsakey = RSA.importKey(privateKey)
    cipher = PKCS1_v1_5.new(rsakey)
    random_generator = Random.new().read
    text = cipher.decrypt(base64.b64decode(cipher_text), random_generator).decode()
    return text


if __name__ == '__main__':
    s = 'hello world'
    res1 = publicEncrypt(s)
    print(res1)
    res2 = privateDecrypt(res1)
    print(res2)
