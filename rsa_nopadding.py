import rsa
import base64
from Crypto.PublicKey import RSA



# 私钥
privateKey = '-----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALVbcqb7lll83jntI5LAd8minceYNkJqvE9+m1iRyMRYZ8Cxf3g5c4+U9EE6euaOLFmg6du0LDeHelqQoKhQom3SlwtosI3cpiXlyg0SqmWMleJKwwqBxvfBFrR8gJ3s7j2MnTOymLcg/ZCGxvCJt5tMYmKmckZ2407BYxsu2ZxZAgMBAAECgYBlaJs1sBykMWR585YeqyzQPPQI9Z3xiYl+0ga/gdVHpT9uylHCwi1SLjJefvrWDM3T2FysE5Vd/411MsYDGAOagE5Q4nJwrvrpeRzm+s2WjO4ehlUIGWSYGkFcKUOvpHYrYEEkK4wiWT17/76N73Pk1JMWs85G1jrFvQarB9RDAQJBANwqxbc+wLpAmonvosT6WyQXdFl68cpS2tAZZLxTUlj8/FYERh7ILeJCWkUmQLGe7WGVkyzZccXqhPZiPfrF4UkCQQDS36sps7mXntafh0/iqXNbygFTJ7i3JC+A6e4dCFy4TC62R4bshID+BDRVa+QKqRZAzymno+fe4ou7ocJ1XvKRAkB7CE/qod+zdUymzkooRztNROoY4tJhXMG4TqhzcSBwaBdevg6tPvIdITUutTyrxYMj6CERjAW/MtnQkX/PNms5AkEAqtLqM1QWio7vyjexLSqb+sV/oT9SUXoMyV+3tukpQ1rjlGIJGNyWKjB5vKE0ELa9Ai9PzS/oDBR1ob/+aVpLIQJADSlH/V21ZtIkG7uJy+xabAbvDuVDRpT4lyzaaFfNFYcXRAvXirfmvfZS4MoVwctKKye7RbXA0frzb9+zWA6kAg==\n-----END PRIVATE KEY-----'
# 公钥
publicKey = '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1W3Km+5ZZfN457SOSwHfJop3HmDZCarxPfptYkcjEWGfAsX94OXOPlPRBOnrmjixZoOnbtCw3h3pakKCoUKJt0pcLaLCN3KYl5coNEqpljJXiSsMKgcb3wRa0fICd7O49jJ0zspi3IP2QhsbwibebTGJipnJGduNOwWMbLtmcWQIDAQAB\n-----END PUBLIC KEY-----'

"""
ras_nopadding 公钥加密0填充
一般支付类和爬虫类喜欢用这种加密方式，每次加密的结果都是一样的
"""

class Encrypt:
    # 加密函数
    def encrypt(self, message):
        rsa_pubkey = RSA.importKey(publicKey)
        crypto = self.toEncrypt(message.encode(), rsa_pubkey)
        ret = base64.b64encode(crypto).decode() #一般支付类喜欢用base64加密一下
        # ret = crypto.hex()  # 爬虫喜欢用16进制
        return ret


    def toEncrypt(self, message, pub_key):
        keylength = rsa.common.byte_size(pub_key.n)
        padded = self._pad_for_encryption(message, keylength)
        payload = rsa.transform.bytes2int(padded)
        encrypted = rsa.core.encrypt_int(payload, pub_key.e, pub_key.n)
        block = rsa.transform.int2bytes(encrypted, keylength)
        return block

    @staticmethod# 填充函数
    def _pad_for_encryption(message, target_length):
        msglength = len(message)
        padding_length = target_length - msglength
        #0补位 后填充message
        padding = b'\x00' * padding_length + message
        # 0补位 前填充message
        # padding = message + b'\x00' * padding_length
        return padding




if __name__ == '__main__':
    message = 'vjtHrOPA8opX5owa'
    en = Encrypt()
    res = en.encrypt(message)
    print(res)
