import os
from rsa import common, transform, core
from Crypto.PublicKey import RSA

# 私钥
privateKey = '-----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALVbcqb7lll83jntI5LAd8minceYNkJqvE9+m1iRyMRYZ8Cxf3g5c4+U9EE6euaOLFmg6du0LDeHelqQoKhQom3SlwtosI3cpiXlyg0SqmWMleJKwwqBxvfBFrR8gJ3s7j2MnTOymLcg/ZCGxvCJt5tMYmKmckZ2407BYxsu2ZxZAgMBAAECgYBlaJs1sBykMWR585YeqyzQPPQI9Z3xiYl+0ga/gdVHpT9uylHCwi1SLjJefvrWDM3T2FysE5Vd/411MsYDGAOagE5Q4nJwrvrpeRzm+s2WjO4ehlUIGWSYGkFcKUOvpHYrYEEkK4wiWT17/76N73Pk1JMWs85G1jrFvQarB9RDAQJBANwqxbc+wLpAmonvosT6WyQXdFl68cpS2tAZZLxTUlj8/FYERh7ILeJCWkUmQLGe7WGVkyzZccXqhPZiPfrF4UkCQQDS36sps7mXntafh0/iqXNbygFTJ7i3JC+A6e4dCFy4TC62R4bshID+BDRVa+QKqRZAzymno+fe4ou7ocJ1XvKRAkB7CE/qod+zdUymzkooRztNROoY4tJhXMG4TqhzcSBwaBdevg6tPvIdITUutTyrxYMj6CERjAW/MtnQkX/PNms5AkEAqtLqM1QWio7vyjexLSqb+sV/oT9SUXoMyV+3tukpQ1rjlGIJGNyWKjB5vKE0ELa9Ai9PzS/oDBR1ob/+aVpLIQJADSlH/V21ZtIkG7uJy+xabAbvDuVDRpT4lyzaaFfNFYcXRAvXirfmvfZS4MoVwctKKye7RbXA0frzb9+zWA6kAg==\n-----END PRIVATE KEY-----'
# 公钥
publicKey = '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1W3Km+5ZZfN457SOSwHfJop3HmDZCarxPfptYkcjEWGfAsX94OXOPlPRBOnrmjixZoOnbtCw3h3pakKCoUKJt0pcLaLCN3KYl5coNEqpljJXiSsMKgcb3wRa0fICd7O49jJ0zspi3IP2QhsbwibebTGJipnJGduNOwWMbLtmcWQIDAQAB\n-----END PUBLIC KEY-----'


def _pad_for_encryption(message, target_length):
    max_msglength = target_length - 11
    msglength = len(message)

    if msglength > max_msglength:
        raise OverflowError(
            "%i bytes needed for message, but there is only"
            " space for %i" % (msglength, max_msglength)
        )

    padding = b""
    padding_length = target_length - msglength - 3

    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)
        new_padding = os.urandom(needed_bytes + 5)
        new_padding = new_padding.replace(b"\x00", b"")
        padding = padding + new_padding[:needed_bytes]

    assert len(padding) == padding_length

    return b"".join([b"\x00\x02", padding, b"\x00", message])


def decrypt(data: bytes, d, n):
    num = transform.bytes2int(data)
    decrypto = core.decrypt_int(num, d, n)
    out = transform.int2bytes(decrypto)
    sep_idx = out.index(b"\x00", 2)
    out = out[sep_idx + 1:]
    return out


def encrypt(data: bytes, d, n):
    keylength = common.byte_size(n)
    padded = _pad_for_encryption(data, keylength)
    num = transform.bytes2int(padded)
    decrypto = core.encrypt_int(num, d, n)
    out = transform.int2bytes(decrypto)
    return out


if __name__ == '__main__':
    privkey = RSA.importKey(privateKey) # 加载私钥
    pubkey = RSA.importKey(publicKey) # 加载公钥
    data = '123456789'
    data2b = data.encode()
    edata = encrypt(data2b, pubkey.e, pubkey.n)
    print(edata)
    ddata = decrypt(edata, privkey.d, privkey.n)
    ddata = ddata.decode()
    print(ddata)
