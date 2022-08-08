from Crypto.Hash import  SHA512


def hash_SHA512(plaintext_utf8):
    return SHA512.new(plaintext_utf8)


def history(list):
    if len(list) == 5:
        list.clear()
    else:
        return list
    return list
