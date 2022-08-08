import sys
import random
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import json

'''
KeyGen() can be placed as an argument inside the encryption function
'''


def KeyGen():
    try:
        File = open("Templates/SharedKey.txt", 'rb')
        FileContent = File.read()
        File.close()
        return bytes(FileContent)
    except FileNotFoundError:
        file = open("Templates/SharedKey.txt", 'bw+')
        key = get_random_bytes(32)
        file.write(key)
        file.close()
        return key


def encryption(key, plain_text):
    data = bytes(plain_text, 'utf-8')
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ciphertext = b64encode(ciphertext_bytes).decode('utf-8')
    results = json.dumps({"iv": iv, "ciphertext": ciphertext})
    return results


def decryption(key, ciphertext, iv):
    cipher = AES.new(key, AES.MODE_CBC, b64decode(iv))
    plaintext = unpad(cipher.decrypt(b64decode(ciphertext)), AES.block_size)
    return plaintext.decode('utf-8')


result = encryption(KeyGen(), "HelloWorld!")
result2 = encryption(KeyGen(), "Bonjour!")



test = json.loads(result)
