# -*- coding: utf-8 -*-
# Author    : Estéban Ristich <esteban.ristich@protonmail.com>
# License   : MIT

import argon2, binascii
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

"""
__version__ = '0.1.0'
__name__ = 'sausage'
__builtins__ = ('', '')
"""

def encrypt_AES_GCM(msg, password) -> tuple:
    kdfSalt = b'$' + get_random_bytes(30) + b'$'
    msg = msg.encode(encoding='utf-8', errors='strict')
    secretKey = argon2.hash_password_raw(password, hash_len=32, type=argon2.Type.ID, salt=kdfSalt)
    aesCipher = AES.new(key=secretKey, mode=AES.MODE_GCM, nonce=get_random_bytes(64))
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (kdfSalt, ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(encryptedMsg, password):
    (kdfSalt, ciphertext, nonce, authTag) = encryptedMsg
    secretKey = argon2.hash_password_raw(password, hash_len=32, type=argon2.Type.ID, salt=kdfSalt)
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext


"""
password = b's3kr3tp4ssw0rd'
msg = ''

while True:
    msg = input('messages > ')
    encryptedMsg = encrypt_AES_GCM(msg, password)

    print("encryptedMsg", {
        'kdfSalt': binascii.hexlify(encryptedMsg[0]),
        'ciphertext': binascii.hexlify(encryptedMsg[1]),
        'aesIV': binascii.hexlify(encryptedMsg[2]),
        'authTag': binascii.hexlify(encryptedMsg[3])
    })

    nonce = encryptedMsg[2]
    print(f'nonce : {nonce}, type : {type(nonce)}, len : {len(nonce)}')
    decryptedMsg = decrypt_AES_GCM(encryptedMsg, password)
    print("Decrypted msg : ", decryptedMsg)
"""