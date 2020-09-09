
from Crypto.Cipher import AES as AESCipher
from Crypto import Random
import base64
import hashlib


class AES:
    '''
    https://stackoverflow.com/a/21928790
    '''
    bs = AESCipher.block_size

    @staticmethod
    def get_key(seed: str):
        return hashlib.sha256(seed.encode()).digest()

    @staticmethod
    def encrypt(plain_text, key):
        plain_text = AES._pad(plain_text)
        iv = Random.new().read(AES.bs)
        cipher = AESCipher.new(key, AESCipher.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(plain_text.encode())).decode()

    @staticmethod
    def decrypt(cipher_text, key):
        cipher_text = base64.b64decode(cipher_text)
        iv = cipher_text[:AES.bs]
        cipher = AESCipher.new(key, AESCipher.MODE_CBC, iv)
        return AES._unpad(cipher.decrypt(cipher_text[AES.bs:])).decode()

    @staticmethod
    def _pad(s):
        return s + (AES.bs - len(s) % AES.bs) * chr(AES.bs - len(s) % AES.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]
