from typing import Optional, Tuple

import secrets
import zlib
import hashlib
try: # check if argon2 is available
    from argon2 import PasswordHasher
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

from Cryptodome.PublicKey import RSA

# ========== Basic Helper Functions ==========
def random(size: int) -> bytes:
    return secrets.token_bytes(size)

def crc32(data: bytes) -> bytes:
    checksum = zlib.crc32(data) & 0xffffffff
    return checksum.to_bytes(4, byteorder='little')

def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()

def pbkdf2(pw: bytes, salt: bytes, iter: int = 250000, outsize: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', pw, salt, iter, dklen=outsize)

def argon2_hash(pw: bytes, salt: bytes = None) -> str:
    if not HAS_ARGON2:
        raise ImportError("Argon2 library is not installed.")
    p = PasswordHasher()
    return p.hash(pw) if salt == None else p.hash(pw, salt=salt)

def argon2_verify(hashed: str, pw: bytes) -> bool:
    if not HAS_ARGON2:
        raise ImportError("Argon2 library is not installed.")
    p = PasswordHasher()
    try:
        p.verify(hashed, pw)
        return True
    except:
        return False

# ========== RSA Functions ==========
class RSAtool:
    def __init__(self):
        self.private : Optional[bytes] = None
        self.public : Optional[bytes] = None

    def genkey(self, bits: int = 2048):
        key = RSA.generate(bits)
        self.private = key.export_key()
        self.public = key.publickey().export_key()

    def loadkey(self, private: Optional[bytes] = None, public: Optional[bytes] = None):
        if private != None:
            self.private = private
        if public != None:
            self.public = public

    def encrypt(self, data: bytes) -> bytes:
        if self.public == None:
            raise ValueError("Public key not loaded.")
        key = RSA.import_key(self.public)
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(data)
    
    def decrypt(self, data: bytes) -> bytes:
        if self.private == None:
            raise ValueError("Private key not loaded.")
        key = RSA.import_key(self.private)
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(data)
    
    def sign(self, data: bytes) -> bytes:
        if self.private == None:
            raise ValueError("Private key not loaded.")
        key = RSA.import_key(self.private)
        h = SHA256.new(data)
        signature = pkcs1_15.new(key).sign(h)
        return signature
    
    def verify(self, data: bytes, signature: bytes) -> bool:
        if self.public == None:
            raise ValueError("Public key not loaded.")
        key = RSA.import_key(self.public)
        h = SHA256.new(data)
        try:
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
