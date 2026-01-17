# test793a : USAG-Lib bencrypt
from typing import Optional, Tuple

import io
import secrets
import hashlib
import hmac
try: # check if argon2 is available
    from argon2 import PasswordHasher
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256, SHA512
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

def mkiv(g: bytes, c: int) -> bytearray:
    g, c = bytearray(g), c.to_bytes(8, 'little')
    for i in range(0, 8):
        g[4 + i] ^= c[i]
    return g

# ========== Basic Functions ==========
def random(size: int) -> bytes:
    return secrets.token_bytes(size)

def sha3256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def sha3512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()

def pbkdf2(pw: bytes, salt: bytes, iter: int = 1000000, outsize: int = 64) -> bytes:
    return hashlib.pbkdf2_hmac('sha512', pw, salt, iter, dklen=outsize)

def argon2Hash(pw: bytes, salt: bytes = None) -> str:
    if not HAS_ARGON2:
        raise ImportError("Argon2 library is not installed.")
    p = PasswordHasher()
    return p.hash(pw) if salt == None else p.hash(pw, salt=salt)

def argon2Verify(hashed: str, pw: bytes) -> bool:
    if not HAS_ARGON2:
        raise ImportError("Argon2 library is not installed.")
    p = PasswordHasher()
    try:
        p.verify(hashed, pw)
        return True
    except:
        return False

def genkey(data: bytes, lbl: str, size: int) -> bytes: # HMAC-SHA3-512
    key = hmac.new(data, lbl.encode('utf-8'), hashlib.sha3_512).digest()
    if size > len(key):
        raise ValueError("key size too large")
    return key[:size]

# ========== Encrypting Functions ==========
def enAESGCM(key: bytes, data: bytes) -> bytes: # AES-GCM
    if len(key) != 44:
        raise ValueError("key size must be 44 bytes")
    cipher = AES.new(key[12:], AES.MODE_GCM, nonce=key[:12])
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext + tag

def deAESGCM(key: bytes, data: bytes) -> bytes: # AES-GCM
    if len(key) != 44:
        raise ValueError("key size must be 44 bytes")
    cipher = AES.new(key[12:], AES.MODE_GCM, nonce=key[:12])
    return cipher.decrypt_and_verify(data[:-16], data[-16:])

def enAESGCMx(key: bytes, src: io.IOBase, size: int, dst: io.IOBase, chunkSize: int = 1048576): # AES-GCM extended
    if len(key) != 44:
        raise ValueError("key size must be 44 bytes")
    globalIV, globalKey, count = key[:12], key[12:], 0
    for i in range(0, size // chunkSize):
        iv = mkiv(globalIV, count)
        count += 1
        cipher = AES.new(globalKey, AES.MODE_GCM, nonce=iv)
        chunk = src.read(chunkSize)
        ciphertext, tag = cipher.encrypt_and_digest(chunk)
        dst.write(ciphertext)
        dst.write(tag)
    if size % chunkSize != 0:
        iv = mkiv(globalIV, count)
        cipher = AES.new(globalKey, AES.MODE_GCM, nonce=iv)
        chunk = src.read(size % chunkSize)
        ciphertext, tag = cipher.encrypt_and_digest(chunk)
        dst.write(ciphertext)
        dst.write(tag)

def deAESGCMx(key: bytes, src: io.IOBase, size: int, dst: io.IOBase, chunkSize: int = 1048576): # AES-GCM extended
    if len(key) != 44:
        raise ValueError("key size must be 44 bytes")
    globalIV, globalKey, count = key[:12], key[12:], 0
    for i in range(0, size // (chunkSize + 16)):
        iv = mkiv(globalIV, count)
        count += 1
        cipher = AES.new(globalKey, AES.MODE_GCM, nonce=iv)
        chunk = src.read(chunkSize)
        tag = src.read(16)
        plaintext = cipher.decrypt_and_verify(chunk, tag)
        dst.write(plaintext)
    if size % (chunkSize + 16) != 0:
        iv = mkiv(globalIV, count)
        cipher = AES.new(globalKey, AES.MODE_GCM, nonce=iv)
        chunk = src.read(size % (chunkSize + 16) - 16)
        tag = src.read(16)
        plaintext = cipher.decrypt_and_verify(chunk, tag)
        dst.write(plaintext)

# ========== Signing Functions ==========
class RSA1:
    def __init__(self):
        self.public: Optional[RSA.RsaKey] = None
        self.private: Optional[RSA.RsaKey] = None

    def genkey(self, bits: int = 2048) -> Tuple[bytes, bytes]: # DER format, (public, private)
        key = RSA.generate(bits) # 2048, 3072, 4096
        self.private = key
        self.public = key.publickey()
        return (self.public.export_key(format='DER'), self.private.export_key(format='DER'))

    def loadkey(self, public: bytes|None, private: bytes|None): # DER format, load if not None
        if public != None:
            self.public = RSA.import_key(public)
        if private != None:
            self.private = RSA.import_key(private)

    def encrypt(self, data: bytes) -> bytes: # OAEP-SHA-512
        cipher = PKCS1_OAEP.new(self.public, hashAlgo=SHA512)
        return cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes: # OAEP-SHA-512
        cipher = PKCS1_OAEP.new(self.private, hashAlgo=SHA512)
        return cipher.decrypt(data)

    def sign(self, data: bytes) -> bytes: # PKCS1 v1.5 + SHA256
        h = SHA256.new(data)
        return pkcs1_15.new(self.private).sign(h)

    def verify(self, data: bytes, signature: bytes) -> bool: # PKCS1 v1.5 + SHA256
        try:
            h = SHA256.new(data)
            pkcs1_15.new(self.public).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

class ECC1:
    def __init__(self):
        self.public: Optional[ECC.EccKey] = None
        self.private: Optional[ECC.EccKey] = None
        # encryption format: [1B PubLen][PubKey][encdata][tag]

    def genkey(self) -> Tuple[bytes, bytes]: # DER format, (public, private)
        key = ECC.generate(curve='P-521')
        self.private = key
        self.public = key.public_key()
        return (self.public.export_key(format='DER'), self.private.export_key(format='DER'))

    def loadkey(self, public: bytes|None, private: bytes|None): # DER format, load if not None
        if public is not None:
            self.public = ECC.import_key(public)
        if private is not None:
            self.private = ECC.import_key(private)

    def encrypt(self, data: bytes, receiver: ECC.EccKey) -> bytes: # encrypt with receiver's public key
        tempKey = ECC.generate(curve='P-521') # ephemeral key
        sharedPtr = receiver.pointQ * tempKey.d # shared secret (ECDH)
        sharedValue = sharedPtr.x.to_bytes(128, 'little') # x coordinate 128B as secret
        gcmKey = genkey(sharedValue, "KEYGEN_ECC1_ENCRYPT", 44)
        enc = enAESGCM(gcmKey, data)
        pubBytes = tempKey.public_key().export_key(format='DER') # ephemeral public key
        if len(pubBytes) > 255:
            raise ValueError("key too long")
        return len(pubBytes).to_bytes(1, 'big') + pubBytes + enc

    def decrypt(self, data: bytes) -> bytes:
        keyLen = data[0]
        tempPub = ECC.import_key(data[1 : 1 + keyLen]) # ephemeral public key
        enc = data[1 + keyLen :]
        sharedPtr = tempPub.pointQ * self.private.d # shared secret (ECDH)
        sharedValue = sharedPtr.x.to_bytes(128, 'little') # x coordinate 128B as secret
        gcmKey = genkey(sharedValue, "KEYGEN_ECC1_ENCRYPT", 44)
        return deAESGCM(gcmKey, enc)

    def sign(self, data: bytes) -> bytes:
        h = SHA256.new(data)
        signer = DSS.new(self.private, 'fips-186-3', encoding='der')
        return signer.sign(h)

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            h = SHA256.new(data)
            verifier = DSS.new(self.public, 'fips-186-3', encoding='der')
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False