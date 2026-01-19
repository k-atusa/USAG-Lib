# test793a : USAG-Lib bencrypt
from typing import Optional, Tuple

import threading
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

from cryptography.hazmat.primitives.asymmetric import x448, ed448
from cryptography.hazmat.primitives import serialization

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
    p = PasswordHasher(time_cost=3, memory_cost=262144, parallelism=4, hash_len=32, salt_len=16) # fix parameters
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
class AES1:
    def __init__(self):
        self._processed: int = 0
        self._lock = threading.Lock()

    def processed(self) -> int:
        with self._lock:
            return self._processed

    def enAESGCM(self, key: bytes, data: bytes) -> bytes: # AES-GCM
        with self._lock: self._processed = 0
        if len(key) != 44:
            raise ValueError("key size must be 44 bytes")
        cipher = AES.new(key[12:], AES.MODE_GCM, nonce=key[:12])
        ciphertext, tag = cipher.encrypt_and_digest(data)
        with self._lock: self._processed = len(data)
        return ciphertext + tag # [encdata][tag 16B]

    def deAESGCM(self, key: bytes, data: bytes) -> bytes: # AES-GCM
        with self._lock: self._processed = 0
        if len(key) != 44:
            raise ValueError("key size must be 44 bytes")
        cipher = AES.new(key[12:], AES.MODE_GCM, nonce=key[:12])
        plaintext = cipher.decrypt_and_verify(data[:-16], data[-16:])
        with self._lock: self._processed = len(data)
        return plaintext

    def enAESGCMx(self, key: bytes, src: io.IOBase, size: int, dst: io.IOBase, chunkSize: int = 1048576): # AES-GCM extended
        with self._lock: self._processed = 0
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
            with self._lock: self._processed += chunkSize
        if size == 0 or size % chunkSize != 0:
            iv = mkiv(globalIV, count)
            cipher = AES.new(globalKey, AES.MODE_GCM, nonce=iv)
            chunk = src.read(size % chunkSize)
            ciphertext, tag = cipher.encrypt_and_digest(chunk)
            dst.write(ciphertext)
            dst.write(tag)
            with self._lock: self._processed += size % chunkSize

    def deAESGCMx(self, key: bytes, src: io.IOBase, size: int, dst: io.IOBase, chunkSize: int = 1048576): # AES-GCM extended
        with self._lock: self._processed = 0
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
            with self._lock: self._processed += chunkSize + 16
        if size == 0 or size % (chunkSize + 16) != 0:
            iv = mkiv(globalIV, count)
            cipher = AES.new(globalKey, AES.MODE_GCM, nonce=iv)
            chunk = src.read(size % (chunkSize + 16) - 16)
            tag = src.read(16)
            plaintext = cipher.decrypt_and_verify(chunk, tag)
            dst.write(plaintext)
            with self._lock: self._processed += size % (chunkSize + 16)

# ========== Signing Functions ==========
class RSA1:
    def __init__(self):
        self.public: Optional[RSA.RsaKey] = None
        self.private: Optional[RSA.RsaKey] = None

    def genkey(self, bits: int = 2048) -> Tuple[bytes, bytes]: # DER(PKIX, PKCS8) format, (public, private)
        key = RSA.generate(bits) # 2048, 3072, 4096
        self.private = key
        self.public = key.publickey()
        return (self.public.export_key(format='DER'), self.private.export_key(format='DER', pkcs=8))

    def loadkey(self, public: bytes|None, private: bytes|None): # DER(PKIX, PKCS8) format, load if not None
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

class ECC1: # Curve448
    def __init__(self):
        self.pubX: Optional[x448.X448PublicKey] = None
        self.priX: Optional[x448.X448PrivateKey] = None
        self.pubEd: Optional[ed448.Ed448PublicKey] = None
        self.priEd: Optional[ed448.Ed448PrivateKey] = None
        self.em = AES1()
        # encryption format: [1B PubLen][PubKey][encdata][tag]

    def genkey(self) -> Tuple[bytes, bytes]: # [X448 56B][Ed448 57B] format, (public, private)
        # 1. Generate both keys
        self.priX = x448.X448PrivateKey.generate()
        self.pubX = self.priX.public_key()
        self.priEd = ed448.Ed448PrivateKey.generate()
        self.pubEd = self.priEd.public_key()

        # 2. Get Raw Bytes
        pub0 = self.pubX.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        pri0 = self.priX.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        pub1 = self.pubEd.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        pri1 = self.priEd.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

        # 3. Join to 113B
        return (pub0 + pub1, pri0 + pri1)

    def loadkey(self, public: bytes|None, private: bytes|None): # [X448 56B][Ed448 57B] format, load if not None
        if public != None:
            if len(public) != 113: raise ValueError("Invalid Curve448 public key length (must be 113 bytes)")
            self.pubX = x448.X448PublicKey.from_public_bytes(public[:56])
            self.pubEd = ed448.Ed448PublicKey.from_public_bytes(public[56:])
        if private != None:
            if len(private) != 113: raise ValueError("Invalid Curve448 private key length (must be 113 bytes)")
            self.priX = x448.X448PrivateKey.from_private_bytes(private[:56])
            self.priEd = ed448.Ed448PrivateKey.from_private_bytes(private[56:])

    def encrypt(self, data: bytes, receiver: bytes) -> bytes: # encrypt with receiver's public key
        if len(receiver) != 113: raise ValueError("Invalid receiver key")
        peerKey = x448.X448PublicKey.from_public_bytes(receiver[:56]) # 1. Get receiver X448 public key
        tempKey = x448.X448PrivateKey.generate() # 2. Generate temp ephemeral key
        tempPub = tempKey.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        shared = tempKey.exchange(peerKey) # 3. Get shared secret (ECDH)
        gcmKey = genkey(shared, "KEYGEN_ECC1_ENCRYPT", 44)
        enc = self.em.enAESGCM(gcmKey, data) # 4. Encrypt with AES-GCM
        return len(tempPub).to_bytes(1, 'big') + tempPub + enc

    def decrypt(self, data: bytes) -> bytes:
        # 1. parse data
        keylen = data[0]
        tempPub = data[1 : 1 + keylen]
        enc = data[1 + keylen :]

        # 2. Load key, Get shared secret (ECDH)
        tempKey = x448.X448PublicKey.from_public_bytes(tempPub)
        shared = self.priX.exchange(tempKey)

        # 3. Decrypt with AES-GCM
        gcmKey = genkey(shared, "KEYGEN_ECC1_ENCRYPT", 44)
        return self.em.deAESGCM(gcmKey, enc)

    def sign(self, data: bytes) -> bytes: # Ed448
        return self.priEd.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool: # Ed448
        try:
            self.pubEd.verify(signature, data)
            return True
        except:
            return False