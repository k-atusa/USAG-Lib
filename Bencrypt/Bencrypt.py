# test793a : USAG-Lib bencrypt
from typing import Optional, Tuple

import threading
import io
import secrets
import hashlib
import hmac

from argon2 import PasswordHasher
from argon2 import low_level

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256, SHA512

from cryptography.hazmat.primitives.asymmetric import x448, ed448
from cryptography.hazmat.primitives import serialization

from pqcrypto.kem.ml_kem_1024 import generate_keypair as mlkem_gen, encrypt as mlkem_enc, decrypt as mlkem_dec
from pqcrypto.sign.ml_dsa_87 import generate_keypair as mldsa_gen, sign as mldsa_sign, verify as mldsa_verify

# ========== Basic Functions ==========
def Random(size: int) -> bytes:
    return secrets.token_bytes(size)

def SHA3256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def SHA3512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()

def genkey(data: bytes, lbl: str, size: int) -> bytes: # HMAC-SHA3-512
    key = hmac.new(data, lbl.encode('utf-8'), hashlib.sha3_512).digest()
    if size > len(key):
        raise ValueError("key size too large")
    return key[:size]

def mkiv(g: bytes, c: int) -> bytearray:
    g, c = bytearray(g), c.to_bytes(8, 'little')
    for i in range(0, 8):
        g[4 + i] ^= c[i]
    return g

# ========== Data Masker ==========
class Masker:
    _instance = None # singleton
    _PRIME_CANDIDATES = [
        15485863, 32452843, 86028121, 104395301,
        179424673, 228017633, 236887691, 345098717,
        413158511, 481230491, 563117203, 693240851,
        715225741, 812349821, 882046271, 999999937
    ]

    def __new__(cls, pool_size_mb: int = 8):
        if cls._instance is None:
            cls._instance = super(Masker, cls).__new__(cls)
            cls._instance._initialize(pool_size_mb)
        return cls._instance
    
    def __del__(self):
        if hasattr(self, 'pool') and isinstance(self.pool, bytearray):
            for i in range(len(self.pool)):
                self.pool[i] = 0
            del self.pool

    def _initialize(self, pool_size_mb: int):
        self.POOL_SIZE = pool_size_mb * 1024 * 1024
        self.pool = bytearray(Random(self.POOL_SIZE))
        self.prime = self._PRIME_CANDIDATES[secrets.randbelow(len(self._PRIME_CANDIDATES))]

    def XOR(self, data: bytes) -> bytes:
        L = len(data)
        if L == 0:
            return data
        if L > self.POOL_SIZE:
            raise ValueError(f"Data {L} exceeds Pool {self.POOL_SIZE}")
        
        stride = self.POOL_SIZE // L
        result = bytearray(L)
        for i in range(L):
            jitter = (i * self.prime) % stride
            idx = (i * stride) + jitter
            result[i] = data[i] ^ self.pool[idx]
        return bytes(result)

# ========== Hash Function Master ==========
class HashMaster:
    def __init__(self, algo: str, hashSize: int = 32, keySize: int = 44):
        if algo not in ["sha3", "pbk2", "arg2"]:
            raise ValueError(f"Unsupported algorithm: {algo}")
        self.algo = algo
        self.hashSize = hashSize
        self.keySize = keySize
    
    def KDF(self, pw: bytes, salt: bytes) -> Tuple[bytes, bytes]: # (PW storage, user key)
        lblStore, lblKeygen, master = "", "", None
        if self.algo == "sha3":
            lblStore, lblKeygen = "PWHASH_SHA3", "KEYGEN_SHA3"
            master = SHA3512(salt + pw)
        elif self.algo == "pbk2":
            lblStore, lblKeygen = "PWHASH_PBK2", "KEYGEN_PBK2"
            master = pbkdf2(pw, salt)
        elif self.algo == "arg2":
            lblStore, lblKeygen = "PWHASH_ARG2", "KEYGEN_ARG2"
            master = argon2(pw, salt)
        else:
            return (None, None)
        pwStore, keyGen = genkey(master, lblStore, self.hashSize), genkey(master, lblKeygen, self.keySize)
        del master
        return pwStore, keyGen
    
# ========== Hash Functions ==========
def pbkdf2(pw: bytes, salt: bytes, iter: int = 1000000, outsize: int = 64) -> bytes:
    return hashlib.pbkdf2_hmac('sha512', pw, salt, iter, dklen=outsize)

def argon2(pw: bytes, salt: bytes) -> bytes:
    return low_level.hash_secret_raw(secret=pw, salt=salt, time_cost=3, memory_cost=262144, parallelism=4, hash_len=48, type=low_level.Type.ID)

def argon2Hash(pw: bytes, salt: bytes | None = None) -> str:
    p = PasswordHasher(time_cost=3, memory_cost=262144, parallelism=4, hash_len=48, salt_len=16) # fix parameters
    return p.hash(pw) if salt == None else p.hash(pw, salt=salt)

def argon2Verify(hashed: str, pw: bytes) -> bool:
    p = PasswordHasher()
    try:
        p.verify(hashed, pw)
        return True
    except:
        return False

# ========== Symmetric Encryption Master ==========
class SymMaster:
    def __init__(self, algo: str, key: bytes):
        if algo not in ["gcm1", "gcmx1"]:
            raise ValueError(f"Unsupported algorithm: {algo}")
        self.algo = algo
        if self.algo == 'gcm1' or self.algo == 'gcmx1':
            if len(key) != 44:
                raise ValueError("Key length must be 44 bytes (12B IV + 32B Key)")
            self.mask = Masker()
            self.key, self.worker = self.mask.XOR(key), AES1() # saved as XOR masked

    def __del__(self):
        if hasattr(self, 'mask'):
            del self.mask
        if hasattr(self, 'key'):
            del self.key

    def AfterSize(self, size: int) -> int:
        if self.algo == "gcm1":
            return size + 16 # tag size
        elif self.algo == "gcmx1":
            c = size // 1048576 + 1
            if size != 0 and size % 1048576 == 0:
                c -= 1
            return size + 16 * c
        
    def Processed(self) -> int:
        if self.algo == 'gcm1' or self.algo == 'gcmx1':
            return self.worker.processed()

    def EnBin(self, data: bytes) -> bytes:
        if self.algo == "gcm1":
            return self.worker.enAESGCM(self.mask.XOR(self.key), data)
        elif self.algo == "gcmx1":
            wr = io.BytesIO()
            self.worker.enAESGCMx(self.mask.XOR(self.key), io.BytesIO(data), len(data), wr)
            return wr.getvalue()

    def DeBin(self, data: bytes) -> bytes:
        if self.algo == "gcm1":
            return self.worker.deAESGCM(self.mask.XOR(self.key), data)
        elif self.algo == "gcmx1":
            wr = io.BytesIO()
            self.worker.deAESGCMx(self.mask.XOR(self.key), io.BytesIO(data), len(data), wr)
            return wr.getvalue()

    def EnFile(self, src: io.IOBase, size: int, dst: io.IOBase):
        if self.algo == "gcm1":
            data = self.worker.enAESGCM(self.mask.XOR(self.key), src.read(size))
            dst.write(data)
        elif self.algo == "gcmx1":
            self.worker.enAESGCMx(self.mask.XOR(self.key), src, size, dst)

    def DeFile(self, src: io.IOBase, size: int, dst: io.IOBase):
        if self.algo == "gcm1":
            data = self.worker.deAESGCM(self.mask.XOR(self.key), src.read(size))
            dst.write(data)
        elif self.algo == "gcmx1":
            self.worker.deAESGCMx(self.mask.XOR(self.key), src, size, dst)

# ========== AES Encryption ==========
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
        if size < 16:
            raise ValueError("cipher too short to decrypt")
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

# ========== Asymmetric Encryption Master ==========
class AsymMaster:
    def __init__(self, algo: str):
        if algo not in ["rsa1", "rsa2", "ecc1", "pqc1"]:
            raise ValueError(f"Unsupported algorithm: {algo}")
        self.algo = algo
        if self.algo == 'rsa1' or self.algo == 'rsa2':
            self.worker = RSA1()
        elif self.algo == 'ecc1':
            self.worker = ECC1()
        elif self.algo == 'pqc1':
            self.worker = PQC1()

    def __del__(self):
        if hasattr(self, 'worker'):
            del self.worker

    def Genkey(self) -> Tuple[bytes, bytes]:
        if self.algo == 'rsa1':
            return self.worker.genkey(2048)
        elif self.algo == 'rsa2':
            return self.worker.genkey(4096)
        elif self.algo == 'ecc1':
            return self.worker.genkey()
        elif self.algo == 'pqc1':
            return self.worker.genkey()

    def Loadkey(self, public: bytes|None, private: bytes|None):
        if self.algo in ["rsa1", "rsa2", "ecc1", "pqc1"]:
            self.worker.loadkey(public, private)

    def Encrypt(self, data: bytes) -> bytes:
        if self.algo in ["rsa1", "rsa2", "ecc1", "pqc1"]:
            return self.worker.encrypt(data)

    def Decrypt(self, data: bytes) -> bytes:
        if self.algo in ["rsa1", "rsa2", "ecc1", "pqc1"]:
            return self.worker.decrypt(data)

    def Sign(self, data: bytes) -> bytes:
        if self.algo in ["rsa1", "rsa2", "ecc1", "pqc1"]:
            return self.worker.sign(data)

    def Verify(self, data: bytes, signature: bytes) -> bool:
        if self.algo in ["rsa1", "rsa2", "ecc1", "pqc1"]:
            return self.worker.verify(data, signature)

# ========== RSA Encryption ==========
class RSA1:
    def __init__(self):
        self.public: Optional[RSA.RsaKey] = None
        self.private: Optional[RSA.RsaKey] = None

    def __del__(self):
        self.public = None
        self.private = None

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

# ========== ECC Encryption ==========
class ECC1: # Curve448
    def __init__(self):
        self.pubX: Optional[x448.X448PublicKey] = None
        self.priX: Optional[x448.X448PrivateKey] = None
        self.pubEd: Optional[ed448.Ed448PublicKey] = None
        self.priEd: Optional[ed448.Ed448PrivateKey] = None
        # encryption format: [1B PubLen][PubKey][encdata][tag]

    def __del__(self):
        self.pubX = None
        self.priX = None
        self.pubEd = None
        self.priEd = None

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

    def encrypt(self, data: bytes) -> bytes: # encrypt with public key
        tempKey = x448.X448PrivateKey.generate() # 1. Generate temp ephemeral key
        tempPub = tempKey.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        shared = tempKey.exchange(self.pubX) # 2. Get shared secret (ECDH)
        gcmKey = genkey(shared, "KEYGEN_ECC1_ENCRYPT", 44)
        enc = SymMaster("gcm1", gcmKey).EnBin(data) # 3. Encrypt with AES-GCM

        del tempKey
        del shared
        del gcmKey
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
        del tempKey
        del shared
        return SymMaster("gcm1", gcmKey).DeBin(enc)

    def sign(self, data: bytes) -> bytes: # Ed448
        return self.priEd.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool: # Ed448
        try:
            self.pubEd.verify(signature, data)
            return True
        except:
            return False

# ========== PQC1 Encryption ==========
class PQC1:
    def __init__(self):
        # ECC Key Objects
        self.pubX: Optional[x448.X448PublicKey] = None
        self.priX: Optional[x448.X448PrivateKey] = None
        self.pubEd: Optional[ed448.Ed448PublicKey] = None
        self.priEd: Optional[ed448.Ed448PrivateKey] = None
        
        # PQC Key Bytes
        self.pubKEM: Optional[bytes] = None
        self.priKEM: Optional[bytes] = None
        self.pubDSA: Optional[bytes] = None
        self.priDSA: Optional[bytes] = None

        # save PQC bytes as XOR masked
        self.mask = Masker()

    def __del__(self):
        self.pubX = None
        self.priX = None
        self.pubEd = None
        self.priEd = None

        self.pubKEM = None
        self.priKEM = None
        self.pubDSA = None
        self.priDSA = None

        self.mask = None

    def genkey(self) -> Tuple[bytes, bytes]: # (public, private)
        # 1. Curve448 key generation
        self.priX = x448.X448PrivateKey.generate()
        self.pubX = self.priX.public_key()
        self.priEd = ed448.Ed448PrivateKey.generate()
        self.pubEd = self.priEd.public_key()

        # get raw bytes
        pub0 = self.pubX.public_bytes_raw() # 56B
        pri0 = self.priX.private_bytes_raw() # 56B
        pub1 = self.pubEd.public_bytes_raw() # 57B
        pri1 = self.priEd.private_bytes_raw() # 57B

        # 2. ML-KEM-1024 & ML-DSA-87 key generation
        self.pubKEM, self.priKEM = mlkem_gen()
        self.pubDSA, self.priDSA = mldsa_gen()

        # 3. join keys (Public: 4273B, Private: 8177B)
        pubB = pub0 + pub1 + self.pubKEM + self.pubDSA
        priB = pri0 + pri1 + self.priKEM + self.priDSA
        self.priKEM, self.priDSA = self.mask.XOR(self.priKEM), self.mask.XOR(self.priDSA) # save as XOR masked
        return (pubB, priB)

    def loadkey(self, public: bytes|None, private: bytes|None):
        if public:
            if len(public) != 4273: raise ValueError("Invalid PQC1 public key length")
            self.pubX = x448.X448PublicKey.from_public_bytes(public[:56])
            self.pubEd = ed448.Ed448PublicKey.from_public_bytes(public[56:113])
            self.pubKEM = public[113:1681]  # 113 + 1568
            self.pubDSA = public[1681:4273] # 1681 + 2592
            
        if private:
            if len(private) != 8177: raise ValueError("Invalid PQC1 private key length")
            self.priX = x448.X448PrivateKey.from_private_bytes(private[:56])
            self.priEd = ed448.Ed448PrivateKey.from_private_bytes(private[56:113])
            self.priKEM = self.mask.XOR(private[113:3281])  # 113 + 3168
            self.priDSA = self.mask.XOR(private[3281:8177]) # 3281 + 4896

    def encrypt(self, data: bytes) -> bytes:
        # 1. Ephemeral X448 tempkey generation
        tempKey = x448.X448PrivateKey.generate()
        tempPub = tempKey.public_key().public_bytes_raw()
        ssvECC = tempKey.exchange(self.pubX) # 56B

        # 2. ML-KEM-1024 Encapsulation
        kemEnc, ssvKEM = mlkem_enc(self.pubKEM) # Cipher 1568B, Secret 32B

        # 3. Hybrid KDF & Encryption
        gcmKey = genkey(ssvECC + ssvKEM, "KEYGEN_PQC1_ENCRYPT", 44)
        enc = SymMaster("gcm1", gcmKey).EnBin(data)

        # [Temp X448 56B][Temp KEM 1568B][CipherText][Tag 16B]
        del tempKey
        del ssvECC
        del ssvKEM
        del gcmKey
        return tempPub + kemEnc + enc

    def decrypt(self, data: bytes) -> bytes:
        # 1. seperate data
        tempPub = data[:56]
        kemEnc = data[56:1624]
        enc = data[1624:]

        # 2. Shared Secret Value
        tempXKey = x448.X448PublicKey.from_public_bytes(tempPub)
        ssvECC = self.priX.exchange(tempXKey)
        ssvKEM = mlkem_dec(self.mask.XOR(self.priKEM), kemEnc)

        # 3. Hybrid KDF & Decryption
        gcmKey = genkey(ssvECC + ssvKEM, "KEYGEN_PQC1_ENCRYPT", 44)
        del tempXKey
        del ssvECC
        del ssvKEM
        return SymMaster("gcm1", gcmKey).DeBin(enc)

    def sign(self, data: bytes) -> bytes:
        # ECC-Ed448 (114B) + ML-DSA-87 (4627B)
        edSgn = self.priEd.sign(data)
        mlSgn = mldsa_sign(self.mask.XOR(self.priDSA), data)
        return edSgn + mlSgn

    def verify(self, data: bytes, signature: bytes) -> bool:
        if len(signature) != 4741: return False
        edSgn = signature[:114]
        mlSgn = signature[114:]
        try:
            self.pubEd.verify(edSgn, data)
            return mldsa_verify(self.pubDSA, data, mlSgn)
        except:
            return False