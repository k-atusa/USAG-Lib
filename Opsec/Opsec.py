# test794a : USAG-Lib opsec
from typing import Dict, Union

import zlib
import Bencrypt

def crc32(data: bytes) -> bytes:
    return zlib.crc32(data).to_bytes(4, 'little')

def encodeInt(data: int, size: int, signed: bool) -> bytes:
    return data.to_bytes(size, 'little', signed=signed)

def decodeInt(data: bytes, signed: bool) -> int:
    return int.from_bytes(data, 'little', signed=signed)

def encodeCfg(data: Dict[str, bytes]) -> bytes: # keysize max 127, datasize max 65535
    result = bytearray()
    for key, data in data.items():
        keyBytes = key.encode('utf-8')
        keyLen = len(keyBytes)
        dataLen = len(data)
        if keyLen > 127:
            raise ValueError(f"Key length is too long: {keyLen}")
        if dataLen > 65535:
            raise ValueError(f"Data size too big: {dataLen}")
        if dataLen > 255: # dataLen > 255, datasize is 2B
            encodedKeyLen = keyLen + 128
            result.append(encodedKeyLen)
            result.extend(keyBytes)
            result.extend(dataLen.to_bytes(2, 'little'))
        else: # dataLen <= 255, datasize is 1B
            result.append(keyLen)
            result.extend(keyBytes)
            result.append(dataLen)
        result.extend(data)
    return bytes(result)

def decodeCfg(data: bytes) -> Dict[str, bytes]: # format: [keyLen 1B][key][dataLen 1B/2B][data]
    result: Dict[str, bytes] = {}
    offset = 0
    totalLen = len(data)
    while offset < totalLen:
        keyLen = data[offset] # read keyLen
        isLongData = False
        offset += 1
        if keyLen > 127:
            keyLen -= 128
            isLongData = True
        keyBytes = data[offset : offset + keyLen] # read key
        key = keyBytes.decode('utf-8')
        offset += keyLen
        if isLongData: # dataLen is 2B
            dataLen = int.from_bytes(data[offset : offset + 2], 'little')
            offset += 2
        else: # dataLen is 1B
            dataLen = data[offset]
            offset += 1
        result[key] = data[offset : offset + dataLen] # read data
        offset += dataLen
    return result

# Opsec header handler
"""
pw: (msg), headAlgo, salt, pwHash, encHeadData
rsa: (msg), headAlgo, encHeadKey, encHeadData
ecc: (msg), headAlgo, encHeadData
header: (smsg), (size), (name), (bodyKey), (bodyAlgo), (contAlgo), (sign)
"""
class Opsec: # !!! DO NOT REUSE THIS OBJECT !!! reset after reading body key
    def __init__(self):
        self.reset()
    def reset(self):
        self.msg: str = "" # non-secured message
        self.headAlgo: str = "" # header algorithm, [arg1 pbk1 rsa1 ecc1]
        self.salt: bytes = b"" # salt
        self.pwHash: bytes = b"" # pw hash
        self.encHeadKey: bytes = b"" # encrypted header key
        self.encHeadData: bytes = b"" # encrypted header data

        self.smsg: str = "" # secured message
        self.size: int = -1 # full body size, flag for bodyKey generation
        self.name: str = "" # body name
        self.bodyKey: bytes = b"" # body key
        self.bodyAlgo: str = "" # body algorithm, [gcm1 gcmx1]
        self.contAlgo: str = "" # container algorithm, [zip1 tar1]
        self.sign: bytes = b"" # signature to bodyKey/smsg

    def _wrapHead(self) -> bytes:
        cfg: Dict[str, bytes] = {}
        if self.smsg != "":
            cfg["smsg"] = self.smsg.encode('utf-8')
        if self.size >= 0:
            if self.size < 65536:
                cfg["sz"] = encodeInt(self.size, 2, False)
            elif self.size < 4294967296:
                cfg["sz"] = encodeInt(self.size, 4, False)
            else:
                cfg["sz"] = encodeInt(self.size, 8, False)
        if self.name != "":
            cfg["nm"] = self.name.encode('utf-8')
        if self.bodyKey != b"":
            cfg["bkey"] = self.bodyKey
        if self.bodyAlgo != "":
            cfg["bodyal"] = self.bodyAlgo.encode('utf-8')
        if self.contAlgo != "":
            cfg["contal"] = self.contAlgo.encode('utf-8')
        if self.sign != b"":
            cfg["sgn"] = self.sign
        return encodeCfg(cfg)
    
    def _unwrapHead(self, data: bytes):
        cfg = decodeCfg(data)
        if "smsg" in cfg:
            self.smsg = cfg["smsg"].decode('utf-8')
        if "sz" in cfg:
            self.size = decodeInt(cfg["sz"], False)
        if "nm" in cfg:
            self.name = cfg["nm"].decode('utf-8')
        if "bkey" in cfg:
            self.bodyKey = cfg["bkey"]
        if "bodyal" in cfg:
            self.bodyAlgo = cfg["bodyal"].decode('utf-8')
        if "contal" in cfg:
            self.contAlgo = cfg["contal"].decode('utf-8')
        if "sgn" in cfg:
            self.sign = cfg["sgn"]

    def encpw(self, method: str, pw: bytes, kf: bytes = b"") -> bytes:
        # set basic parameters
        if method not in ["arg1", "pbk1"]:
            raise ValueError(f"Unsupported method: {method}")
        self.headAlgo = method
        self.salt = Bencrypt.random(16)
        if self.size >= 0:
            self.bodyKey = Bencrypt.random(44)

        # get master key, make pwHash, hkey
        if method == "arg1":
            mkey = Bencrypt.argon2Hash(pw + kf, self.salt).encode('utf-8')
            self.pwHash = Bencrypt.genkey(mkey, "PWHASH_OPSEC_ARGON2", 32)
            hkey = Bencrypt.genkey(mkey, "KEYGEN_OPSEC_ARGON2", 44)
        elif method == "pbk1":
            mkey = Bencrypt.pbkdf2(pw + kf, self.salt)
            self.pwHash = Bencrypt.genkey(mkey, "PWHASH_OPSEC_PBKDF2", 32)
            hkey = Bencrypt.genkey(mkey, "KEYGEN_OPSEC_PBKDF2", 44)

        # encrypt header
        headData = self._wrapHead()
        m = Bencrypt.AES1()
        self.encHeadData = m.enAESGCM(hkey, headData)

        # warp message
        cfg: Dict[str, bytes] = {}
        if self.msg != "":
            cfg["msg"] = self.msg.encode('utf-8')
        cfg["headal"] = self.headAlgo.encode('utf-8')
        cfg["salt"] = self.salt
        cfg["pwh"] = self.pwHash
        cfg["ehd"] = self.encHeadData
        return encodeCfg(cfg)
    
    def encpub(self, method: str, public: bytes, private: Union[bytes, None] = None) -> bytes: # sign if private is not None
        # set basic parameters
        if method not in ["rsa1", "ecc1"]:
            raise ValueError(f"Unsupported method: {method}")
        self.headAlgo = method
        if self.size >= 0:
            self.bodyKey = Bencrypt.random(44)
        if private != None:
            m = Bencrypt.RSA1() if method == "rsa1" else Bencrypt.ECC1()
            m.loadkey(None, private)
            if self.bodyKey != b"":
                self.sign = m.sign(self.bodyKey)
            elif self.smsg != "":
                self.sign = m.sign(self.smsg.encode('utf-8'))
        
        # encrypt header
        headData = self._wrapHead()
        if method == "rsa1":
            m = Bencrypt.RSA1()
            m.loadkey(public, None)
            hkey = Bencrypt.random(44)
            self.encHeadKey = m.encrypt(hkey)
            m = Bencrypt.AES1()
            self.encHeadData = m.enAESGCM(hkey, headData)
        elif method == "ecc1":
            m = Bencrypt.ECC1()
            m.loadkey(public, None)
            self.encHeadData = m.encrypt(headData)

        # warp message
        cfg: Dict[str, bytes] = {}
        if self.msg != "":
            cfg["msg"] = self.msg.encode('utf-8')
        cfg["headal"] = self.headAlgo.encode('utf-8')
        if self.encHeadKey != b"":
            cfg["ehk"] = self.encHeadKey
        cfg["ehd"] = self.encHeadData
        return encodeCfg(cfg)
        
    def view(self, data: bytes):
        self.reset()
        cfg = decodeCfg(data)
        if "msg" in cfg:
            self.msg = cfg["msg"].decode('utf-8')
        if "headal" in cfg:
            self.headAlgo = cfg["headal"].decode('utf-8')
        if "salt" in cfg:
            self.salt = cfg["salt"]
        if "pwh" in cfg:
            self.pwHash = cfg["pwh"]
        if "ehk" in cfg:
            self.encHeadKey = cfg["ehk"]
        if "ehd" in cfg:
            self.encHeadData = cfg["ehd"]

    def decpw(self, pw: bytes, kf: bytes = b""):
        if self.headAlgo == "":
            raise ValueError("Call view() first")
        if self.headAlgo not in ["arg1", "pbk1"]:
            raise ValueError(f"Unsupported method: {self.headAlgo}")
        mkey = b""
        verify_lbl = ""
        keygen_lbl = ""

        # generate master key
        if self.headAlgo == "arg1":
            mkey = Bencrypt.argon2Hash(pw + kf, self.salt).encode('utf-8')
            verify_lbl = "PWHASH_OPSEC_ARGON2"
            keygen_lbl = "KEYGEN_OPSEC_ARGON2"
        elif self.headAlgo == "pbk1":
            mkey = Bencrypt.pbkdf2(pw + kf, self.salt)
            verify_lbl = "PWHASH_OPSEC_PBKDF2"
            keygen_lbl = "KEYGEN_OPSEC_PBKDF2"

        # check password, generate header key
        calc_hash = Bencrypt.genkey(mkey, verify_lbl, 32)
        if calc_hash != self.pwHash:
            raise ValueError("Incorrect password")
        hkey = Bencrypt.genkey(mkey, keygen_lbl, 44)

        # decrypt header
        m = Bencrypt.AES1()
        try:
            decrypted_head = m.deAESGCM(hkey, self.encHeadData)
        except Exception:
            raise ValueError("AES decryption failed")
        self._unwrapHead(decrypted_head)

    def decpub(self, private: bytes, public: Union[bytes, None] = None): # verify sign if public is not None
        if self.headAlgo == "":
            raise ValueError("Call view() first")
        if self.headAlgo not in ["rsa1", "ecc1"]:
            raise ValueError(f"Unsupported method: {self.headAlgo}")
        decrypted_head = b""

        if self.headAlgo == "rsa1":
            rsa = Bencrypt.RSA1()
            aes = Bencrypt.AES1()
            try:
                rsa.loadkey(None, private)
                hkey = rsa.decrypt(self.encHeadKey)
                decrypted_head = aes.deAESGCM(hkey, self.encHeadData)
            except Exception:
                raise ValueError("RSA decryption failed")

        elif self.headAlgo == "ecc1":
            ecc = Bencrypt.ECC1()
            try:
                ecc.loadkey(None, private)
                decrypted_head = ecc.decrypt(self.encHeadData)
            except Exception:
                raise ValueError("ECC decryption failed")

        # unwrap header, check sign
        self._unwrapHead(decrypted_head)
        if public != None:
            s = b""
            if self.bodyKey != b"":
                s = self.bodyKey
            elif self.smsg != "":
                s = self.smsg.encode('utf-8')
            if self.headAlgo == "rsa1":
                m = Bencrypt.RSA1()
                m.loadkey(public, None)
                if not m.verify(s, self.sign):
                    raise ValueError("RSA signature verification failed")
            elif self.headAlgo == "ecc1":
                ecc = Bencrypt.ECC1()
                ecc.loadkey(public, None)
                if not ecc.verify(s, self.sign):
                    raise ValueError("ECC signature verification failed")