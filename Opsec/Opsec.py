# test794a : USAG-Lib opsec
from typing import Dict, Union

import io
import zlib
import Bencrypt

def crc32(data: bytes) -> str:
    return zlib.crc32(data).to_bytes(4, 'little').hex()

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
            raise ValueError(f"Key length too long: {keyLen}")
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
        self._headAlgo: str = "" # header algorithm, [arg1 pbk1 rsa1 ecc1]
        self._salt: bytes = b"" # salt
        self._pwHash: bytes = b"" # pw hash
        self._encHeadKey: bytes = b"" # encrypted header key
        self._encHeadData: bytes = b"" # encrypted header data

        self.smsg: str = "" # secured message
        self.size: int = -1 # full body size, flag for bodyKey generation
        self.name: str = "" # body name
        self.bodyKey: bytes = b"" # body key
        self.bodyAlgo: str = "" # body algorithm, [gcm1 gcmx1]
        self.contAlgo: str = "" # container algorithm, [zip1 tar1]
        self._sign: bytes = b"" # signature to bodyKey/smsg

    def read(self, ins: io.IOBase, cut: int = 65535) -> bytes: # set cut to 0 to read all
        c = 0
        while True:
            data = ins.read(4)
            c += 4
            if data == b"":
                return b""
            elif data == b"YAS2":
                size = decodeInt(ins.read(2), False)
                if size == 65535:
                    size += decodeInt(ins.read(2), False)
                return ins.read(size)
            else:
                ins.read(124)
                c += 124
            if cut > 0 and c > cut:
                return b""

    def write(self, outs: io.IOBase, head: bytes):
        outs.write(b"YAS2")
        size = len(head)
        if size < 65535:
            outs.write(encodeInt(size, 2, False))
        elif size <= 65535 * 2:
            outs.write(encodeInt(65535, 2, False))
            outs.write(encodeInt(size - 65535, 2, False))
        else:
            raise ValueError(f"Data size too big: {size}")
        outs.write(head)

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
        if self._sign != b"":
            cfg["sgn"] = self._sign
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
            self._sign = cfg["sgn"]

    def encpw(self, method: str, pw: bytes, kf: bytes = b"") -> bytes:
        # set basic parameters
        if method not in ["arg1", "pbk1"]:
            raise ValueError(f"Unsupported method: {method}")
        self._headAlgo = method
        self._salt = Bencrypt.random(16)
        if self.size >= 0:
            self.bodyKey = Bencrypt.random(44)

        # get master key, make pwHash, hkey
        if method == "arg1":
            mkey = Bencrypt.argon2Hash(pw + kf, self._salt).encode('utf-8')
            self._pwHash = Bencrypt.genkey(mkey, "PWHASH_OPSEC_ARGON2", 32)
            hkey = Bencrypt.genkey(mkey, "KEYGEN_OPSEC_ARGON2", 44)
        elif method == "pbk1":
            mkey = Bencrypt.pbkdf2(pw + kf, self._salt)
            self._pwHash = Bencrypt.genkey(mkey, "PWHASH_OPSEC_PBKDF2", 32)
            hkey = Bencrypt.genkey(mkey, "KEYGEN_OPSEC_PBKDF2", 44)

        # encrypt header
        headData = self._wrapHead()
        sm = Bencrypt.SymMaster("gcm1", hkey)
        self._encHeadData = sm.enBin(headData)

        # warp message
        cfg: Dict[str, bytes] = {}
        if self.msg != "":
            cfg["msg"] = self.msg.encode('utf-8')
        cfg["headal"] = self._headAlgo.encode('utf-8')
        cfg["salt"] = self._salt
        cfg["pwh"] = self._pwHash
        cfg["ehd"] = self._encHeadData
        return encodeCfg(cfg)
    
    def encpub(self, method: str, public: bytes, private: Union[bytes, None] = None) -> bytes: # sign if private is not None
        # set basic parameters
        if method not in ["rsa1", "ecc1"]:
            raise ValueError(f"Unsupported method: {method}")
        self._headAlgo = method
        if self.size >= 0:
            self.bodyKey = Bencrypt.random(44)
        
        # Init Master & Sign
        am = Bencrypt.AsymMaster(method)
        am.loadkey(public, private)
        
        if private != None:
            if self.bodyKey != b"":
                self._sign = am.sign(self.bodyKey)
            elif self.smsg != "":
                self._sign = am.sign(self.smsg.encode('utf-8'))
        
        # encrypt header
        headData = self._wrapHead()
        if method == "rsa1":
            # RSA Hybrid: Encrypt Key with RSA, Data with AES
            hkey = Bencrypt.random(44)
            self._encHeadKey = am.encrypt(hkey)
            sm = Bencrypt.SymMaster("gcm1", hkey)
            self._encHeadData = sm.enBin(headData)
        elif method == "ecc1":
            # ECC Hybrid: Handled internally by ECC1 class
            self._encHeadData = am.encrypt(headData)

        # warp message
        cfg: Dict[str, bytes] = {}
        if self.msg != "":
            cfg["msg"] = self.msg.encode('utf-8')
        cfg["headal"] = self._headAlgo.encode('utf-8')
        if self._encHeadKey != b"":
            cfg["ehk"] = self._encHeadKey
        cfg["ehd"] = self._encHeadData
        return encodeCfg(cfg)
        
    def view(self, data: bytes):
        self.reset()
        cfg = decodeCfg(data)
        if "msg" in cfg:
            self.msg = cfg["msg"].decode('utf-8')
        if "headal" in cfg:
            self._headAlgo = cfg["headal"].decode('utf-8')
        if "salt" in cfg:
            self._salt = cfg["salt"]
        if "pwh" in cfg:
            self._pwHash = cfg["pwh"]
        if "ehk" in cfg:
            self._encHeadKey = cfg["ehk"]
        if "ehd" in cfg:
            self._encHeadData = cfg["ehd"]

    def decpw(self, pw: bytes, kf: bytes = b""):
        if self._headAlgo == "":
            raise ValueError("Call view() first")
        if self._headAlgo not in ["arg1", "pbk1"]:
            raise ValueError(f"Unsupported method: {self._headAlgo}")
        mkey = b""
        verify_lbl = ""
        keygen_lbl = ""

        # generate master key
        if self._headAlgo == "arg1":
            mkey = Bencrypt.argon2Hash(pw + kf, self._salt).encode('utf-8')
            verify_lbl = "PWHASH_OPSEC_ARGON2"
            keygen_lbl = "KEYGEN_OPSEC_ARGON2"
        elif self._headAlgo == "pbk1":
            mkey = Bencrypt.pbkdf2(pw + kf, self._salt)
            verify_lbl = "PWHASH_OPSEC_PBKDF2"
            keygen_lbl = "KEYGEN_OPSEC_PBKDF2"

        # check password, generate header key
        calc_hash = Bencrypt.genkey(mkey, verify_lbl, 32)
        if calc_hash != self._pwHash:
            raise ValueError("Incorrect password")
        hkey = Bencrypt.genkey(mkey, keygen_lbl, 44)

        # decrypt header
        sm = Bencrypt.SymMaster("gcm1", hkey)
        self._unwrapHead(sm.deBin(self._encHeadData))

    def decpub(self, private: bytes, public: Union[bytes, None] = None): # verify sign if public is not None
        if self._headAlgo == "":
            raise ValueError("Call view() first")
        if self._headAlgo not in ["rsa1", "ecc1"]:
            raise ValueError(f"Unsupported method: {self._headAlgo}")
        
        am = Bencrypt.AsymMaster(self._headAlgo)
        am.loadkey(public, private)
        decrypted_head = b""

        # decrypt header
        if self._headAlgo == "rsa1":
            hkey = am.decrypt(self._encHeadKey)
            sm = Bencrypt.SymMaster("gcm1", hkey)
            decrypted_head = sm.deBin(self._encHeadData)
        elif self._headAlgo == "ecc1":
            decrypted_head = am.decrypt(self._encHeadData)

        # unwrap header, check sign
        self._unwrapHead(decrypted_head)
        if public != None:
            s = b""
            if self.bodyKey != b"":
                s = self.bodyKey
            elif self.smsg != "":
                s = self.smsg.encode('utf-8')
            
            if not am.verify(s, self._sign):
                raise ValueError(f"{self._headAlgo.upper()} signature verification failed")