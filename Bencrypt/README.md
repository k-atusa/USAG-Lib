## Bencrypt

현재 표준 권장 알고리즘보다 더 높은 보안 여유를 지원하는 암호화 모듈입니다.

Encryption module that supports higher security margin than currently recommended standard algorithms.

options
- Hash: `sha3, pbk2, arg2`
- Symmetric: `gcm1, gcmx1`
- Asymmetric: `rsa1, rsa2, ecc1, pqc1`

#### python
```py
class HashMaster:
    def __init__(algo: str, hashSize: int = 32, keySize: int = 44) -> None
    def KDF(pw: bytes, salt: bytes) -> (bytes, bytes)
    
class SymMaster:
    def __init__(algo: str, key: bytes) -> None
    def AfterSize(size: int) -> int
    def Processed() -> int
    def EnBin(data: bytes) -> bytes
    def DeBin(data: bytes) -> bytes
    def EnFile(src: io.IOBase, size: int, dst: io.IOBase) -> None
    def DeFile(src: io.IOBase, size: int, dst: io.IOBase) -> None

class AsymMaster:
    def __init__(algo: str) -> None
    def Genkey() -> (bytes, bytes)
    def Loadkey(public: bytes | None, private: bytes | None)
    def Encrypt(data: bytes) -> bytes
    def Decrypt(data: bytes) -> bytes
    def Sign(data: bytes) -> bytes
    def Verify(data: bytes, signature: bytes) -> bool

def Random(size: int) -> bytes
def SHA3256(data: bytes) -> bytes
def SHA3512(data: bytes) -> bytes
```

#### javascript
```js
class HashMaster {
    constructor(algo: string, hashSize: number, keySize: number)
    async function KDF(pw, salt): Promise<[Uint8Array, Uint8Array]>
}

class SymMaster {
    constructor(algo: string, key: Uint8Array)
    AfterSize(size: number): number
    Processed(): number
    async function EnBin(data): Promise<Uint8Array>
    async function DeBin(data): Promise<Uint8Array>
    async function EnFile(src, size, dst)
    async function DeFile(src, size, dst)
}

class AsymMaster {
    constructor(algo: string)
    async function Genkey(): Promise<[Uint8Array, Uint8Array]>
    async function Loadkey(pub, pri)
    async function Encrypt(data): Promise<Uint8Array>
    async function Decrypt(data): Promise<Uint8Array>
    async function Sign(data): Promise<Uint8Array>
    async function Verify(data, signature): Promise<boolean>
}

function Random(size: number): Uint8Array
function SHA3256(data: Uint8Array | string): Uint8Array
function SHA3512(data: Uint8Array | string): Uint8Array
```

#### golang
```go
struct HashMaster {
    func Init(algo string, hashSize int, keySize int)
    func KDF(pw []byte, salt []byte) ([]byte, []byte, error)
}

struct SymMaster {
    func Init(algo string, key []byte)
    func AfterSize(size int64) int64
    func Processed() int64
    func EnBin(data []byte) ([]byte, error)
    func DeBin(data []byte) ([]byte, error)
    func EnFile(src io.Reader, size int64, dst io.Writer, chunkSize int) error
    func DeFile(src io.Reader, size int64, dst io.Writer, chunkSize int) error
}

struct AsymMaster {
    func Init(algo string)
    func Genkey() ([]byte, []byte, error)
    func Loadkey(public []byte, private []byte) error
    func Encrypt(data []byte) ([]byte, error)
    func Decrypt(data []byte) ([]byte, error)
    func Sign(data []byte) ([]byte, error)
    func Verify(data []byte, signature []byte) bool
}

func Random(size int) []byte
func SHA3256(data []byte) []byte
func SHA3512(data []byte) []byte
```

#### java
```java
class Bencrypt {
    static class HashMaster {
        HashMaster(String algo, int hashSize, int keySize)
        byte[][] KDF(byte[] pw, byte[] salt)
    }
    
    static class SymMaster {
        SymMaster(String algo, byte[] key)
        long AfterSize(long size)
        long Processed()
        byte[] EnBin(byte[] data)
        byte[] DeBin(byte[] data)
        void EnFile(InputStream src, long size, OutputStream dst)
        void DeFile(InputStream src, long size, OutputStream dst)
    }

    static class AsymMaster {
        AsymMaster(String algo)
        byte[][] Genkey()
        void Loadkey(byte[] pubBytes, byte[] priBytes)
        byte[] Encrypt(byte[] data)
        byte[] Decrypt(byte[] data)
        byte[] Sign(byte[] data)
        boolean Verify(byte[] data, byte[] signature)
    }

    // Basic Functions
    byte[] Random(int size)
    static byte[] SHA3256(byte[] data)
    static byte[] SHA3512(byte[] data)
}
```

## Usage

#### Hash Functions

- Used for data validation and key derivation
- Password (Low Entropy) + Salt (Stored for deterministic behavior) --(Hash/KDF)-> Master Secret (High Entropy) --(HMAC with different labels)-> Password Storage Hash, Session Key

#### Symmetric Encryption

- Used for large object encryption
- AES-256 is considered safe even in the era of quantum computers

#### Asymmetric Encryption

- Used for communication between users
- Use PQC algorithms for data used after year 2040 or for long-term storage
- You may use ECC for non-stored short-term data

## Format Standard

#### SHA3

- Supports SHA3-256/512. HashMaster and HMAC genkey is based on SHA3-512
- It can be used for linking subsystems, not directly hashing raw password
- Method `sha3` parameter: single SHA3-512

#### PBKDF2

- classic key derivation function
- Method `pbk2` parameter: `Hash=SHA-512, Iter=1000000, Outsize=64B`

#### Argon2id

- Modern key derivation function
- Method `arg2` parameter: `Time=3, Memory=262144, Parallel=4, Outsize=48B`, requires 256MiB

#### AES-GCM

- 44B integrated key: `[iv 12B][key 32B]`
- Method `gcm1` format: `[CipherText][Tag 16B]`
- Method `gcmx1` format: `[CipherText 0][Tag 0 16B][CipherText 1][Tag 1 16B]...`, Divides input into 1MiB chunks and applies independent IVs (Base IV[4:12] XOR counter).
- **Each Message Must Have Their Own Key**: Do not use same key twice, derive key from random source or use random salt (use Opsec layer)

#### RSA

- Legacy asymmetric algorithm
- Method `rsa1` is RSA-2048 and `rsa2` is RSA-4096
- Key format: PKIX-DER for public key and PKCS8-DER for private key
- OAEP-SHA-512 for encryption and PKCS#1 v1.5 SHA-256 for signature

#### ECC

- Modern asymmetric algorithm using Curve448, which is independent from NSA issues
- Key format: `[X448 56B][Ed448 57B]` for both public and private key
- Encryption: `[KeyLen 1B][TempKey][CipherText][Tag 16B]`
- Signature: raw bytes using ECDSA Ed448

#### PQC1

- Hybrid model using both Curve448 and NIST FIPS 203/204
- Safe after post-quantum attacks
- Public Key: `[ECC-X448 56B][ECC-Ed448 57B][ML-KEM1024 1568B][ML-DSA87 2592B]` (4273B)
- Private Key: `[ECC-X448 56B][ECC-Ed448 57B][ML-KEM1024 3168B][ML-DSA87 4896B]` (8177B)
- Encryption: `[Temp ECC-X448 56B][Temp ML-KEM1024 1568B][CipherText][Tag 16B]` with HMAC(ECDH + ML-SSV)
- Signature: `[ECC-Ed448 114B][ML-DSA87 4627B]` (4741B), both parts are verified
