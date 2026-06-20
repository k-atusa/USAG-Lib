## Bencrypt

현재 표준 권장 알고리즘보다 더 높은 보안 여유를 지원하는 암호화 모듈입니다.
메모리 마스킹으로 유휴시간 동안의 평문 키 노출을 줄일 수 있습니다.

Encryption module that supports higher security margin than currently recommended standard algorithms.
You can reduce plaintext key exposure during idle time through memory masking.

options
- Hash: `sha3, arg2low, arg2st`
- Symmetric: `gcm1, gcmx1`
- Asymmetric: `ecc1, pqc1`

#### python
```py
class HashMaster:
    def __init__(algo: str, hashSize: int = 32, keySize: int = 32) -> None
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

class Masker:
    def XOR(data: bytes) -> bytes

def Random(size: int) -> bytes
def SHA3256(data: bytes) -> bytes
def HMAC3256(key: bytes, data: bytes) -> bytes
def SHA3512(data: bytes) -> bytes
def HMAC3512(key: bytes, data: bytes) -> bytes
```

#### javascript
```js
class HashMaster {
    constructor(algo: string, hashSize: number = 32, keySize: number = 32)
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

class Masker {
    function XOR(data: Uint8Array): Uint8Array
}

function Random(size: number): Uint8Array
function SHA3256(data: Uint8Array | string): Uint8Array
function HMAC3256(key: Uint8Array | string, data: Uint8Array | string): Uint8Array
function SHA3512(data: Uint8Array | string): Uint8Array
function HMAC3512(key: Uint8Array | string, data: Uint8Array | string): Uint8Array
```

#### golang
```go
struct HashMaster {
    func Init(algo string, hashSize int, keySize int) error
    func KDF(pw []byte, salt []byte) ([]byte, []byte, error)
}

struct SymMaster {
    func Init(algo string, key []byte) error
    func AfterSize(size int64) int64
    func Processed() int64
    func EnBin(data []byte) ([]byte, error)
    func DeBin(data []byte) ([]byte, error)
    func EnFile(src io.Reader, size int64, dst io.Writer, chunkSize int) error
    func DeFile(src io.Reader, size int64, dst io.Writer, chunkSize int) error
}

struct AsymMaster {
    func Init(algo string) error
    func Genkey() ([]byte, []byte, error)
    func Loadkey(public []byte, private []byte) error
    func Encrypt(data []byte) ([]byte, error)
    func Decrypt(data []byte) ([]byte, error)
    func Sign(data []byte) ([]byte, error)
    func Verify(data []byte, signature []byte) bool
}

GetMasker(poolSizeMb int) *Masker
type Masker struct {
    func XOR(data []byte) ([]byte, error)
}

func Random(size int) []byte
func SHA3256(data []byte) []byte
func HMAC3256(key []byte, data []byte) []byte
func SHA3512(data []byte) []byte
func HMAC3512(key []byte, data []byte) []byte
```

#### java
```java
class Bencrypt {
    static class HashMaster {
        HashMaster(String algo, int hashSize, int keySize)
        HashMaster(String algo)
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

    static class Masker {
        Masker GetMasker()
        byte[] XOR(byte[] data)
    }

    // Basic Functions
    byte[] Random(int size)
    static byte[] SHA3256(byte[] data)
    static byte[] HMAC3256(byte[] key, byte[] data)
    static byte[] SHA3512(byte[] data)
    static byte[] HMAC3512(byte[] key, byte[] data)
}
```

## Usage

#### Memory Masker

- The purpose of masking is to reduce the attack surface where critical memory is exposed to swap
- Mask long-lived byte arrays in memory
- Using plaintext for short-lived variables like local variables with wiping is allowed

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

#### Argon2id

- Modern key derivation function
- Method `arg2low` parameter: `Time=4, Memory=65536, Parallel=8, Outsize=48B`, requires 64MiB
- Method `arg2st` parameter: `Time=3, Memory=262144, Parallel=6, Outsize=48B`, requires 256MiB

#### AES-GCM

- 32B key with 12B random generated IV
- Method `gcm1` format: `[IV 12B][CipherText][Tag 16B]`
- Method `gcmx1` format: `[GlobalIV 12B][CipherText 0][Tag 0 16B][CipherText 1][Tag 1 16B]...`, Divides input into 1MiB chunks and applies independent IVs (Base IV[4:12] XOR counter).

#### ECC

- Modern asymmetric algorithm using Curve448, which is independent from NSA issues
- Key format: `[X448 56B][Ed448 57B]` for both public and private key
- Encryption: `[KeyLen 1B][TempKey][IV 12B][CipherText][Tag 16B]`
- Signature: raw bytes using ECDSA Ed448

#### PQC1

- Hybrid model using both Curve448 and NIST FIPS 203/204
- Safe after post-quantum attacks
- Public Key: `[ECC-X448 56B][ECC-Ed448 57B][ML-KEM1024 1568B][ML-DSA87 2592B]` (4273B)
- Private Key: `[ECC-X448 56B][ECC-Ed448 57B][ML-KEM1024 3168B][ML-DSA87 4896B]` (8177B)
- Encryption: `[Temp ECC-X448 56B][Temp ML-KEM1024 1568B][IV 12B][CipherText][Tag 16B]` with HMAC(ECDH + ML-SSV)
- Signature: `[ECC-Ed448 114B][ML-DSA87 4627B]` (4741B), both parts are verified
