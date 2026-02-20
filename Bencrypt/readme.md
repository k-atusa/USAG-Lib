## Bencrypt

AES, RSA, ECC를 지원하는 암호화 모듈입니다. 현재 표준 권장 알고리즘보다 더 높은 보안 여유를 가지고 있습니다.

Encryption module supporting AES, RSA, and ECC. It has a higher security margin than currently recommended standard algorithms.

options
- gcm1
- gcmx1
- rsa1
- rsa1-2k
- rsa1-3k
- rsa1-4k
- ecc1

#### python
```py
class SymMaster:
    def __init__(algo: str, key: bytes) -> None
    def aftersize(size: int) -> int
    def processed() -> int
    def enBin(data: bytes) -> bytes
    def deBin(data: bytes) -> bytes
    def enFile(src: io.IOBase, size: int, dst: io.IOBase) -> None
    def deFile(src: io.IOBase, size: int, dst: io.IOBase) -> None

class AsymMaster:
    def __init__(algo: str) -> None
    def genkey() -> Tuple[bytes, bytes]
    def loadkey(public: bytes | None, private: bytes | None)
    def encrypt(data: bytes) -> bytes
    def decrypt(data: bytes) -> bytes
    def sign(data: bytes) -> bytes
    def verify(data: bytes, signature: bytes) -> bool

def random(size: int) -> bytes
def sha3256(data: bytes) -> bytes
def sha3512(data: bytes) -> bytes
def pbkdf2(pw: bytes, salt: bytes, iter: int, outsize: int) -> bytes
def argon2Hash(pw: bytes, salt: bytes = None) -> str
def argon2Verify(hashed: str, pw: bytes) -> bool
def genkey(data: bytes, lbl: str, size: int) -> bytes
```

#### javascript
```js
function InitBencrypt() // Initialize (Required)

class SymMaster {
    constructor(algo: string, key: Uint8Array)
    aftersize(size: number): number
    processed(): number
    async function enBin(data): Promise<Uint8Array>
    async function deBin(data): Promise<Uint8Array>
    async function enFile(src, size, dst)
    async function deFile(src, size, dst)
}

class AsymMaster {
    constructor(algo: string)
    async function genkey(): Promise<[Uint8Array, Uint8Array]>
    async function loadkey(pub, pri)
    async function encrypt(data): Promise<Uint8Array>
    async function decrypt(data): Promise<Uint8Array>
    async function sign(data): Promise<Uint8Array>
    async function verify(data, signature): Promise<boolean>
}

function random(size: number): Uint8Array
function sha3256(data: Uint8Array | string): Uint8Array
function sha3512(data: Uint8Array | string): Uint8Array
async function pbkdf2(pw, salt, iter, outsize): Promise<Uint8Array>
async function argon2Hash(pw, salt): Promise<string>
async function argon2Verify(hashed, pw): Promise<boolean>
function genkey(data, lbl, size): Uint8Array
```

#### golang
```go
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
func Sha3256(data []byte) []byte
func Sha3512(data []byte) []byte
func Pbkdf2(pw []byte, salt []byte, iter int, outsize int) []byte
func Argon2Hash(pw []byte, salt []byte) string
func Argon2Verify(hashed string, pw []byte) bool
func Genkey(data []byte, lbl string, size int) ([]byte, error)
```

#### java
```java
class Bencrypt {
    static class SymMaster {
        SymMaster(String algo, byte[] key)
        long aftersize(long size)
        long processed()
        byte[] enBin(byte[] data)
        byte[] deBin(byte[] data)
        void enFile(InputStream src, long size, OutputStream dst)
        void deFile(InputStream src, long size, OutputStream dst)
    }

    static class AsymMaster {
        AsymMaster(String algo)
        byte[][] genkey()
        void loadkey(byte[] pubBytes, byte[] priBytes)
        byte[] encrypt(byte[] data)
        byte[] decrypt(byte[] data)
        byte[] sign(byte[] data)
        boolean verify(byte[] data, byte[] signature)
    }

    // Basic Functions
    byte[] random(int size)
    static byte[] sha3256(byte[] data)
    static byte[] sha3512(byte[] data)
    static byte[] pbkdf2(byte[] pw, byte[] salt, int iter, int outsize)
    String argon2Hash(byte[] pw, byte[] salt)
    boolean argon2Verify(String hashed, byte[] pw)
    static byte[] genkey(byte[] data, String lbl, int size)
}
```

## Format Standard

#### Hash Functions

비밀번호(저 엔트로피) + Salt(결정적 동작을 위해 저장됨) --(Argon2id/PBKDF2)-> Master Secret(고 엔트로피) --(서로 다른 라벨로 HMAC)-> 비밀번호 저장해시, 세션 키

Password (Low Entropy) + Salt (Stored for deterministic behavior) --(Argon2id/PBKDF2)-> Master Secret (High Entropy) --(HMAC with different labels)-> Password Storage Hash, Session Key

- SHA3-256/512: SHA3 해시함수입니다. 데이터 변조를 탐지하는데 사용합니다.
SHA3 hash functions. Used to detect data tampering.
- PBKDF2: 비밀번호를 저장하는 해시함수입니다. 기본 파라미터는  `Hash=SHA-512, Iter=1000000, Outsize=64B`입니다.
Hash function for storing passwords. Default parameters are `Hash=SHA-512, Iter=1000000, Outsize=64B`.
- Argon2id: 비밀번호를 저장하는 최신 해시함수입니다. 파라미터는 `Time=3, Memory=262144, Parallel=4, Outsize=32B`입니다. 한 번 계산에 256MiB의 메모리가 필요합니다.
Modern hash function for storing passwords. Parameters are `Time=3, Memory=262144, Parallel=4, Outsize=32B`. Requires 256MiB of memory per calculation.
- genkey: 해시함수 결과물을 세션 키로 만드는 해시함수입니다. `HMAC-SHA3-512` 기반입니다.
Hash function to generate session keys from hash results. Based on `HMAC-SHA3-512`.

#### AES-GCM

키는 44바이트 고정으로, 앞 12바이트를 iv, 뒤 32바이트를 key로 사용합니다.
Key is fixed at 44 bytes; the first 12 bytes are used as IV, and the last 32 bytes as the Key.
- GCM 모드는 결과로 태그가 붙은 암호문을 내보냅니다. 형식: `[CipherText][Tag 16B]`
GCM mode: Outputs ciphertext with a tag appended. Format: `[CipherText][Tag 16B]`
- GCMx 모드는 입력은 1MiB로 나눠서 독립적인 iv(기본 iv[4:12] XOR counter)를 적용합니다. 출력에는 태그가 붙은 청크를 그대로 이어붙여 씁니다. 형식: `[CipherText 0][Tag 0 16B][CipherText 1][Tag 1 16B]...`
GCMx mode: Divides input into 1MiB chunks and applies independent IVs (Base IV[4:12] XOR counter). The output consists of concatenated tagged chunks. Format: `[CipherText 0][Tag 0 16B][CipherText 1][Tag 1 16B]...`

#### RSA

- 지원 비트: 2048, 3072, 4096
​Supported bits: 2048, 3072, 4096
- 키 형식: 공개키(PKIX-DER), 개인키(PKCS8-DER) 형식의 바이트 배열입니다.
Key format: Byte arrays in Public Key (PKIX-DER) and Private Key (PKCS8-DER) formats.
- 암호화: `OAEP-SHA-512`를 사용합니다.
Encryption: Uses OAEP-SHA-512.
- 서명: `PKCS#1 v1.5 SHA-256`을 사용합니다.
Signing: Uses `PKCS#1 v1.5 SHA-256`.

#### ECC

- 타원곡선: 생성 과정이 투명한 `Curve448`을 사용합니다.
Elliptic Curve: Uses Curve448, which has a transparent generation process.
- 키 형식: 공개키와 개인키 모두 113바이트 고정 길이 키를 사용합니다. 형식: `[X448 56B][Ed448 57B]`
Key format: Both public and private keys use fixed-length 113-byte keys. Format: `[X448 56B][Ed448 57B]`
- 암호화: 임시 키를 생성하고 수신자 공개키와 섞어 ECDH 공유 비밀키를 생성합니다. 이후 AES-GCM으로 데이터를 암호화합니다. 형식: `[KeyLen 1B][TempKey][CipherText][Tag 16B]`
Encryption: Generates an ephemeral key and mixes it with the recipient's public key to generate an ECDH shared secret. Then encrypts data using AES-GCM. Format: `[KeyLen 1B][TempKey][CipherText][Tag 16B]`
- 서명: ECDSA Ed448로 서명합니다.
Signing: Signs using ECDSA Ed448.
