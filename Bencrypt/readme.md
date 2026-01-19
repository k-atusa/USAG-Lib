## Bencrypt v0.1

AES, RSA, ECC를 지원하는 암호화 모듈입니다.

#### python
```py
def random(size: int) -> bytes
def sha3256(data: bytes) -> bytes
def sha3512(data: bytes) -> bytes
def pbkdf2(pw: bytes, salt: bytes, iter: int, outsize: int) -> bytes
def argon2Hash(pw: bytes, salt: bytes = None) -> str
def argon2Verify(hashed: str, pw: bytes) -> bool
def genkey(data: bytes, lbl: str, size: int) -> bytes

class AES1:
    def processed() -> int
    def enAESGCM(key: bytes, data: bytes) -> bytes
    def deAESGCM(key: bytes, data: bytes) -> bytes
    def enAESGCMx(key: bytes, src: io.IOBase, size: int, dst: io.IOBase, chunkSize: int)
    def deAESGCMx(key: bytes, src: io.IOBase, size: int, dst: io.IOBase, chunkSize: int)

class RSA1:
    def genkey(bits: int) -> Tuple[bytes, bytes]
    def loadkey(public: bytes | None, private: bytes | None)
    def encrypt(data: bytes) -> bytes
    def decrypt(data: bytes) -> bytes
    def sign(data: bytes) -> bytes
    def verify(data: bytes, signature: bytes) -> bool

class ECC1:
    def genkey() -> Tuple[bytes, bytes]
    def loadkey(public: bytes | None, private: bytes | None)
    def encrypt(data: bytes, receiver: bytes) -> bytes
    def decrypt(data: bytes) -> bytes
    def sign(data: bytes) -> bytes
    def verify(data: bytes, signature: bytes) -> bool
```

#### javascript
```js
function InitBencrypt() // Initialize (Required)

function random(size: number): Uint8Array
function sha3256(data: Uint8Array | string): Uint8Array
function sha3512(data: Uint8Array | string): Uint8Array
async function pbkdf2(pw, salt, iter, outsize): Promise<Uint8Array>
async function argon2Hash(pw, salt): Promise<string>
async function argon2Verify(hashed, pw): Promise<boolean>
function genkey(data, lbl, size): Uint8Array

class AES1 {
    processed(): number
    async function enAESGCM(key, data): Promise<Uint8Array>
    async function deAESGCM(key, data): Promise<Uint8Array>
    async function enAESGCMx(key, src, size, dst, chunkSize)
    async function deAESGCMx(key, src, size, dst, chunkSize)
}

class RSA1 {
    async function genkey(bits): Promise<[Uint8Array, Uint8Array]>
    async function loadkey(publicBuf, privateBuf)
    async function encrypt(data): Promise<Uint8Array>
    async function decrypt(data): Promise<Uint8Array>
    async function sign(data): Promise<Uint8Array>
    async function verify(data, signature): Promise<boolean>
}

class ECC1 {
    async function genkey(): Promise<[Uint8Array, Uint8Array]>
    async function loadkey(pub, pri)
    async function encrypt(data, receiver): Promise<Uint8Array>
    async function decrypt(data): Promise<Uint8Array>
    async function sign(data): Promise<Uint8Array>
    async function verify(data, signature): Promise<boolean>
}
```

#### golang
```go
func Random(size int) []byte
func Sha3256(data []byte) []byte
func Sha3512(data []byte) []byte
func Pbkdf2(pw []byte, salt []byte, iter int, outsize int) []byte
func Argon2Hash(pw []byte, salt []byte) string
func Argon2Verify(hashed string, pw []byte) bool
func Genkey(data []byte, lbl string, size int) ([]byte, error)

struct AES1 {
    func Init()
    func Processed() int
    func EnAESGCM(key [44]byte, data []byte) ([]byte, error)
    func DeAESGCM(key [44]byte, data []byte) ([]byte, error)
    func EnAESGCMx(key [44]byte, src io.Reader, size int, dst io.Writer, chunkSize int) error
    func DeAESGCMx(key [44]byte, src io.Reader, size int, dst io.Writer, chunkSize int) error
}

struct RSA1 {
    func Genkey(bits int) ([]byte, []byte, error)
    func Loadkey(public []byte, private []byte) error
    func Encrypt(data []byte) ([]byte, error)
    func Decrypt(data []byte) ([]byte, error)
    func Sign(data []byte) ([]byte, error)
    func Verify(data []byte, signature []byte) bool
}

struct ECC1 {
    func Genkey() ([]byte, []byte, error)
    func Loadkey(public []byte, private []byte) error
    func Encrypt(data []byte, receiver []byte) ([]byte, error)
    func Decrypt(data []byte) ([]byte, error)
    func Sign(data []byte) ([]byte, error)
    func Verify(data []byte, signature []byte) bool
}
```

#### java
```java
class Bencrypt {
    // Basic Functions
    byte[] random(int size)
    byte[] sha3256(byte[] data)
    byte[] sha3512(byte[] data)
    byte[] pbkdf2(byte[] pw, byte[] salt, int iter, int outsize)
    String argon2Hash(byte[] pw, byte[] salt)
    boolean argon2Verify(String hashed, byte[] pw)
    byte[] genkey(byte[] data, String lbl, int size)

    // AES Functions
    long Processed()
    byte[] enAESGCM(byte[] key, byte[] data)
    byte[] deAESGCM(byte[] key, byte[] data)
    void enAESGCMx(byte[] key, InputStream src, long size, OutputStream dst, int chunkSize)
    void deAESGCMx(byte[] key, InputStream src, long size, OutputStream dst, int chunkSize)

    // RSA Functions
    byte[][] RSAgenkey(int bits)
    void RSAloadkey(byte[] pubBytes, byte[] priBytes)
    byte[] RSAencrypt(byte[] data)
    byte[] RSAdecrypt(byte[] data)
    byte[] RSAsign(byte[] data)
    boolean RSAverify(byte[] data, byte[] signature)

    // ECC Functions
    byte[][] ECCgenkey()
    void ECCloadkey(byte[] pubBytes, byte[] priBytes)
    byte[] ECCencrypt(byte[] data, byte[] receiver)
    byte[] ECCdecrypt(byte[] data)
    byte[] ECCsign(byte[] data)
    boolean ECCverify(byte[] data, byte[] signature)
}
```