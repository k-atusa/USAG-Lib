## Opsec v0.1

Bencrypt에 기반하는 보안 파일 컨테이너와 지원 함수들입니다. 비밀번호 기반 모드와 공개키 기반 모드가 있습니다. 이 모듈은 헤더 데이터만 담당하며, 본문 데이터 아카이빙과 암호화는 `body key`로 따로 수행해야 합니다. 

#### python
```py
def crc32(data: bytes) -> bytes
def encodeInt(data: int, size: int, signed: bool) -> bytes
def decodeInt(data: bytes, signed: bool) -> int
def encodeCfg(data: Dict[str, bytes]) -> bytes
def decodeCfg(data: bytes) -> Dict[str, bytes]

class Opsec:
    msg: str           # Non-secured message
    headAlgo: str      # Header algorithm [arg1, pbk1, rsa1, ecc1]
    salt: bytes        # Salt
    pwHash: bytes      # Password hash
    encHeadKey: bytes  # Encrypted header key (RSA)
    encHeadData: bytes # Encrypted header data
    smsg: str          # Secured message
    size: int          # Body size (-1: no body key)
    name: str          # Body name
    bodyKey: bytes     # Body key
    bodyAlgo: str      # Body algorithm
    contAlgo: str      # Container algorithm
    sign: bytes        # Signature
    
    def reset()
    def read(ins: io.IOBase, cut: int = 65535) -> bytes
    def write(outs: io.IOBase, head: bytes)
    
    def encpw(method: str, pw: bytes, kf: bytes = b"") -> bytes
    def encpub(method: str, public: bytes, private: bytes | None = None) -> bytes
    def view(data: bytes)
    def decpw(pw: bytes, kf: bytes = b"")
    def decpub(private: bytes, public: bytes | None = None)
```

#### javascript
```js
function crc32(data: Uint8Array | string): Uint8Array
function encodeInt(data: number, size: number): Uint8Array
function decodeInt(data: Uint8Array): number
function encodeCfg(data: Object): Uint8Array
function decodeCfg(data: Uint8Array): Object

class Opsec {
    msg: String
    headAlgo: String
    salt: Uint8Array
    pwHash: Uint8Array
    encHeadKey: Uint8Array
    encHeadData: Uint8Array
    smsg: String
    size: Number
    name: String
    bodyKey: Uint8Array
    bodyAlgo: String
    contAlgo; : String
    sign: Uint8Array
    
    reset()
    async function read(ins, cut): Promise<Uint8Array>
    async function write(outs, head)
    
    async function encpw(method, pw, kf): Promise<Uint8Array>
    async function encpub(method, publicBuf, privateBuf): Promise<Uint8Array>
    function view(data)
    async function decpw(pw, kf)
    async function decpub(privateBuf, publicBuf)
}
```

#### golang
```go
func Crc32(data []byte) []byte
func EncodeInt(data uint64, size int) []byte
func DecodeInt(data []byte) uint64
func EncodeCfg(data map[string][]byte) ([]byte, error)
func DecodeCfg(data []byte) map[string][]byte

type Opsec struct {
    Msg         string
    HeadAlgo    string
    Salt        []byte
    PwHash      []byte
    EncHeadKey  []byte
    EncHeadData []byte
    Smsg        string
    Size        int
    Name        string
    BodyKey     []byte
    BodyAlgo    string
    ContAlgo    string
    Sign        []byte

    func Reset()
    func Read(r io.Reader, cut int) ([]byte, error)
    func Write(w io.Writer, head []byte) error
    
    func Encpw(method string, pw []byte, kf []byte) ([]byte, error)
    func Encpub(method string, public []byte, private []byte) ([]byte, error)
    func View(data []byte)
    func Decpw(pw []byte, kf []byte) error
    func Decpub(private []byte, public []byte) error
}
```

#### java
```java
public class Opsec {
    public byte[] crc32(byte[] data)
    public byte[] encodeInt(long data, int size)
    public long decodeInt(byte[] data)
    public byte[] encodeCfg(Map<String, byte[]> data) throws IOException
    public Map<String, byte[]> decodeCfg(byte[] data)
    
    public String msg;
    public String headAlgo;
    public byte[] salt;
    public byte[] pwHash;
    public byte[] encHeadKey;
    public byte[] encHeadData;
    public String smsg;
    public long size;
    public String name;
    public byte[] bodyKey;
    public String bodyAlgo;
    public String contAlgo;
    public byte[] sign;

    public void reset()
    public byte[] read(InputStream ins, int cut) throws IOException
    public void write(OutputStream outs, byte[] head) throws IOException

    public byte[] encpw(String method, byte[] pw, byte[] kf) throws Exception
    public byte[] encpub(String method, byte[] publicBytes, byte[] privateBytes) throws Exception
    public void view(byte[] data)
    public void decpw(byte[] pw, byte[] kf) throws Exception
    public void decpub(byte[] privateBytes, byte[] publicBytes) throws Exception
}
```

#### Config Encoding

헤더 정보는 `[KeyLen 1B][Key][DataSize 1B/2B][Data]`의 반복으로 직렬화됩니다. 키는 127 바이트, 데이터는 65535 바이트까지 기록할 수 있습니다.
데이터 크기가 255 바이트보다 크면 KeyLen에 128을 더해 표시하고 길이 표기에 2 바이트를 사용합니다. 아니라면 길이 표기에 1 바이트만 사용합니다.

#### File Structure

Opsec 컨테이너는 시작과 끝에 무의미한 데이터나 위장 파일을 넣을 수 있습니다.
128의 배수 위치에 있는 매직넘버 "YAS2"로 파일을 식별합니다.
이후 첫 2 바이트로 헤더 크기를 구합니다. 만약 이것이 65535라면 뒤의 2 바이트도 읽어 헤더 크기에 합산합니다. 헤더 크기는 최대 131070 바이트입니다.

#### Header Fields

다음 항목은 헤더에 그대로 노출됩니다.
- msg: 일반 메세지.
- headal: 헤더 암호화 알고리즘. 다음 중 하나여야 합니다: [arg1, pbk1, rsa1, ecc1]
- salt: pw-mode에서 사용하는 salt.
- pwh: pw-mode에서 사용하는 비밀번호 검증용 해시.
- ehk: rsa-mode용 암호화된 헤더 정보 키.
- ehd: 암호화된 헤더 정보.

다음 항목은 암호화되어 헤더에 들어갑니다.
- smsg: 비밀 메세지.
- nm: 원본 파일명.
- sz: 원본 데이터 크기. -1로 설정될 경우 body가 없는 경우라 `body key`를 생성하지 않습니다.
- bkey: 본문 키.
- bodyal: 본문 암호화 알고리즘. 다음 중 하나여야 합니다: [gcm1, gcmx1]
- contal: 평문 컨테이너 종류. 다음 중 하나여야 합니다: [zip1, tar1]
- sgn: 전자서명 데이터. bkey가 존재한다면 bkey에 서명하고, 아니라면 smsg에 서명합니다.
