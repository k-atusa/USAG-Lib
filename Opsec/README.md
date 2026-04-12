## Opsec

Bencrypt에 기반하는 보안 파일 컨테이너와 지원 함수들입니다. 비밀번호 기반 모드와 공개키 기반 모드가 있습니다. 이 모듈은 헤더 데이터만 담당하며, 본문 데이터 아카이빙과 암호화는 `body key`로 따로 수행해야 합니다.

Secure file container and helper functions based on Bencrypt. Supports password-based mode and public-key-based mode. This module handles header data only; archiving and encryption of body data must be performed separately using the body key.

#### Supported Methods

- sha3
- pbk1
- arg1
- rsa1
- rsa2
- ecc1

#### python
```py
def Crc32(data: bytes) -> str
def EncodeInt(data: int, size: int, signed: bool) -> bytes
def DecodeInt(data: bytes, signed: bool) -> int
def EncodeCfg(data: Dict[str, bytes]) -> bytes
def DecodeCfg(data: bytes) -> Dict[str, bytes]

class Opsec:
    Msg: str           # Non-secured message
    Smsg: str          # Secured message
    Size: int          # Body size (-1: no body key)
    Name: str          # Body name
    BodyKey: bytes     # Body key
    BodyAlgo: str      # Body algorithm
    ContAlgo: str      # Container algorithm
    
    def Reset()
    def Read(ins: io.IOBase, cut: int = 65535) -> bytes
    def Write(outs: io.IOBase, head: bytes)
    
    def Encpw(method: str, pw: bytes, kf: bytes = b"") -> bytes
    def Encpub(method: str, public: bytes, private: bytes | None = None) -> bytes
    def View(data: bytes)
    def Decpw(pw: bytes, kf: bytes = b"")
    def Decpub(private: bytes, public: bytes | None = None)
```

#### javascript
```js
function Crc32(data: Uint8Array | string): string
function EncodeInt(data: number, size: number): Uint8Array
function DecodeInt(data: Uint8Array): number
function EncodeCfg(data: Object): Uint8Array
function DecodeCfg(data: Uint8Array): Object

class Opsec {
    Msg: String
    Smsg: String
    Size: Number
    Name: String
    BodyKey: Uint8Array
    BodyAlgo: String
    ContAlgo: String
    
    Reset()
    async function Read(ins, cut): Promise<Uint8Array>
    async function Write(outs, head)
    
    async function Encpw(method, pw, kf): Promise<Uint8Array>
    async function Encpub(method, publicBuf, privateBuf): Promise<Uint8Array>
    function View(data)
    async function Decpw(pw, kf)
    async function Decpub(privateBuf, publicBuf)
}
```

#### golang
```go
func Crc32(data []byte) string
func EncodeInt(data uint64, size int) []byte
func DecodeInt(data []byte) uint64
func EncodeCfg(data map[string][]byte) ([]byte, error)
func DecodeCfg(data []byte) map[string][]byte

type Opsec struct {
    Msg         string
    Smsg        string
    Size        int64
    Name        string
    BodyKey     []byte
    BodyAlgo    string
    ContAlgo    string

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
    public String Crc32(byte[] data)
    public byte[] EncodeInt(long data, int size)
    public long DecodeInt(byte[] data)
    public byte[] EncodeCfg(Map<String, byte[]> data) throws IOException
    public Map<String, byte[]> DecodeCfg(byte[] data)
    
    public String Msg;
    public String Smsg;
    public long Size;
    public String Name;
    public byte[] BodyKey;
    public String BodyAlgo;
    public String ContAlgo;

    public void Reset()
    public byte[] Read(InputStream ins, int cut) throws IOException
    public void Write(OutputStream outs, byte[] head) throws IOException

    public byte[] Encpw(String method, byte[] pw, byte[] kf) throws Exception
    public byte[] Encpub(String method, byte[] publicBytes, byte[] privateBytes) throws Exception
    public void View(byte[] data)
    public void Decpw(byte[] pw, byte[] kf) throws Exception
    public void Decpub(byte[] privateBytes, byte[] publicBytes) throws Exception
}
```

#### Config Encoding

헤더 정보는 `[KeyLen 1B][Key][DataSize 1B/2B][Data]`의 반복으로 직렬화됩니다. 키는 127 바이트, 데이터는 65535 바이트까지 기록할 수 있습니다.
데이터 크기가 255 바이트보다 크면 KeyLen에 128을 더해 표시하고 길이 표기에 2 바이트를 사용합니다. 아니라면 길이 표기에 1 바이트만 사용합니다.

Header information is serialized as a repetition of `[KeyLen 1B][Key][DataSize 1B/2B][Data]`. Keys can be up to 127 bytes, and data up to 65535 bytes.
If the data size is greater than 255 bytes, 128 is added to KeyLen to indicate this, and 2 bytes are used for the length field. Otherwise, only 1 byte is used for the length field.

#### File Structure

Opsec 컨테이너는 시작과 끝에 무의미한 데이터나 위장 파일을 넣을 수 있습니다.
128의 배수 위치에 있는 매직넘버 "YAS2"로 파일을 식별합니다.
이후 첫 2 바이트로 헤더 크기를 구합니다. 만약 이것이 65535라면 뒤의 2 바이트도 읽어 헤더 크기에 합산합니다. 헤더 크기는 최대 131070 바이트입니다.

Opsec containers can include meaningless data or decoy files at the beginning and end.
The file is identified by the magic number "YAS2" located at a multiple of 128 bytes.
Following this, the first 2 bytes determine the header size. If this value is 65535, the next 2 bytes are also read and added to the header size. The maximum header size is 131070 bytes.

#### Header Fields

다음 항목은 헤더에 그대로 노출됩니다.
- msg: 일반 메세지.
- headal: 헤더 암호화 알고리즘. 다음 중 하나여야 합니다: [arg1, pbk1, rsa1, ecc1]
- salt: pw-mode에서 사용하는 salt.
- pwh: pw-mode에서 사용하는 비밀번호 검증용 해시.
- ehk: rsa-mode용 암호화된 헤더 정보 키.
- ehd: 암호화된 헤더 정보.

The following fields are exposed in the header as-is:
- ​msg: General message.
- ​headal: Header encryption algorithm. Must be one of: [arg1, pbk1, rsa1, ecc1]
- ​salt: Salt used in pw-mode.
- ​pwh: Password verification hash used in pw-mode.
- ​ehk: Encrypted header information key for rsa-mode.
- ​ehd: Encrypted header information.

다음 항목은 암호화되어 헤더에 들어갑니다.
- smsg: 비밀 메세지.
- nm: 원본 파일명.
- sz: 원본 데이터 크기. -1로 설정될 경우 body가 없는 경우라 `body key`를 생성하지 않습니다.
- bkey: 본문 키.
- bodyal: 본문 암호화 알고리즘. 다음 중 하나여야 합니다: [gcm1, gcmx1]
- contal: 평문 컨테이너 종류. 다음 중 하나여야 합니다: [zip1, tar1]
- sgn: 전자서명 데이터. bkey가 존재한다면 bkey에 서명하고, 아니라면 smsg에 서명합니다.

The following fields are encrypted and stored within the header:
- ​smsg: Secret message.
- ​nm: Original filename.
- ​sz: Original data size. If set to -1, it indicates no body, so a body key is not generated.
- ​bkey: Body key.
- ​bodyal: Body encryption algorithm. Must be one of: [gcm1, gcmx1]
- ​contal: Plaintext container type. Must be one of: [zip1, tar1]
​sgn: Digital signature data. Signs bkey if it exists, otherwise signs smsg.
