## Opsec

Bencrypt에 기반하는 보안 파일 컨테이너와 지원 함수들입니다. 비밀번호 기반 모드와 공개키 기반 모드가 있습니다. 이 모듈은 헤더 데이터만 담당하며, **본문 데이터 아카이빙, 암호화, 패딩은 `body key`로 따로 수행**해야 합니다.

Secure file container and helper functions based on Bencrypt. Supports password-based mode and public-key-based mode. This module handles header data only; **archiving, encryption, and padding of body data must be performed separately** using the body key.

#### Supported Methods

- pw-mode: `sha3, arg2low, arg2st`
- pub-mode: `ecc1, pqc1`

#### python
```py
def Crc32(data: bytes) -> str
def PadLen(size: int) -> int
def PadFile(f: io.IOBase, size: int)

def EncodeInt(data: int, size: int, signed: bool) -> bytes
def DecodeInt(data: bytes, signed: bool) -> int
def EncodeCfg(data: Dict[str, bytes]) -> bytes
def DecodeCfg(data: bytes) -> Dict[str, bytes]

class Opsec:
    Msg: str
    MsgInfo: bytes
    Smsg: str
    SmsgInfo: bytes
    BodyAlgo: str
    BodyKey: bytes
    BodySize: int
    BodyInfo: bytes
    
    def Init()
    def Clear()
    def Read(ins: io.IOBase, cut: int = 65535) -> bytes
    def Write(outs: io.IOBase, head: bytes)
    
    def Encpw(method: str, pw: bytes, kf: bytes = b"") -> bytes
    def Encpub(method: str, peerPub: bytes, myPri: bytes | None = None) -> bytes
    def View(data: bytes)
    def Decpw(pw: bytes, kf: bytes = b"")
    def Decpub(myPri: bytes, myPub: bytes | None = None, peerPub: bytes | None = None)
```

#### javascript
```js
function Crc32(data: Uint8Array | string): string
function PadLen(size: number): number
async function PadFile(f: Object, size: number)

function EncodeInt(data: number, size: number): Uint8Array
function DecodeInt(data: Uint8Array): number
function EncodeCfg(data: Object): Uint8Array
function DecodeCfg(data: Uint8Array): Object

class Opsec {
    Msg: string
    MsgInfo: Uint8Array
    Smsg: string
    SmsgInfo: Uint8Array
    BodyAlgo: string
    BodyKey: Uint8Array
    BodySize: number
    BodyInfo: Uint8Array
    
    Init()
    Clear()
    async function Read(ins, cut): Promise<Uint8Array>
    async function Write(outs, head)
    
    async function Encpw(method, pw, kf): Promise<Uint8Array>
    async function Encpub(method, peerPub, myPri = null): Promise<Uint8Array>
    function View(data)
    async function Decpw(pw, kf)
    async function Decpub(myPri, myPub = null, peerPub = null)
}
```

#### golang
```go
func Crc32(data []byte) string
func PadLen(size int64) int64
func PadFile(f io.Writer, size int64) error

func EncodeInt(data uint64, size int) []byte
func DecodeInt(data []byte) uint64
func EncodeCfg(data map[string][]byte) ([]byte, error)
func DecodeCfg(data []byte) map[string][]byte

type Opsec struct {
    Msg string
    MsgInfo []byte
    Smsg string
    SmsgInfo []byte
    BodyAlgo string
    BodyKey []byte
    BodySize int64
    BodyInfo []byte

    func Init()
    func Clear()
    func Read(r io.Reader, cut int) ([]byte, error)
    func Write(w io.Writer, head []byte) error
    
    func Encpw(method string, pw []byte, kf []byte) ([]byte, error)
    func Encpub(method string, peerPub []byte, myPri []byte) ([]byte, error)
    func View(data []byte)
    func Decpw(pw []byte, kf []byte) error
    func Decpub(myPri []byte, myPub []byte, peerPub []byte) error
}
```

#### java
```java
class Opsec {
    String Crc32(byte[] data)
    long PadLen(long size)
    PadFile(OutputStream f, long size) throws Exception
    
    byte[] EncodeInt(long data, int size)
    long DecodeInt(byte[] data)
    byte[] EncodeCfg(Map<String, byte[]> data) throws IOException
    Map<String, byte[]> DecodeCfg(byte[] data)
    
    String Msg;
    byte[] MsgInfo;
    String Smsg;
    byte[] SmsgInfo;
    String BodyAlgo;
    byte[] BodyKey;
    long BodySize;
    byte[] BodyInfo;

    void Init()
    void Clear()
    byte[] Read(InputStream ins, int cut) throws IOException
    void Write(OutputStream outs, byte[] head) throws IOException

    byte[] Encpw(String method, byte[] pw, byte[] kf) throws Exception
    byte[] Encpub(String method, byte[] peerPub, byte[] myPri) throws Exception
    void View(byte[] data)
    void Decpw(byte[] pw, byte[] kf) throws Exception
    void Decpub(byte[] myPri, byte[] myPub, byte[] peerPub) throws Exception
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

#### Header Structure

- hal (headAlgo): 헤더 암호화 알고리즘 Header encryption algorithm
- msg: 공개 메세지 **누구나 변조 가능** Public message **Modifiable by anyone**
- minf (msgInfo): 공개 보조정보 (RSA 보조 암호화 키 등) Public auxiliary information (ex. RSA auxiliary encryption keys)
- salt: pw-mode salt
- pwh (pwHash): pw-mode password hash
- ehd (encHeadData): 암호화된 헤더 정보 (다음 내용을 포함한다) Encrypted header data, which contains the following:
    - smsg (secureMsg): 비밀 메세지 Private message
    - sinf (secureInfo): 비밀 보조정보 (메세지 ID 등) Private auxiliary information (ex. Message ID)
    - bal (bodyAlgo): 본문 암호화 알고리즘 Body encryption algorithm
    - bkey (bodyKey): 본문 암호화 키 Body encryption key
    - bsz (bodySize): 본문 크기 Actual size of the body
    - binf (bodyInfo): 본문 보조정보 (패키징 알고리즘 등) Body auxiliary information (ex. packaging algorithms)
    - sgn (signature): 발신자 서명 (다음 내용을 합해 서명한다) Sender’s digital signature, generated by signing the following:
        - hal: 헤더 암호화 알고리즘 Header encryption algorithm
        - peerPub: 수신자 공개키 Receiver public key
        - smsg: 비밀 메세지 Private message
        - sinf: 비밀 보조정보 Private auxiliary information

- 헤더 노출 공개 필드 Publicly Exposed: `headAlgo, msg, msgInfo, salt, pwHash`
- 발신자 부인 불가 암호화 필드 Sender Non-Deniable: `secureMsg, secureInfo`
- 발신자 부인 가능 암호화 필드 Sender Deniable: `bodyAlgo, bodyKey, bodySize, bodyInfo` (informations about body)

비밀번호 모드는 발신자 검증을 지원하지 않으며, 공개키 모드는 서명을 포함하지 않는 익명 발송도 가능합니다.
pw-mode does not support sender verification. You can transmit anonymously by omitting the signature with pub-mode.

#### Padding Algorithm

트래픽 크기 분석을 방지하기 위해 패딩 함수를 제공합니다. 입력 크기에 따른 패딩 규칙은 다음과 같습니다. (경계값 크기인 경우 패딩하지 않습니다.)
Opsec은 원본 크기를 입력하면 패딩으로 추가할 크기를 계산해 반환하는 함수와 패딩 크기만큼 파일스트림에 랜덤값을 쓰는 함수를 제공합니다.

To prevent traffic size analysis attacks, we provide a standardized padding function.
The padding rules based on the input size are as follows (files which size is on border are not padded)
Opsec provides a function that calculates and returns the size to be added as padding when the original size is input.
It also offers a function that writes random values to a file stream corresponding to that padding size.

| Original Size | Padding Method | Buckets | Max Overhead |
| :--- | :--- | :--- | :--- |
| 0-16KiB | Fixed 4KiB Multiples | - | 4KiB |
| 16KiB-16MiB | Binary Floating-Point (K=2) | 2 per interval | 50.0% |
| 16MiB-512MiB | Binary Floating-Point (K=3) | 4 per interval | 25.0% |
| 512MiB-8GiB | Binary Floating-Point (K=4) | 8 per interval | 12.5% |
| 8GiB+ | Binary Floating-Point (K=5) | 16 per interval | 6.25% |
