## Bencode v0.1

Base-N으로 이진 데이터를 텍스트로 인코딩합니다. Base-64 모드는 표준적으로 사용되는 영문으로 인코딩합니다. Base-32k 모드는 한글과 한자로 인코딩하여 유니코드 지원 영역에서 더 높은 압축률을 가집니다.

#### python
```py
class Bencode:
    def encode(data: bytes, isBase64: bool) -> str
    def decode(data: str) -> bytes
```

#### javascript
```js
class Bencode {
    function encode(data: Uint8Array, isBase64: boolean): string
    function decode(data: string): Uint8Array
}
```

#### golang
```go
struct Bencode {
    func Encode(data []byte, isBase64 bool) string
    func Decode(data string) ([]byte, error)
}
```

#### java
```java
class Bencode {
    String encode(byte[] data, boolean isBase64)
    byte[] decode(String data)
}
```

#### Base-32k

한글 11172자 (U+AC00~), 한자 20992자 (U+4E00~), 총 32164개의 문자로 바이너리 데이터를 인코딩합니다. 바이너리는 15비트 단위로 끊겨 하나의 문자에 들어갑니다.
15 비트를 나타내기 위해 32164보다 크거나 같은 숫자는 이스케이프 처리로 `.`과 `값 - 32164`에 해당하는 문자를 사용합니다.
한 글자가 15비트를 나타내기 때문에, 비트스트림 마지막에 1을 붙이고 전체 길이가 15의 배수가 될 때까지 0으로 패딩합니다. 디코딩 시 마지막 1 전까지의 데이터만 사용합니다.

영문과 한글/한자는 글자 개수는 같아도 차지하는 폭이 약 2배 차이가 납니다.
Base64는 한 글자가 6비트를 나타내고 단일 폭도 6비트를 나타냅니다.
Base32k는 무작위 데이터를 가정하면, 98.16%는 한 글자/두 폭이 15비트를 나타내고 1.84%는 두 글자/세 폭이 15비트를 나타냅니다. 합하면 한 글자가 14.86비트를 나타내고 단일 폭이 7.45비트를 나타냅니다.
**텍스트 환경에서 실질 길이가 24.2% 감소합니다. 단, 한글/한자는 UTF-8 인코딩 시 3바이트를 사용하기 때문에 용량은 Base64보다 늘어납니다.**
