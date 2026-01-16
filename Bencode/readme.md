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
