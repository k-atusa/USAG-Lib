## Bencode

Base64 기반으로 이진 데이터를 텍스트로 인코딩합니다. 구분자를 사용해 인코딩 결과를 나눌 수 있습니다.

Encodes binary data into text using Base64. Using spliter will divide encode result.

spliter options: `!, @, #, $, %, ^, &, *, ~, |`

#### python
```py
def Encode64(data: bytes, spliter: str = "", linenum: int = 40, colnum: int = 10) -> str
def Decode64(data: str, spliter: str = "") -> bytes:
```

#### javascript
```js
function Encode64(data: Uint8Array, spliter: str = "", linenum: number = 40, colnum: number = 10): string
function Decode64(data: string, spliter: str = ""): Uint8Array
```

#### golang
```go
func Encode64(data []byte, spliter string, linenum int, colnum int) (string, error)
func Decode64(data string, spliter string) ([]byte, error)
```

#### java
```java
class Bencode {
    String Encode64(byte[] data, String spliter, int linenum, int colnum)
    byte[] Decode64(String data, String spliter)
}
```
