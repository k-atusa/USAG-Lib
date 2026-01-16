## Szip v0.1

간단화한 Zip64 컨테이너 형식을 읽고 쓰는 모듈입니다.

#### python
```py
class ZipWriter:
    def __init__(output: str, compress: bool)
    def writefile(name: str, path: str)
    def writebin(name: str, data: bytes)
    def close() -> bytes

class ZipReader:
    def __init__(input: str | bytes)
    names: list[str]
    sizes: list[int]
    def read(idx: int) -> bytes
    def open(idx: int) -> io.IOBase
    def close()
```

#### javascript
```js
class ZipWriter {
    constructor(output: string, compress: boolean)
    async function writefile(name: string, src: string | Blob | File)
    function writebin(name: string, data: Uint8Array | string | Blob)
    async function close(): Uint8Array | null
}

class ZipReader {
    constructor(input: string | Blob | Uint8Array)
    names: string[]
    sizes: number[]
    async function init()
    async function read(idx: number): Uint8Array
    function close()
}
```

#### golang
```go
struct ZipWriter {
    func Init(output string, compress bool) error
    func WriteFile(name string, path string) error
    func WriteBin(name string, data []byte) error
    func Close() ([]byte, error)
}

struct ZipReader {
    Names []string
    Sizes []int
    func Init(input interface{}) error
    func Read(idx int) ([]byte, error)
    func Open(idx int) (io.ReadCloser, error)
    func Close() error
}
```

#### java
```java
class Szip {
    // Writer
    void openWriter(File file, boolean compress)
    void write(String name, byte[] data)
    void write(String name, File file)
    void write(String name, InputStream inputStream)
    byte[] closeZip()

    // Reader
    List<String> names
    List<Long> sizes
    void openReader(File file)
    void openReader(byte[] data)
    byte[] read(int idx)
    InputStream open(int idx)
}
```
