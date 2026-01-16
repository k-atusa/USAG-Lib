## USAG-Lib Star v0.1

간단화한 TAR-PAX 컨테이너 형식을 읽고 쓰는 모듈입니다. 안전성과 호환성을 위해 외부 라이브러리 없이 동작합니다.

#### python
```py
class TarWriter:
    def __init__(output: str)
    def writeFile(name: str, path: str, mode: int = 0o644)
    def writeDir(name: str, mode: int = 0o755)
    def writeBin(name: str, data: bytes, mode: int = 0o644)
    def close() -> bytes

class TarReader:
    def __init__(src: str | bytes)
    name: str
    size: int
    mode: int
    isDir: bool
    isEOF: bool
    def next() -> bool
    def read() -> bytes
    def mkfile(path: str)
    def skip()
    def close()
```

#### javascript
```js
class TarWriter {
    constructor(output: string)
    async function write(name: string, src: string | Blob | Uint8Array, isDir: boolean)
    async function close(): Uint8Array | null
}

class TarReader {
    constructor(input: string | Blob | Uint8Array)
    files: Array<{name: string, size: number, offset: number, isDir: boolean}>
    async function init()
    function read(idx: number): Uint8Array
    function close()
}
```

#### golang
```go
struct TarWriter {
    func Init(output string) error
    func WriteFile(name string, path string, mode int) error
    func WriteDir(name string, mode int) error
    func WriteBin(name string, data []byte, mode int) error
    func Close() []byte
}

struct TarReader {
    Name  string
    Size  int
    Mode  int
    IsDir bool
    IsEOF bool
    
    func Init(input interface{}) error
    func Next() bool
    func Read() []byte
    func Mkfile(path string) error
    func Skip()
    func Close()
}
```

#### java
```java
class Star implements Closeable {
    // Writer
    void openWriter(OutputStream out)
    void write(String name, byte[] data, int mode)
    void write(String name, File file, int mode)
    void write(String name, InputStream data, long size, int mode, boolean isDir)
    byte[] closeTar()

    // Reader
    String name;
    long size;
    int mode;
    boolean isDir;
    
    void openReader(InputStream in)
    boolean next()
    byte[] read()
    void mkfile(OutputStream dst)
    void skip()

    // Common
    byte[] closeTar()
    void close()
}
```
