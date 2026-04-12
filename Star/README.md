## USAG-Lib Star

간단화한 TAR-PAX 컨테이너 형식을 읽고 쓰는 모듈입니다. 안정성과 호환성을 위해 외부 라이브러리 없이 동작합니다.
스트림 형태로 입력받기 때문에, 데이터 로드 후 `헤더 탐색, 필드에 저장된 값 확인, 읽기 혹은 지나가기`를 반복하여 사용합니다.

Module for reading and writing a simplified TAR-PAX container format. Operates without external libraries for stability and compatibility.
Since it accepts input as a stream, it is used by repeating the process of header search, checking field values, reading or skipping after loading data.

#### python
```py
class TarWriter:
    def __init__(output: str)
    def WriteFile(name: str, path: str, mode: int = 0o644)
    def WriteDir(name: str, mode: int = 0o755)
    def WriteBin(name: str, data: bytes, mode: int = 0o644)
    def Close() -> bytes

class TarReader:
    def __init__(src: str | bytes)
    Name: str
    Size: int
    mode: int
    IsDir: bool
    IsEOF: bool
    def Next() -> bool
    def Read() -> bytes
    def Mkfile(path: str)
    def Skip()
    def Close()

Pack(srcs: str|list[str], dst: str) -> None
Unpack(src: str, dst: str) -> None
```

#### javascript
```js
class TarWriter {
    constructor(output: string)
    async function Write(name: string, src: string | Blob | Uint8Array, isDir: boolean)
    async function Close(): Uint8Array | null
}

class TarReader {
    constructor(input: string | Blob | Uint8Array)
    Files: Array<{Name: string, Size: number, Offset: number, IsDir: boolean}>
    async function Init()
    function Read(idx: number): Uint8Array
    function Close()
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
    Size  int64
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

func Pack(srcs []string, dst string) error
func Unpack(src string, dst string) error
```

#### java
```java
class Star {
    static class TarWriter implements Closeable {
        void Open(OutputStream out)
        void Write(String name, byte[] data, int mode)
        void Write(String name, File file, int mode)
        void Write(String name, InputStream data, long size, int mode, boolean isDir)
        byte[] Close()
        void close()
    }

    static class TarReader implements Closeable {
        String Name;
        long Size;
        int Mode;
        boolean IsDir;
        
        void Open(InputStream in)
        boolean Next()
        byte[] Read()
        void Mkfile(OutputStream dst)
        void Skip()
        void close()
    }
}
```
