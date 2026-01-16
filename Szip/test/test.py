import os
import Szip

if not os.path.exists("big.bin"):
    with open("big.bin", "wb") as f:
        test = b"\x00" * 1024 * 1024 * 1024
        for i in range(5):
            f.write(test)

m = Szip.ZipWriter("test.zip", False)
m.writebin("이진 데이터", b"Hello, world!")
m.writefile("file", "big.bin")
m.close()
m = Szip.ZipReader("test.zip")
print(m.names, m.sizes, m.read(0))
m.close()
