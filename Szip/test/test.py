import os
import Szip

if not os.path.exists("big.bin"):
    with open("big.bin", "wb") as f:
        test = b"\x00" * 1024 * 1024 * 1024
        for i in range(5):
            f.write(test)

m = Szip.ZipWriter("test.zip", True)
m.WriteBin("이진 데이터", b"Hello, world!")
m.WriteFile("file", "big.bin")
m.Close()
m = Szip.ZipReader("test.zip")
print(m.Names, m.Sizes, m.Read(0))
m.Close()

# pack/unpack
os.mkdir("pack")
with open("pack/test.txt", "wb") as f:
    f.write(b"Hello, world!")
Szip.Pack("pack", "t.zip")
Szip.Unpack("t.zip", "pack")
