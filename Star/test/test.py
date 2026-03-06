import os
import Star

if not os.path.exists("small.bin"): # make 100MiB file
    with open("small.bin", "wb") as f:
        f.write(b"\x00" * 1048576 * 100)

m = Star.TarWriter("")
m.WriteDir("test/")
m.WriteFile(f"test/{'가'*100}파일.bin", "small.bin") # long name test
m.WriteBin("이진 데이터", b"Hello, world!")

# write tar
with open("test.tar", "wb") as f:
    f.write(m.Close())
print("Created test.tar")

m = Star.TarReader("test.tar")

m.Next() # test/
print(f"Name: {m.Name}, Size: {m.Size}, IsDir: {m.IsDir}")
m.Mkfile(m.Name)

m.Next() # test/가가파일.bin
print(f"Name: {m.Name}, Size: {m.Size}, IsDir: {m.IsDir}")
m.Mkfile("small_out.bin")

m.Next() # binary data
print(f"Name: {m.Name}, Size: {m.Size}, IsDir: {m.IsDir}")
print("Data:", m.Read())

m.Close()

# pack/unpack
os.mkdir("pack")
with open("pack/test.txt", "wb") as f:
    f.write(b"Hello, world!")
Star.Pack("pack", "t.tar")
Star.Unpack("t.tar", "pack")
