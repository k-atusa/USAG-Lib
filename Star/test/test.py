import os
import Star

if not os.path.exists("small.bin"): # make 100MiB file
    with open("small.bin", "wb") as f:
        f.write(b"\x00" * 1048576 * 100)

m = Star.TarWriter("")
m.writeDir("test/")
m.writeFile(f"test/{'_'*100}small.bin", "small.bin") # long name test
m.writeBin("이진 데이터", b"Hello, world!")

# write tar
with open("test.tar", "wb") as f:
    f.write(m.close())
print("Created test.tar")

m = Star.TarReader("test.tar")

m.next() # test/
print(f"Name: {m.name}, Size: {m.size}, IsDir: {m.isDir}")
m.mkfile(m.name)

m.next() # test/___small.bin
print(f"Name: {m.name}, Size: {m.size}, IsDir: {m.isDir}")
m.mkfile("small_out.bin")

m.next() # binary data
print(f"Name: {m.name}, Size: {m.size}, IsDir: {m.isDir}")
print("Data:", m.read())

m.close()