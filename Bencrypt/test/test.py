import io
import base64
import Bencrypt

sheet = [ ]
with open("testsheet.txt", "r") as f:
    sheet = [ base64.b64decode(i) for i in f.read().split("\n") ]
pos = 0

# basic function test
print("testing basic functions...")
data = b"0000"
print( base64.b64encode(Bencrypt.Random(16)).decode('ascii') )
print( base64.b64encode(Bencrypt.SHA3256(data)).decode('ascii') ) # pq9wt68/QjUteD6LB1FeQzw9RWadTv7mcFFnJxk7KRs=
print( base64.b64encode(Bencrypt.SHA3512(data)).decode('ascii') ) # tnjOmGIvYntbNcoej2VvG9M1RdJCtZ8BWjHek4r6OvvmhThbjjzJ/zfYwq+G7r/TGe7WWr20vkGBzULuTzcPYQ==

# Masker
print("testing Masker...")
mA = Bencrypt.Masker()
mB = Bencrypt.Masker()
print(mA.XOR(b"\x00\x00\x00\x00"))
key = Bencrypt.Random(8753)
print(mB.XOR(mA.XOR(key)) == key)
key = Bencrypt.Random(16384)
print(mB.XOR(mA.XOR(key)) == key)

# HashMaster (pw_store, keygen)
print("testing HashMaster...")
hashm = ["sha3", "pbk2", "arg2"]
pw, salt = b"ABCDABCDABCDABCD", b"1234123412341234"
for algo in hashm:
    w = Bencrypt.HashMaster(algo)
    pwst, keygen = w.KDF(pw, salt)
    print(sheet[pos] == pwst)
    pos += 1
    print(sheet[pos] == keygen)
    pos += 1

# SymMaster (enbin, enfile)
print("testing SymMaster...")
symm = ["gcm1", "gcmx1"]
key = b"0" * 44
plain = b"Hello, world!" * 32
for algo in symm:
    w = Bencrypt.SymMaster(algo, key)
    print( plain == w.DeBin(sheet[pos]) )
    pos += 1
    temp = io.BytesIO()
    w.DeFile(io.BytesIO(sheet[pos]), len(sheet[pos]), temp)
    print( plain == temp.getvalue() )
    pos += 1

    bigdata = b"\x00" * 10000000 # 10MB
    bigenc = w.EnBin(bigdata)
    print( bigdata == w.DeBin(bigenc) )
    temp = io.BytesIO()
    w.EnFile(io.BytesIO(bigdata), len(bigdata), temp)
    bigenc = temp.getvalue()
    temp = io.BytesIO()
    w.DeFile(io.BytesIO(bigenc), len(bigenc), temp)
    print( bigdata == temp.getvalue() )

# AsymMaster (pubkey, prikey, enc, sign)
print("testing AsymMaster...")
asymm = ["rsa1", "rsa2", "ecc1", "pqc1"]
plain = b"Hello, world!"
for algo in asymm:
    w = Bencrypt.AsymMaster(algo)
    pub, pri = sheet[pos], sheet[pos + 1]
    pos += 2
    w.Loadkey(pub, pri)
    enc, sign = sheet[pos], sheet[pos + 1]
    pos += 2
    print( plain == w.Decrypt(enc) )
    print( w.Verify(plain, sign) )

    temp = Bencrypt.AsymMaster(algo)
    pub, pri = temp.Genkey()
    a, b = Bencrypt.AsymMaster(algo), Bencrypt.AsymMaster(algo)
    a.Loadkey(pub, None)
    b.Loadkey(None, pri)
    enc = a.Encrypt(plain)
    sign = b.Sign(plain)
    print( plain == b.Decrypt(enc) )
    print( a.Verify(plain, sign) )
