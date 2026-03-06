import io
import Bencrypt
import Opsec

print(Opsec.Crc32(b"test")) # 0c7e7fd8
m = Bencrypt.AsymMaster("rsa1")
pub0, pri0 = m.Genkey()
m = Bencrypt.AsymMaster("rsa2")
pub1, pri1 = m.Genkey()
m = Bencrypt.AsymMaster("ecc1")
pub2, pri2 = m.Genkey()
m = Opsec.Opsec()

# rw
w = io.BytesIO()
w.write(b"\x00" * 128 * 4)
m.Write(w, b"Hello, world!")
r = io.BytesIO(w.getvalue())
print(m.Read(r).decode("utf-8"))

# SHA3
m.Msg, m.Smsg, m.Size, m.Name, m.BodyAlgo, m.ContAlgo = "msg-test", "smsg-test", 1024, "name-test", "gcm1", "zip1"
enc = m.Encpw("sha3", b"password", b"keyfile")
m.View(enc)
m.Decpw(b"password", b"keyfile")
print(m.Msg, m.Smsg, m.Size, m.Name, m.BodyAlgo, m.ContAlgo, len(m.BodyKey))
m.Reset()

# PBKDF2
m.Msg, m.Smsg, m.Size, m.Name, m.BodyAlgo, m.ContAlgo = "msg-test", "smsg-test", 1024, "name-test", "gcm1", "zip1"
enc = m.Encpw("pbk1", b"password", b"keyfile")
m.View(enc)
m.Decpw(b"password", b"keyfile")
print(m.Msg, m.Smsg, m.Size, m.Name, m.BodyAlgo, m.ContAlgo, len(m.BodyKey))
m.Reset()

# Argon2
m.Msg, m.Smsg = "msg-test", "smsg-test"
enc = m.Encpw("arg1", b"password")
m.View(enc)
m.Decpw(b"password")
print(m.Msg, m.Smsg, m.Size, m.Name, m.BodyAlgo, m.ContAlgo, len(m.BodyKey))
m.Reset()

# RSA1
m.Msg, m.Smsg, m.Size, m.Name, m.BodyAlgo, m.ContAlgo = "msg-test", "smsg-test", 1024, "name-test", "gcm1", "zip1"
enc = m.Encpub("rsa1", pub0, pri0)
m.View(enc)
m.Decpub(pri0, pub0)
print(m.Msg, m.Smsg, m.Size, m.Name, m.BodyAlgo, m.ContAlgo, len(m.BodyKey))
m.Reset()

# RSA2
m.Msg, m.Smsg, m.Size, m.Name, m.BodyAlgo, m.ContAlgo = "msg-test", "smsg-test", 1024, "name-test", "gcm1", "zip1"
enc = m.Encpub("rsa2", pub1, pri1)
m.View(enc)
m.Decpub(pri1, pub1)
print(m.Msg, m.Smsg, m.Size, m.Name, m.BodyAlgo, m.ContAlgo, len(m.BodyKey))
m.Reset()

# ECC
m.Msg, m.Smsg = "msg-test", "smsg-test"
enc = m.Encpub("ecc1", pub2, pri2)
m.View(enc)
m.Decpub(pri2, pub2)
print(m.Msg, m.Smsg, m.Size, m.Name, m.BodyAlgo, m.ContAlgo, len(m.BodyKey))
m.Reset()
