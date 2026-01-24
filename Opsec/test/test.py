import Bencrypt
import Opsec

for i in Opsec.crc32(b"test"):
    print(i, end=" ") # 12 126 127 216
print("")
m = Bencrypt.RSA1()
pub0, pri0 = m.genkey(2048)
m = Bencrypt.ECC1()
pub1, pri1 = m.genkey()
m = Opsec.Opsec()

# PBKDF2
m.msg, m.smsg, m.size, m.name, m.bodyAlgo, m.contAlgo = "msg-test", "smsg-test", 1024, "name-test", "gcm1", "zip1"
enc = m.encpw("pbk1", b"password", b"keyfile")
m.view(enc)
m.decpw(b"password", b"keyfile")
print(m.msg, m.headAlgo, m.smsg, m.size, m.name, m.bodyAlgo, m.contAlgo, len(m.bodyKey))
m.reset()

# Argon2
m.msg, m.smsg = "msg-test", "smsg-test"
enc = m.encpw("arg1", b"password")
m.view(enc)
m.decpw(b"password")
print(m.msg, m.headAlgo, m.smsg, m.size, m.name, m.bodyAlgo, m.contAlgo, len(m.bodyKey))
m.reset()

# RSA
m.msg, m.smsg, m.size, m.name, m.bodyAlgo, m.contAlgo = "msg-test", "smsg-test", 1024, "name-test", "gcm1", "zip1"
enc = m.encpub("rsa1", pub0, pri0)
m.view(enc)
m.decpub(pri0, pub0)
print(m.msg, m.headAlgo, m.smsg, m.size, m.name, m.bodyAlgo, m.contAlgo, len(m.bodyKey))
m.reset()

# ECC
m.msg, m.smsg = "msg-test", "smsg-test"
enc = m.encpub("ecc1", pub1, pri1)
m.view(enc)
m.decpub(pri1, pub1)
print(m.msg, m.headAlgo, m.smsg, m.size, m.name, m.bodyAlgo, m.contAlgo, len(m.bodyKey))
m.reset()
