import io
import Bencrypt
import Opsec

# CRC32, Pad, RW
print(Opsec.Crc32(b"test")) # 0c7e7fd8
for size in [0, 1024, 12 * 1048576, 123456789, 2147483647, 8 * 1073741824]:
    print(size, Opsec.PadLen(size) + size)
w = io.BytesIO()
w.write(b"\x00" * 128 * 4)
m = Opsec.Opsec()
m.Write(w, b"Hello, world!")
r = io.BytesIO(w.getvalue())
print(m.Read(r).decode("utf-8"))

# test parameters
msg = "msg-test"
smsg = "smsg-test"
sinf = b"sinf-test"
bodyalgo = "gcmx1"
bodysize = 1048576
bodyinfo = b"binf-test"

# pw-mode
methods = ["sha3", "pbk2", "arg2"]
for method in methods:
    m.Reset()
    m.Msg, m.Smsg, m.SmsgInfo, m.BodyAlgo, m.BodySize, m.BodyInfo = msg, smsg, sinf, bodyalgo, bodysize, bodyinfo
    enc = m.Encpw(method, b"password", b"keyfile")
    bodykey = m.BodyKey # get generated BodyKey
    m.View(enc)
    m.Decpw(b"password", b"keyfile")
    print(method)
    print(msg == m.Msg, smsg == m.Smsg, sinf == m.SmsgInfo, bodyalgo == m.BodyAlgo, bodysize == m.BodySize, bodyinfo == m.BodyInfo, bodykey == m.BodyKey)

# pub-mode (from peer to me)
methods = ["rsa1", "rsa2", "ecc1", "pqc1"]
for method in methods:
    me = Bencrypt.AsymMaster(method)
    myPub, myPri = me.Genkey()
    peer = Bencrypt.AsymMaster(method)
    peerPub, peerPri = peer.Genkey()

    m.Reset()
    m.Msg, m.Smsg, m.SmsgInfo, m.BodyAlgo, m.BodySize, m.BodyInfo = msg, smsg, sinf, bodyalgo, bodysize, bodyinfo
    enc = m.Encpub(method, myPub, peerPri)
    bodykey = m.BodyKey # get generated BodyKey
    m.View(enc)
    m.Decpub(myPri, myPub, peerPub)
    print(method)
    print(msg == m.Msg, smsg == m.Smsg, sinf == m.SmsgInfo, bodyalgo == m.BodyAlgo, bodysize == m.BodySize, bodyinfo == m.BodyInfo, bodykey == m.BodyKey)
