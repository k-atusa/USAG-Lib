import io
import base64
import Bencrypt

result = [ ]

# HashMaster (pw_store, keygen)
hashm = ["sha3", "arg2low", "arg2st"]
pw, salt = b"ABCDABCDABCDABCD", b"1234123412341234"
for algo in hashm:
    w = Bencrypt.HashMaster(algo)
    pwst, keygen = w.KDF(pw, salt)
    result.append(pwst)
    result.append(keygen)

# SymMaster (enbin, enfile)
symm = ["gcm1", "gcmx1"]
key = b"0" * 32
plain = b"Hello, world!" * 32
for algo in symm:
    w = Bencrypt.SymMaster(algo, key)
    result.append( w.EnBin(plain) )
    temp = io.BytesIO()
    w.EnFile(io.BytesIO(plain), len(plain), temp)
    result.append( temp.getvalue() )

# AsymMaster (pubkey, prikey, enc, sign)
asymm = ["ecc1", "pqc1"]
plain = b"Hello, world!"
for algo in asymm:
    w = Bencrypt.AsymMaster(algo)
    pub, pri = w.Genkey()
    enc = w.Encrypt(plain)
    sign = w.Sign(plain)
    result = result + [pub, pri, enc, sign]

with open("testsheet.txt", "w") as f:
    f.write( "\n".join( [base64.b64encode(b).decode('ascii') for b in result] ) )
    
