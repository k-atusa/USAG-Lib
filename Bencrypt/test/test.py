import io
import base64
import Bencrypt

pub0 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA36kLQ7+w1kCw1S1b6T1ikSZ5S/m/QX5tPQkiasibLWyKKr113TUIGEn6hjY0mmy8w5WLgiP144ib8/D07OXSyxwv5NYMW8B3BJCgYcj2c5Zr7b3yjwLAI/dWOWof9ZoJpqF/0BrEyYDtdcnV6p5qTYS37EV6SsCCAIa1DT3pnDrT/vn5VbXLFYVqJAdxePvDKkAfAEwKvKDo4Etd7WSN8oXsDOgFCTrW7L5iWwfrlr21tX5FqIG1uKjlrb5kY0omfc2RqZo5a/3LfUEwrRrw/Bj3T7iIg43mmfdeRxEH9KJzEjjeNwzvjBBBd/cg63bpz7KyxnNp3jXGZQ9QAYp6vwIDAQAB'
pri0 = 'MIIEpQIBAAKCAQEA36kLQ7+w1kCw1S1b6T1ikSZ5S/m/QX5tPQkiasibLWyKKr113TUIGEn6hjY0mmy8w5WLgiP144ib8/D07OXSyxwv5NYMW8B3BJCgYcj2c5Zr7b3yjwLAI/dWOWof9ZoJpqF/0BrEyYDtdcnV6p5qTYS37EV6SsCCAIa1DT3pnDrT/vn5VbXLFYVqJAdxePvDKkAfAEwKvKDo4Etd7WSN8oXsDOgFCTrW7L5iWwfrlr21tX5FqIG1uKjlrb5kY0omfc2RqZo5a/3LfUEwrRrw/Bj3T7iIg43mmfdeRxEH9KJzEjjeNwzvjBBBd/cg63bpz7KyxnNp3jXGZQ9QAYp6vwIDAQABAoIBAG3GlCtT/jEivkhbg4WmpebVSeqy8Z7tNSOkhJqBzLxOTkBtDlkc6tS1FrviBg6XeUzL7RXanZjol5bzONu/b6dWNeGs95LfE+uPKtDj6KbR+TZOqSttL65XeyAiCP6sdLkvAkM7qEO4vpQ2FQMbbtSOZBGZBk2DUCt+8oVF0o/lWsRu3mvhm5sh38s3OEVw2XI/+lARF5g0jyzn9uAu0DS3m9E9L9IIOaN6R//l47sKnRM4PynRx+XlcbdksLTvkRJMIJpiovoaV1IzSNBBuSwsu8Sd25T0jQRIkJRAGsUfqqk03ZkM/jFAyugJyeJAFQbmPQvqBXyT2ifj247QXTUCgYEA5Sh4kZrVjEiBzeBM/F0BgGiw/TCxJ7c4WzfdYOXZZhV4fkqE/Qa6WjBPJNAhtXZVtPe2rgKmwAEpVxHCnghnLkNLHj0B5IBP8V7BXmm1hPqwFo5TcBAqgUYuI/ZLDlLQJp2f1G76aIu9IzVxRoSd4LJz/28PDL9Os8gROP6vVGUCgYEA+du3n87mSDGsrOKnQORGQhxT0vwYJEyRpP4njHQ7h+lXjQGGuqR/p3rkZykc6e138m7gKVZZdLbvOSCcNAsVaT/kWKfG9lKqKvVL/axOV7En77HmBeml27RmEZ7oySym0ZBbbqxaFML+82uMP5xfohAFBWa0LmYmMsm0K8D8xlMCgYEAq4bakKpj0+hl+NM+7Ns1B4fViv8Ka57yOR0cwK3rR0Uk9usSlk6V6HImm3iK8sgLqTSN8bwcUrXL2td5ZE8H5JIMRSsHIqGEtTfm56OaclouugN4ovYGytLcMKDnV2ZXVcBAZYNYPi7yuMsE6fLUNd99giIAEtuTrnA/q/i/Bh0CgYEA9+rvtH4TOScw8wqicl0O6aI5+mtxePMQwOn+S/s45o699IfDK4b1szTZVRMSQXsDPWaOvfWUJZ8ulzyoQWuN/zUKWn1/igJUHvPuRvKleZWqzsdyOgOwMuQ5Mtq+mH7Zt67JSnNxnpAtcVMRgjyjF6dVlBpoRnHNDS/eultvdUkCgYEAgykFWG76/DqZSL01/O6cw/6Mvqor0HdrMtOFr8MZnDBxyZpVApQob8k+Y8LSg2xaZCC1Y4GcP6CrlhAaI1jSKJKsHdGmjEFDUTte3zGsq3YKNmbh15VsK2KCBxD9Kd8oIqNweY9Z+WfTytnU4RFKzkxFT5dRsQlx2kDLNP8lbaY='
pub1 = 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBsdsVMpCNOhURl5ZcvIL6tUUtuqljCIvk0w/d0Qoqq4DylyUViCi/nEobWQg/MJRPIiQ8matncdaWNAoxE4XTPF8Bn1Om4HY8fqQvuLChLVF5AzWW7wsLr0tvkN+nz7338HK7uWd3diJMzjXZbjF1nvlwCHZ3BHAiarnygHE33Oj/xFs='
pri1 = 'MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAhiTp7VQaVK20gTMsJDimzcY9SswWOdJJK/AObOdyOkckomcGM+Mx+Af57bv+5hvmO05kFloPDLxTWNVwwY0AqCihgYkDgYYABAGx2xUykI06FRGXlly8gvq1RS26qWMIi+TTD93RCiqrgPKXJRWIKL+cShtZCD8wlE8iJDyZq2dx1pY0CjEThdM8XwGfU6bgdjx+pC+4sKEtUXkDNZbvCwuvS2+Q36fPvffwcru5Z3d2IkzONdluMXWe+XAIdncEcCJqufKAcTfc6P/EWw=='
def p(d: bytes):
    for i in d:
        print(i, end=" ")
    print("====================")

p(Bencrypt.random(16))
p(Bencrypt.sha3256(b""))
p(Bencrypt.sha3512(b""))
p(Bencrypt.pbkdf2(b"0000", b"0000000000000000"))
t = Bencrypt.argon2Hash(b"0000", b"0000000000000000")
print(t)
print(Bencrypt.argon2Verify(t, b"0000"))
p(Bencrypt.genkey(b"0000000000000000", "test", 16))

plain, key = b"Hello, world!" * 4, b"0123" * 11
print( Bencrypt.deAESGCM(key, Bencrypt.enAESGCM(key, plain)).decode() )
plain = b"\x00" * 100000000 # 100MB
r = io.BytesIO(plain)
w = io.BytesIO()
Bencrypt.enAESGCMx(key, r, len(plain), w)
t = w.getvalue()
r = io.BytesIO(t)
w = io.BytesIO()
Bencrypt.deAESGCMx(key, r, len(t), w)
print(w.getvalue() == plain)

you = Bencrypt.RSA1()
you.loadkey(base64.b64decode(pub0), base64.b64decode(pri0))
enc = you.encrypt(b"Hello, world!" * 4)
print(you.decrypt(enc).decode())
me = Bencrypt.RSA1()
me.genkey()
enc = me.sign(b"Hello, world!" * 4)
print(me.verify(b"Hello, world!" * 4, enc))

you = Bencrypt.ECC1()
you.loadkey(base64.b64decode(pub1), base64.b64decode(pri1))
me = Bencrypt.ECC1()
me.genkey()
enc = me.encrypt(b"Hello, world!" * 4, you.public)
print(you.decrypt(enc).decode())
enc = me.sign(b"Hello, world!" * 4)
print(me.verify(b"Hello, world!" * 4, enc))