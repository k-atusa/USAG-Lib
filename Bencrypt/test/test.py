import io
import base64
import Bencrypt

pub0 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApCITGWNQcB8GdwWFpKW02VVYdtir1/IAbUstmwhBugo2rbdi1a/7n/hafglvwV+kxQ4jJychYjl921OhPwqlaFv/+iP8sDemmjXKW5G9QtSGFx34FVLYGewrF1ApoyvI5Zi3m7KBhrAFQyZ+6VYojnx0NJPjnCOGwSx8rb73Csi+gBoxSse5EUUwywWJ9tQkQfayFY7bVAORje7y58rrk4ASwpGNnaXgsNQffCgtBf6J4XhXm/neZP7wpDJqx6j4c5JY0OnYnCIkU66RMgEn4jHc+hg9Hfr99AWBnxjuMrAUbsaDrHrAcl5Sxhi0xzlxFvT+/PFx0BzPSt/noM0C1wIDAQAB'
pri0 = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkIhMZY1BwHwZ3BYWkpbTZVVh22KvX8gBtSy2bCEG6Cjatt2LVr/uf+Fp+CW/BX6TFDiMnJyFiOX3bU6E/CqVoW//6I/ywN6aaNcpbkb1C1IYXHfgVUtgZ7CsXUCmjK8jlmLebsoGGsAVDJn7pViiOfHQ0k+OcI4bBLHytvvcKyL6AGjFKx7kRRTDLBYn21CRB9rIVjttUA5GN7vLnyuuTgBLCkY2dpeCw1B98KC0F/onheFeb+d5k/vCkMmrHqPhzkljQ6dicIiRTrpEyASfiMdz6GD0d+v30BYGfGO4ysBRuxoOsesByXlLGGLTHOXEW9P788XHQHM9K3+egzQLXAgMBAAECggEAAOL2O3Lf4lsoi8gJ2sPSYEInwiyVcQsrmWuIiYfX4wtfFD0jWYgj0c9jnb6rTd4YY8AZzIJXmdI5rc+b1V1XW2Lz1QQQv1rtmXOk7i2xWgUP3FwbFPJnnGw8J1oVf34jDapvg3XJYVLeFGjG0rfWbD6b2hTaa+N9PNniqoWXjAVbWp2yJ0emN2nyFF/jhXIKJHmJZFAe4DFp/vHLykxHKOtMxsoHikjRj3KnpPy2NQzZue8jQ6UvX1zZhucR9tJb+9kVq9nLVxKVinSvaq8hLavtEh74o0ykQzxr4bT+eeX+6Jm0vON7VCH+HmeKdrACnsZ5tKd4oCA+2EXw2cPPMQKBgQDELGPJHQH0SxSjOyaXkKoSf2jvxYCQiay6Y+qT6lnL7Ag9MtOOGLARezaV8fYRBwTYdIUKCJj8jZtzTJVmg30t1qyy1jTkzwlq36cWxzToaQPYZVULuHOWMyMcUPdgLk+kslVxN7ZyhpDxdatAcnr4HphAsD20F+Dk0ZJASDU0kwKBgQDWMD3OKZOC661NsSjI7+INDIxov8aP/MBJKirj+/I9KU4cXfvzuMS/G20EvI9Bxc294Aghnp/I25Eg9NTL8AzWCJlXM4AF+fzM8yR/NlW/nfxOT07wHbvKMTQHM3bBcIKQkg3BCCIomGf0jWthXRROdWaFE3G7HksfnOS0k2pHLQKBgQC/2d24yKqpnGfRfz6tyafaMUqR+2hRcqM/Igo+oFkzamFgYH2vIQvH/OUUXa7VVjTx73pQprnffCnD5+jQedWJZ8I7n+vYvXWrVJEXYLiodlNxZSB4NuqrwNUckz5qjMANBO80q1S9ykakLfzOKWeDkoA5+2JM53FktmQ+g5+tCwKBgFnjhQywhie7oM+qOeOaSNQRIBwV388t08Tg3X8wjUj9vLpK9yIhuPA7IlWKjNSdnurAyqjRWV2CSDX8ihHMfJaWpUPjaScY8u9QW1DIDNSOCQUUY5yB3f3NCHi9MGmePi1OHleUgkFnNLl9YENMPOlwe8X9kw1keUKbJaBi/YdBAoGAWQ+zica3FnZI5oTEv44qh/S0hbjHjo3AhST+5VTOx7pitwySI8gC2u1af5fHJskBEwQKhkvOt1n7eh88aLo3b7HHB4QIur+KFrKmUvBHIa3Y2FQOTsBQj1Cj9hMTWBErqEb/+/D9n5PlH7zt5MVwZTA8HAGUpVhIR3xxUtpTiJI='
enc0 = 'nCFhvHbvIbAYlk8MpjVd5hmQHrbm3kVc/heznSujIV4xsofvYpxUntktOppBDHMlxoqDSS8KKOw7uC6mnzPjjNAzGY4UWBvakegqEsWVSfiGouh8sNJyMyx5dsc8dk4j2IDe8gNqE/l04cddtrfVSgRle82FJOKvSNyAfI0bJPooj1WJJIXa+LdEiP5EY8y7ccIP+2T5rTqHUHNkjzlUGZOr+6Mkj6eVgfJKhtKhw3tt7tLM/HF8NbBNPRSGO8cHEVuHMke0JLaRHc68qpE3vKT/GCxveJC5L7T5wxiX9KOwB6zr9fWaVxfTiEDGU4IdUZgyeZOAEXY9V19uFExLAw=='
sign0 = 'WagxpWpmGUK2vtx1Vjf1Bn67FHwdNy5co9uMV2SV9ZI6KCOYl/QWfA5oF9qIhb58lY00RVzUE+GiqQozGuAE9KIK70icBlWB1bq5azcBbR1sRDycLldT8HZPTyDdnW+pC/D0lvAWA99xVNSk5mEaJn1FKPbCAJwTrJZY5UQTF0XM8vWFUW2JQtlYLVQgcpALY6HYgOVSaXAaAEifftOurRBncn7BAudwIIv4OL5kBbXciEDlHO5aHDC3I0GG3zVhKA0BousFC2V+fiLYfH73i7K1rXIb5uhopSKhi82tRgII9rxWACwV3n3fOTSaNWvGHwZKIXvQChpRQHcBFomZcg=='
pub1 = '8Gjuhn7QRfAUkKEswjJXCxP+znZnp2oO8mZFHOaHs+0eHb9CnyC6JfScgAMBZB/dGY695aIHu/iY4CNGMcshZ1AxZzPs45kaCb2ZbJIAXM2VuNwdUJG3gmCYqAbRFNJSWTKZu2mFuJW/SiDLccf48YA='
pri1 = '7CLpb2gjTtPzLhAgEcPx2WBeuTDo1K3PGKG891IlmWzCARYbBm/pGQoG5szSqyf/0kGfYc38zOCFJM1kpZ7kKUi1jdqCUUKHXqTW9gr3ppRHQkrjlE0h2k29jrRbBxPfSgILf82roc417N3krf5JiXA='
enc1 = 'OENn7kZfuSIzkrtcAy+qUGM9no4Ra8Wd7HCIY66OOfBTcETHNBkHftaMdZfWTMHj3UkUbtRQpwIoCBYHE8fygKJE9oRtAhMM2cbMBmY='
sign1 = 'eZGi/aYQQKnR8LXtgIcaPWq+rYnq/MYpyrbJ+vjyVR83iL3eX3D3sFvTJ0SCRe5dJMoUBXxW+tAASLxmf0KHs2AeGUeo/IWLOrbwmQhxqegKmzJuOrnw7nMSv6BamvKD3/BkDKaoQiFDCq25E2nlDCIA'
def p(d: bytes):
    for i in d:
        print(i, end=" ")
    print("====================")

print("\n===== basic test =====")
p(Bencrypt.Random(16))
p(Bencrypt.SHA3256(b""))
p(Bencrypt.SHA3512(b""))

print("\n===== basic-adv test =====")
p(Bencrypt.pbkdf2(b"0000", b"0000000000000000"))
t = Bencrypt.argon2Hash(b"0000", b"0000000000000000")
print(t)
print(Bencrypt.argon2Verify(t, b"0000"))
p(Bencrypt.genkey(b"0000000000000000", "test", 16))

print("\n===== sym-gcm1 test =====")
plain, key = b"Hello, world!" * 4, b"0123" * 11
m = Bencrypt.SymMaster("gcm1", key)
print(m.DeBin(m.EnBin(plain)), m.Processed())
plain = b"\x00" * 100000000 # 100MB
r, w = io.BytesIO(plain), io.BytesIO()
m.EnFile(r, len(plain), w)
t = w.getvalue()
r, w = io.BytesIO(t), io.BytesIO()
m.DeFile(r, len(t), w)
print(w.getvalue() == plain, m.Processed())

print("\n===== sym-gcmx1 test =====")
plain, key = b"Hello, world!" * 4, b"0123" * 11
m = Bencrypt.SymMaster("gcmx1", key)
print(m.DeBin(m.EnBin(plain)), m.Processed())
plain = b"\x00" * 100000000 # 100MB
r, w = io.BytesIO(plain), io.BytesIO()
m.EnFile(r, len(plain), w)
t = w.getvalue()
r, w = io.BytesIO(t), io.BytesIO()
m.DeFile(r, len(t), w)
print(w.getvalue() == plain, m.Processed())

# test various sizes
print("\n===== sym-vsizes test =====")
m1, m2 = Bencrypt.SymMaster("gcm1", key), Bencrypt.SymMaster("gcmx1", key)
print(m1.DeBin(m1.EnBin(b"")) == b"")
r, w = io.BytesIO(b""), io.BytesIO()
m2.EnFile(r, 0, w)
t = w.getvalue()
r, w = io.BytesIO(t), io.BytesIO()
m2.DeFile(r, len(t), w)
print(w.getvalue() == b"")
r, w = io.BytesIO(b""), io.BytesIO()
m2.EnFile(r, 0, w)
t = w.getvalue()
r, w = io.BytesIO(t), io.BytesIO()
m2.DeFile(r, len(t), w)
print(w.getvalue() == b"")
r, w = io.BytesIO(b"\x00" * 1048576 * 4), io.BytesIO()
m2.EnFile(r, 1048576 * 4, w)
t = w.getvalue()
r, w = io.BytesIO(t), io.BytesIO()
m2.DeFile(r, len(t), w)
print(w.getvalue() == b"\x00" * 1048576 * 4)

print("\n===== asym-rsa test =====")
me = Bencrypt.AsymMaster("rsa1")
me.Genkey()
enc = me.Encrypt(b"Hello, world!" * 4)
print(me.Decrypt(enc).decode())
enc = me.Sign(b"Hello, world!" * 4)
print(me.Verify(b"Hello, world!" * 4, enc))

you = Bencrypt.AsymMaster("rsa1")
you.Loadkey(base64.b64decode(pub0), base64.b64decode(pri0))
p( you.Decrypt(base64.b64decode(enc0)) )
print( you.Verify(b"0000", base64.b64decode(sign0)) )

print("\n===== asym-ecc test =====")
me = Bencrypt.AsymMaster("ecc1")
me.Genkey()
enc = me.Encrypt(b"Hello, world!" * 4)
print(me.Decrypt(enc).decode())
enc = me.Sign(b"Hello, world!" * 4)
print(me.Verify(b"Hello, world!" * 4, enc))

you = Bencrypt.AsymMaster("ecc1")
you.Loadkey(base64.b64decode(pub1), base64.b64decode(pri1))
p( you.Decrypt(base64.b64decode(enc1)) )
print( you.Verify(b"0000", base64.b64decode(sign1)) )
