import Bencode

text = "안녕하세요, 카투사 프로그래밍 클럽 라이브러리 테스트입니다. Hello, world!".encode('utf-8')
data = [b"", b"\x00", b"\x12\x34", b"\x3f\xff", b"\xff\xee\xff\xff\xff\xdc\xff\xff", b"\xff\x00\x00\x01\xff\x00\x00\x01\x10"]
m = Bencode.Bencode()
test = m.encode(text, True)
print(f"{test} : {m.decode(test).decode('utf-8')}")
test = m.encode(text, False)
print(f"{test} : {m.decode(test).decode('utf-8')}")
for i in range(len(data)):
    test = m.encode(data[i], False)
    print(f"{test} : {m.decode(test)}")


