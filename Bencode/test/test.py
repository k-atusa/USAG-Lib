import Bencode

data = [b"", b"abc", "라이브러리 테스트 코드입니다.".encode("utf-8"), b"ABCD"*64]

for i in data:
    en = Bencode.Encode64(i)
    print(en)
    print(i == Bencode.Decode64(en))

    en = Bencode.Encode64(i, spliter="#", linenum=8, colnum=3)
    print(en)
    print(i == Bencode.Decode64(en, spliter="#"))
