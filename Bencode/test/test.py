import Bencode

print(Bencode.Decode64(Bencode.Encode64(b"")))
print(Bencode.Decode64(Bencode.Encode64(b"abc")))
print(Bencode.Decode64(Bencode.Encode64("라이브러리 테스트 코드입니다.".encode("utf-8"))).decode("utf-8"))