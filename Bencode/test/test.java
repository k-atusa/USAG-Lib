// javac -encoding UTF-8 Bencode.java test.java
// java -cp . test
import java.nio.charset.StandardCharsets;

public class test {
    public static void main(String[] args) {
        byte[] t0 = "".getBytes(StandardCharsets.UTF_8);
        byte[] t1 = "abc".getBytes(StandardCharsets.UTF_8);
        byte[] t2 = "라이브러리 테스트 코드입니다.".getBytes(StandardCharsets.UTF_8);
        System.out.println(new String(Bencode.Decode64(Bencode.Encode64(t0)), StandardCharsets.UTF_8));
        System.out.println(new String(Bencode.Decode64(Bencode.Encode64(t1)), StandardCharsets.UTF_8));
        System.out.println(new String(Bencode.Decode64(Bencode.Encode64(t2)), StandardCharsets.UTF_8));
    }
}
