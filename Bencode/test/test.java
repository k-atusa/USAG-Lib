// javac -encoding UTF-8 Bencode.java test.java
// java -cp . test
import java.nio.charset.StandardCharsets;

public class test {
    public static void main(String[] args) {
        String[] data = {"", "abc", "라이브러리 테스트 코드입니다.", "ABCD".repeat(64)};
        for (String i: data) {
            byte[] b = i.getBytes(StandardCharsets.UTF_8);
            String en = Bencode.Encode64(b, null, 0, 0);
            String de = new String(Bencode.Decode64(en, null), StandardCharsets.UTF_8);
            System.out.println(en);
            System.out.println(i.equals(de));
            en = Bencode.Encode64(b, "#", 8, 3);
            de = new String(Bencode.Decode64(en, "#"), StandardCharsets.UTF_8);
            System.out.println(en);
            System.out.println(i.equals(de));
        }
        for (byte i: Bencode.NormPW("한글 테스트")) {
            System.out.print((int)i & 0xFF);
            System.out.print(" ");
        }
    }
}
