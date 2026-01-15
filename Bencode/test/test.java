// javac -encoding UTF-8 Bencode.java test.java
// java -cp . test

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class test {
    public static void main(String[] args) {
        Bencode m = new Bencode();

        String rawText = "안녕하세요, 카투사 프로그래밍 클럽 라이브러리 테스트입니다. Hello, world!";
        byte[] text = rawText.getBytes(StandardCharsets.UTF_8);
        byte[][] data = {
            new byte[]{}, 
            new byte[]{0x00}, 
            new byte[]{0x12, 0x34}, 
            new byte[]{0x3f, (byte)0xff}, 
            new byte[]{(byte)0xff, (byte)0xee, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xdc, (byte)0xff, (byte)0xff}, 
            new byte[]{(byte)0xff, 0x00, 0x00, 0x01, (byte)0xff, 0x00, 0x00, 0x01, 0x10}
        };

        // Base64 test
        String testBase64 = m.encode(text, true);
        byte[] decodedBase64 = m.decode(testBase64);
        System.out.println(testBase64 + " : " + new String(decodedBase64, StandardCharsets.UTF_8));

        // Base32k test
        String testUnicode = m.encode(text, false);
        byte[] decodedUnicode = m.decode(testUnicode);
        System.out.println(testUnicode + " : " + new String(decodedUnicode, StandardCharsets.UTF_8));

        // binary test
        for (byte[] d : data) {
            String encoded = m.encode(d, false);
            byte[] decoded = m.decode(encoded);
            System.out.println(encoded + " : " + Arrays.toString(decoded));
        }
    }
}