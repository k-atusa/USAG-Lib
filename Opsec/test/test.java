/*
structure:
  lib/bclib.jar
  Bencrypt.java
  Opsec.java
  test.java
windows:
  javac -cp ".;lib/*" Bencrypt.java Opsec.java test.java
  java -cp ".;lib/*" test
mac/linux:
  javac -cp ".:lib/*" Bencrypt.java Opsec.java test.java
  java -cp ".:lib/*" test
*/

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

public class test {
    public static void main(String[] args) {
        try {
            // 1. CRC32 Test
            byte[] crc = Opsec.crc32("test".getBytes(StandardCharsets.UTF_8));
            for (byte b : crc) {
                System.out.print(Byte.toUnsignedInt(b) + " ");
            }
            System.out.println(); // Expected output: 12 126 127 216

            // 2. Key Generation
            Bencrypt b = new Bencrypt();
            byte[][] rsaKeys = b.RSAgenkey(2048);
            byte[] pub0 = rsaKeys[0];
            byte[] pri0 = rsaKeys[1];
            byte[][] eccKeys = b.ECCgenkey();
            byte[] pub1 = eccKeys[0];
            byte[] pri1 = eccKeys[1];
            Opsec m = new Opsec();

            // 3. Read/Write Test
            ByteArrayOutputStream w = new ByteArrayOutputStream();
            w.write(new byte[128 * 4]); 
            m.write(w, "Hello, world!".getBytes(StandardCharsets.UTF_8));
            ByteArrayInputStream r = new ByteArrayInputStream(w.toByteArray());
            byte[] readBack = m.read(r, 65535);
            System.out.println(new String(readBack, StandardCharsets.UTF_8)); // Expected: Hello, world!

            // 4. PBKDF2 Test
            m.msg = "msg-test";
            m.smsg = "smsg-test";
            m.size = 1024;
            m.name = "name-test";
            m.bodyAlgo = "gcm1";
            m.contAlgo = "zip1";

            byte[] encPbk = m.encpw("pbk1", "password".getBytes(StandardCharsets.UTF_8), "keyfile".getBytes(StandardCharsets.UTF_8));
            m.view(encPbk);
            m.decpw("password".getBytes(StandardCharsets.UTF_8), "keyfile".getBytes(StandardCharsets.UTF_8));
            printStatus(m);
            m.reset();

            // 5. Argon2 Test
            m.msg = "msg-test";
            m.smsg = "smsg-test";

            byte[] encArg = m.encpw("arg1", "password".getBytes(StandardCharsets.UTF_8), null);
            m.view(encArg);
            m.decpw("password".getBytes(StandardCharsets.UTF_8), null);
            printStatus(m);
            m.reset();

            // 56. RSA Test
            m.msg = "msg-test";
            m.smsg = "smsg-test";
            m.size = 1024;
            m.name = "name-test";
            m.bodyAlgo = "gcm1";
            m.contAlgo = "zip1";

            byte[] encRSA = m.encpub("rsa1", pub0, pri0);
            m.view(encRSA);
            m.decpub(pri0, pub0);
            printStatus(m);
            m.reset();

            // 7. ECC Test
            m.msg = "msg-test";
            m.smsg = "smsg-test";

            byte[] encECC = m.encpub("ecc1", pub1, pri1);
            m.view(encECC);
            m.decpub(pri1, pub1);
            printStatus(m);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Helper to print object status
    private static void printStatus(Opsec m) {
        System.out.println(
            m.msg + " " +
            m.headAlgo + " " +
            m.smsg + " " +
            m.size + " " +
            m.name + " " +
            m.bodyAlgo + " " +
            m.contAlgo + " " +
            m.bodyKey.length
        );
    }
}