
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
import java.util.Arrays;

public class test {
    public static void main(String[] args) {
        try {
            // 1. CRC32, Pad Test
            System.out.println(Opsec.Crc32("test".getBytes(StandardCharsets.UTF_8))); // Expected: 0c7e7fd8
            long[] sizes = { 0, 1024, 12 * 1048576, 123456789, 2147483647, 8L * 1073741824L };
            for (long size : sizes) {
                System.out.printf("%d -> %d\n", size, Opsec.PadLen(size) + size);
                if (size < 512 * 1048576) {
                    ByteArrayOutputStream f = new ByteArrayOutputStream();
                    Opsec.PadFile(f, size);
                    System.out.println(f.size() == size);
                }
            }

            // 2. Read/Write Stream Test
            ByteArrayOutputStream w = new ByteArrayOutputStream();
            w.write(new byte[128 * 4]); // b"\x00" * 128 * 4
            Opsec m = new Opsec();
            m.Write(w, "Hello, world!".getBytes(StandardCharsets.UTF_8));

            ByteArrayInputStream r = new ByteArrayInputStream(w.toByteArray());
            byte[] readBack = m.Read(r, 65535);
            System.out.println(new String(readBack, StandardCharsets.UTF_8)); // Expected: Hello, world!

            // test parameters
            String msg = "msg-test";
            String smsg = "smsg-test";
            byte[] sinf = "sinf-test".getBytes(StandardCharsets.UTF_8);
            String bodyalgo = "gcmx1";
            long bodysize = 1048576;
            byte[] bodyinfo = "binf-test".getBytes(StandardCharsets.UTF_8);

            // 3. pw-mode (sha3, pbk2, arg2)
            String[] pwMethods = { "sha3", "pbk2", "arg2" };
            for (String method : pwMethods) {
                m.Reset();
                m.Msg = msg;
                m.Smsg = smsg;
                m.SmsgInfo = sinf;
                m.BodyAlgo = bodyalgo;
                m.BodySize = bodysize;
                m.BodyInfo = bodyinfo;

                byte[] enc = m.Encpw(method, "password".getBytes(StandardCharsets.UTF_8),
                        "keyfile".getBytes(StandardCharsets.UTF_8));
                byte[] bodykey = m.BodyKey.clone(); // get BodyKey

                m.View(enc);
                m.Decpw("password".getBytes(StandardCharsets.UTF_8), "keyfile".getBytes(StandardCharsets.UTF_8));

                System.out.println(method);
                boolean b1 = msg.equals(m.Msg);
                boolean b2 = smsg.equals(m.Smsg);
                boolean b3 = Arrays.equals(sinf, m.SmsgInfo);
                boolean b4 = bodyalgo.equals(m.BodyAlgo);
                boolean b5 = (bodysize == m.BodySize);
                boolean b6 = Arrays.equals(bodyinfo, m.BodyInfo);
                boolean b7 = Arrays.equals(bodykey, m.BodyKey);

                System.out.printf("%s %s %s %s %s %s %s\n",
                        b1 ? "OK" : "FAIL", b2 ? "OK" : "FAIL", b3 ? "OK" : "FAIL",
                        b4 ? "OK" : "FAIL", b5 ? "OK" : "FAIL", b6 ? "OK" : "FAIL", b7 ? "OK" : "FAIL");
            }

            // 4. pub-mode (rsa1, rsa2, ecc1, pqc1)
            String[] pubMethods = { "rsa1", "rsa2", "ecc1", "pqc1" };
            for (String method : pubMethods) {
                Bencrypt.AsymMaster me = new Bencrypt.AsymMaster(method);
                byte[][] meKeys = me.Genkey();
                byte[] myPub = meKeys[0];
                byte[] myPri = meKeys[1];

                Bencrypt.AsymMaster peer = new Bencrypt.AsymMaster(method);
                byte[][] peerKeys = peer.Genkey();
                byte[] peerPub = peerKeys[0];
                byte[] peerPri = peerKeys[1];

                m.Reset();
                m.Msg = msg;
                m.Smsg = smsg;
                m.SmsgInfo = sinf;
                m.BodyAlgo = bodyalgo;
                m.BodySize = bodysize;
                m.BodyInfo = bodyinfo;

                // peer -> me
                byte[] enc = m.Encpub(method, myPub, peerPri);
                byte[] bodykey = m.BodyKey.clone();

                m.View(enc);
                m.Decpub(myPri, myPub, peerPub);

                System.out.println(method);
                boolean b1 = msg.equals(m.Msg);
                boolean b2 = smsg.equals(m.Smsg);
                boolean b3 = Arrays.equals(sinf, m.SmsgInfo);
                boolean b4 = bodyalgo.equals(m.BodyAlgo);
                boolean b5 = (bodysize == m.BodySize);
                boolean b6 = Arrays.equals(bodyinfo, m.BodyInfo);
                boolean b7 = Arrays.equals(bodykey, m.BodyKey);

                System.out.printf("%s %s %s %s %s %s %s\n",
                        b1 ? "OK" : "FAIL", b2 ? "OK" : "FAIL", b3 ? "OK" : "FAIL",
                        b4 ? "OK" : "FAIL", b5 ? "OK" : "FAIL", b6 ? "OK" : "FAIL", b7 ? "OK" : "FAIL");
            }

            // 5. Masker Test
            System.out.println("\n--- Masker Test ---");
            Opsec.Masker mA = Opsec.Masker.GetMasker();
            Opsec.Masker mB = Opsec.Masker.GetMasker();
            Bencrypt rg = new Bencrypt();
            byte[] key = rg.Random(8753);
            byte[] maskedZero = mA.XOR(new byte[] { 0, 0, 0, 0 });
            StringBuilder hexZero = new StringBuilder();
            for (byte b : maskedZero) {
                hexZero.append(String.format("%02x", b));
            }
            System.out.println(hexZero.toString());
            byte[] restoredKey = mB.XOR(mA.XOR(key));
            System.out.println(Arrays.equals(restoredKey, key) ? "True" : "False");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}