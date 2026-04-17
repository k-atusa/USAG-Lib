/*
* structure:
*   lib/bclib.jar, Bencrypt.java, test.java
* windows:
*   javac -cp ".;lib/*" Bencrypt.java test.java
*   java -cp ".;lib/*" test
* mac/linux:
*   javac -cp ".:lib/*" Bencrypt.java test.java
*   java -cp ".:lib/*" test
*/
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class test {
    public static byte[] repeat(byte[] data, int times) {
        byte[] out = new byte[data.length * times];
        for (int i = 0; i < times; i++) {
            System.arraycopy(data, 0, out, i * data.length, data.length);
        }
        return out;
    }

    public static void main(String[] args) {
        try {
            // load testsheet.txt
            List<String> lines = Files.readAllLines(Paths.get("testsheet.txt"));
            List<byte[]> sheet = new ArrayList<>();
            for (String line : lines) {
                if (!line.trim().isEmpty()) {
                    sheet.add(Base64.getDecoder().decode(line));
                }
            }
            int pos = 0;

            // basic function test
            System.out.println("testing basic functions...");
            Bencrypt bc = new Bencrypt();
            byte[] data0 = "0000".getBytes(StandardCharsets.UTF_8);
            System.out.println(Base64.getEncoder().encodeToString(bc.Random(16)));
            System.out.println(Base64.getEncoder().encodeToString(Bencrypt.SHA3256(data0))); // pq9wt68/QjUteD6LB1FeQzw9RWadTv7mcFFnJxk7KRs=
            System.out.println(Base64.getEncoder().encodeToString(Bencrypt.SHA3512(data0))); // tnjOmGIvYntbNcoej2VvG9M1RdJCtZ8BWjHek4r6OvvmhThbjjzJ/zfYwq+G7r/TGe7WWr20vkGBzULuTzcPYQ==

            // HashMaster (pw_store, keygen)
            System.out.println("testing HashMaster...");
            String[] hashm = {"sha3", "pbk2", "arg2"};
            byte[] pw = "ABCDABCDABCDABCD".getBytes(StandardCharsets.UTF_8);
            byte[] salt = "1234123412341234".getBytes(StandardCharsets.UTF_8);
            
            for (String algo : hashm) {
                Bencrypt.HashMaster w = new Bencrypt.HashMaster(algo);
                byte[][] res = w.KDF(pw, salt);
                System.out.println(Arrays.equals(sheet.get(pos++), res[0]) ? "True" : "False");
                System.out.println(Arrays.equals(sheet.get(pos++), res[1]) ? "True" : "False");
            }

            // SymMaster (enbin, enfile)
            System.out.println("testing SymMaster...");
            String[] symm = {"gcm1", "gcmx1"};
            byte[] key = repeat("0".getBytes(StandardCharsets.UTF_8), 44);
            byte[] plain = repeat("Hello, world!".getBytes(StandardCharsets.UTF_8), 32);
            
            for (String algo : symm) {
                Bencrypt.SymMaster w = new Bencrypt.SymMaster(algo, key);
                
                System.out.println(Arrays.equals(plain, w.DeBin(sheet.get(pos++))) ? "True" : "False");
                
                ByteArrayOutputStream tempOut = new ByteArrayOutputStream();
                w.DeFile(new ByteArrayInputStream(sheet.get(pos)), sheet.get(pos).length, tempOut);
                System.out.println(Arrays.equals(plain, tempOut.toByteArray()) ? "True" : "False");
                pos++;

                byte[] bigdata = new byte[10000000]; // 10MB (all 0x00 by default)
                byte[] bigenc = w.EnBin(bigdata);
                System.out.println(Arrays.equals(bigdata, w.DeBin(bigenc)) ? "True" : "False");
                
                tempOut = new ByteArrayOutputStream();
                w.EnFile(new ByteArrayInputStream(bigdata), bigdata.length, tempOut);
                bigenc = tempOut.toByteArray();
                
                tempOut = new ByteArrayOutputStream();
                w.DeFile(new ByteArrayInputStream(bigenc), bigenc.length, tempOut);
                System.out.println(Arrays.equals(bigdata, tempOut.toByteArray()) ? "True" : "False");
            }

            // AsymMaster (pubkey, prikey, enc, sign)
            System.out.println("testing AsymMaster...");
            String[] asymm = {"rsa1", "rsa2", "ecc1", "pqc1"};
            byte[] plainAsym = "Hello, world!".getBytes(StandardCharsets.UTF_8);
            
            for (String algo : asymm) {
                Bencrypt.AsymMaster w = new Bencrypt.AsymMaster(algo);
                byte[] pub = sheet.get(pos++);
                byte[] pri = sheet.get(pos++);
                w.Loadkey(pub, pri);
                
                byte[] enc = sheet.get(pos++);
                byte[] sign = sheet.get(pos++);
                
                System.out.println(Arrays.equals(plainAsym, w.Decrypt(enc)) ? "True" : "False");
                System.out.println(w.Verify(plainAsym, sign) ? "True" : "False");

                Bencrypt.AsymMaster tempAsym = new Bencrypt.AsymMaster(algo);
                byte[][] keypair = tempAsym.Genkey();
                
                Bencrypt.AsymMaster a = new Bencrypt.AsymMaster(algo);
                Bencrypt.AsymMaster b = new Bencrypt.AsymMaster(algo);
                a.Loadkey(keypair[0], null);
                b.Loadkey(null, keypair[1]);
                
                byte[] newEnc = a.Encrypt(plainAsym);
                byte[] newSign = b.Sign(plainAsym);
                
                System.out.println(Arrays.equals(plainAsym, b.Decrypt(newEnc)) ? "True" : "False");
                System.out.println(a.Verify(plainAsym, newSign) ? "True" : "False");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}