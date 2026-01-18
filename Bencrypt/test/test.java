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
import java.util.Base64;
import java.util.Arrays;

public class test {
    // Hardcoded Keys from Python test.py
    static String pub0 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApCITGWNQcB8GdwWFpKW02VVYdtir1/IAbUstmwhBugo2rbdi1a/7n/hafglvwV+kxQ4jJychYjl921OhPwqlaFv/+iP8sDemmjXKW5G9QtSGFx34FVLYGewrF1ApoyvI5Zi3m7KBhrAFQyZ+6VYojnx0NJPjnCOGwSx8rb73Csi+gBoxSse5EUUwywWJ9tQkQfayFY7bVAORje7y58rrk4ASwpGNnaXgsNQffCgtBf6J4XhXm/neZP7wpDJqx6j4c5JY0OnYnCIkU66RMgEn4jHc+hg9Hfr99AWBnxjuMrAUbsaDrHrAcl5Sxhi0xzlxFvT+/PFx0BzPSt/noM0C1wIDAQAB";
    static String pri0 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkIhMZY1BwHwZ3BYWkpbTZVVh22KvX8gBtSy2bCEG6Cjatt2LVr/uf+Fp+CW/BX6TFDiMnJyFiOX3bU6E/CqVoW//6I/ywN6aaNcpbkb1C1IYXHfgVUtgZ7CsXUCmjK8jlmLebsoGGsAVDJn7pViiOfHQ0k+OcI4bBLHytvvcKyL6AGjFKx7kRRTDLBYn21CRB9rIVjttUA5GN7vLnyuuTgBLCkY2dpeCw1B98KC0F/onheFeb+d5k/vCkMmrHqPhzkljQ6dicIiRTrpEyASfiMdz6GD0d+v30BYGfGO4ysBRuxoOsesByXlLGGLTHOXEW9P788XHQHM9K3+egzQLXAgMBAAECggEAAOL2O3Lf4lsoi8gJ2sPSYEInwiyVcQsrmWuIiYfX4wtfFD0jWYgj0c9jnb6rTd4YY8AZzIJXmdI5rc+b1V1XW2Lz1QQQv1rtmXOk7i2xWgUP3FwbFPJnnGw8J1oVf34jDapvg3XJYVLeFGjG0rfWbD6b2hTaa+N9PNniqoWXjAVbWp2yJ0emN2nyFF/jhXIKJHmJZFAe4DFp/vHLykxHKOtMxsoHikjRj3KnpPy2NQzZue8jQ6UvX1zZhucR9tJb+9kVq9nLVxKVinSvaq8hLavtEh74o0ykQzxr4bT+eeX+6Jm0vON7VCH+HmeKdrACnsZ5tKd4oCA+2EXw2cPPMQKBgQDELGPJHQH0SxSjOyaXkKoSf2jvxYCQiay6Y+qT6lnL7Ag9MtOOGLARezaV8fYRBwTYdIUKCJj8jZtzTJVmg30t1qyy1jTkzwlq36cWxzToaQPYZVULuHOWMyMcUPdgLk+kslVxN7ZyhpDxdatAcnr4HphAsD20F+Dk0ZJASDU0kwKBgQDWMD3OKZOC661NsSjI7+INDIxov8aP/MBJKirj+/I9KU4cXfvzuMS/G20EvI9Bxc294Aghnp/I25Eg9NTL8AzWCJlXM4AF+fzM8yR/NlW/nfxOT07wHbvKMTQHM3bBcIKQkg3BCCIomGf0jWthXRROdWaFE3G7HksfnOS0k2pHLQKBgQC/2d24yKqpnGfRfz6tyafaMUqR+2hRcqM/Igo+oFkzamFgYH2vIQvH/OUUXa7VVjTx73pQprnffCnD5+jQedWJZ8I7n+vYvXWrVJEXYLiodlNxZSB4NuqrwNUckz5qjMANBO80q1S9ykakLfzOKWeDkoA5+2JM53FktmQ+g5+tCwKBgFnjhQywhie7oM+qOeOaSNQRIBwV388t08Tg3X8wjUj9vLpK9yIhuPA7IlWKjNSdnurAyqjRWV2CSDX8ihHMfJaWpUPjaScY8u9QW1DIDNSOCQUUY5yB3f3NCHi9MGmePi1OHleUgkFnNLl9YENMPOlwe8X9kw1keUKbJaBi/YdBAoGAWQ+zica3FnZI5oTEv44qh/S0hbjHjo3AhST+5VTOx7pitwySI8gC2u1af5fHJskBEwQKhkvOt1n7eh88aLo3b7HHB4QIur+KFrKmUvBHIa3Y2FQOTsBQj1Cj9hMTWBErqEb/+/D9n5PlH7zt5MVwZTA8HAGUpVhIR3xxUtpTiJI=";
    static String enc0 = "nCFhvHbvIbAYlk8MpjVd5hmQHrbm3kVc/heznSujIV4xsofvYpxUntktOppBDHMlxoqDSS8KKOw7uC6mnzPjjNAzGY4UWBvakegqEsWVSfiGouh8sNJyMyx5dsc8dk4j2IDe8gNqE/l04cddtrfVSgRle82FJOKvSNyAfI0bJPooj1WJJIXa+LdEiP5EY8y7ccIP+2T5rTqHUHNkjzlUGZOr+6Mkj6eVgfJKhtKhw3tt7tLM/HF8NbBNPRSGO8cHEVuHMke0JLaRHc68qpE3vKT/GCxveJC5L7T5wxiX9KOwB6zr9fWaVxfTiEDGU4IdUZgyeZOAEXY9V19uFExLAw==";
    static String sign0 = "WagxpWpmGUK2vtx1Vjf1Bn67FHwdNy5co9uMV2SV9ZI6KCOYl/QWfA5oF9qIhb58lY00RVzUE+GiqQozGuAE9KIK70icBlWB1bq5azcBbR1sRDycLldT8HZPTyDdnW+pC/D0lvAWA99xVNSk5mEaJn1FKPbCAJwTrJZY5UQTF0XM8vWFUW2JQtlYLVQgcpALY6HYgOVSaXAaAEifftOurRBncn7BAudwIIv4OL5kBbXciEDlHO5aHDC3I0GG3zVhKA0BousFC2V+fiLYfH73i7K1rXIb5uhopSKhi82tRgII9rxWACwV3n3fOTSaNWvGHwZKIXvQChpRQHcBFomZcg==";
    static String pub1 = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB4/7rJ6fahchEz7zMxDwiTuBV3LiuBDbBBh2dY9/xFe9m+3YjZysS68lR+YM4FBtG3iv+wCqTJIcLimN2srN1m60BBJsaX07gndaDJg+lckP35VDdUNuelksGYHUP/8ctv4s5tCrhZRuA//js9AiipKRCmcJz96Ulc4E1GSvAS9au82Q=";
    static String pri1 = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAo+FXGL3WkDgdlPWNKWASFNIjZ2dFLNqhp+NtBvrTSHygdCp3wspE1lgFKsAjZCw9+PfQY0DZI7Ed9rj3kh6ei+6hgYkDgYYABAHj/usnp9qFyETPvMzEPCJO4FXcuK4ENsEGHZ1j3/EV72b7diNnKxLryVH5gzgUG0beK/7AKpMkhwuKY3ays3WbrQEEmxpfTuCd1oMmD6VyQ/flUN1Q256WSwZgdQ//xy2/izm0KuFlG4D/+Oz0CKKkpEKZwnP3pSVzgTUZK8BL1q7zZA==";
    static String enc1 = "njCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAWlnIT+zgmfnE+2MgAm8qZ2nS37JW5y0a5a7lecFdci6fZ7e+pYKur45vfVDXbs9YyPDF6Dy02tqSA1PnzgeJAm3APxDHHfirmGs6zUPQrpCP7+MIYs7Yd4PH4Ik2nxCvdf+2LOGdGsvlrQ89iXyZF6/rAYHhOmm4B76TofzwFaM7wvf2fw7mpOnHXC7uMa8T/j211GT+rg=";
    static String sign1 = "MIGHAkIAmz/B5YhDZB6Bmm1NPRlE0YtSoBIvLyaBy8z70wuqIMnpu3xt5GkL/x6eHEzRI6O8R9/UxwHLIPvVQkl8bcy0KrkCQVEJqEXc//h5vq9qTVzJk19pX93OQSxsvKPdA0T99AYBwyaLE5MIAKV9/kHzmNc8DHZXSD+ag4nVi8RlG+vLJ3AY";

    public static void p(byte[] d) {
        if (d == null) {
            System.out.println("null");
            return;
        }
        for (byte b : d) {
            System.out.print((b & 0xFF) + " ");
        }
        System.out.println("\n====================");
    }

    public static byte[] repeat(byte[] data, int times) {
        byte[] out = new byte[data.length * times];
        for(int i=0; i<times; i++) {
            System.arraycopy(data, 0, out, i * data.length, data.length);
        }
        return out;
    }

    public static void main(String[] args) {
        try {
            Bencrypt ben = new Bencrypt();

            System.out.println("\n===== basic test =====");
            p(ben.random(16));
            p(ben.sha3256(new byte[0]));
            p(ben.sha3512(new byte[0]));
            p(ben.pbkdf2("0000".getBytes(), "0000000000000000".getBytes(), 0, 0));
            
            String tHash = ben.argon2Hash("0000".getBytes(), "0000000000000000".getBytes());
            System.out.println(tHash);
            System.out.println(ben.argon2Verify(tHash, "0000".getBytes()));
            p(ben.genkey("0000000000000000".getBytes(), "test", 16));

            System.out.println("\n===== aes test =====");
            byte[] plain = repeat("Hello, world!".getBytes(StandardCharsets.UTF_8), 4);
            byte[] key = repeat("0123".getBytes(StandardCharsets.UTF_8), 11); // 44 bytes

            byte[] enc = ben.enAESGCM(key, plain);
            p(enc);
            System.out.println(ben.processed);
            
            byte[] dec = ben.deAESGCM(key, enc);
            System.out.println(new String(dec, StandardCharsets.UTF_8));
            System.out.println(ben.processed);

            // Large stream test (100MB)
            byte[] hugePlain = new byte[100000000]; // 100MB zero-filled
            ByteArrayInputStream rin = new ByteArrayInputStream(hugePlain);
            ByteArrayOutputStream wout = new ByteArrayOutputStream();
            
            ben.enAESGCMx(key, rin, hugePlain.length, wout, 1048576);
            byte[] tBytes = wout.toByteArray();
            
            // Print first 16 bytes (p(t[0:16]))
            p(Arrays.copyOfRange(tBytes, 0, 16));
            System.out.println(ben.processed);

            rin = new ByteArrayInputStream(tBytes);
            wout = new ByteArrayOutputStream();
            ben.deAESGCMx(key, rin, tBytes.length, wout, 1048576);
            System.out.println(ben.processed);
            System.out.println(Arrays.equals(wout.toByteArray(), hugePlain));

            // Test various sizes (Edge cases)
            // Empty string
            byte[] tEmpty = ben.enAESGCM(key, new byte[0]);
            System.out.println(Arrays.equals(ben.deAESGCM(key, tEmpty), new byte[0]));

            // Empty stream
            rin = new ByteArrayInputStream(new byte[0]);
            wout = new ByteArrayOutputStream();
            ben.enAESGCMx(key, rin, 0, wout, 1048576);
            byte[] tStreamEmpty = wout.toByteArray();
            
            rin = new ByteArrayInputStream(tStreamEmpty);
            wout = new ByteArrayOutputStream();
            ben.deAESGCMx(key, rin, tStreamEmpty.length, wout, 1048576);
            System.out.println(Arrays.equals(wout.toByteArray(), new byte[0]));

            // Exact chunk multiple
            int size4M = 1048576 * 4;
            rin = new ByteArrayInputStream(new byte[size4M]);
            wout = new ByteArrayOutputStream();
            ben.enAESGCMx(key, rin, size4M, wout, 1048576);
            byte[] t4M = wout.toByteArray();

            rin = new ByteArrayInputStream(t4M);
            wout = new ByteArrayOutputStream();
            ben.deAESGCMx(key, rin, t4M.length, wout, 1048576);
            System.out.println(Arrays.equals(wout.toByteArray(), new byte[size4M]));


            System.out.println("\n===== rsa test =====");
            // Load pre-existing key (Interop)
            Bencrypt youRSA = new Bencrypt();
            youRSA.RSAloadkey(Base64.getDecoder().decode(pub0), Base64.getDecoder().decode(pri0));
            
            byte[] rsaEnc = youRSA.RSAencrypt(plain); // Hello world * 4
            System.out.println(new String(youRSA.RSAdecrypt(rsaEnc), StandardCharsets.UTF_8));

            // Generate new key
            Bencrypt meRSA = new Bencrypt();
            meRSA.RSAgenkey(2048);
            byte[] rsaSig = meRSA.RSAsign(plain);
            System.out.println(meRSA.RSAverify(plain, rsaSig));

            // Interop: decrypt enc0, verify sign0
            p(youRSA.RSAdecrypt(Base64.getDecoder().decode(enc0))); // Should be "0000" (48 48 48 48)
            System.out.println(youRSA.RSAverify("0000".getBytes(), Base64.getDecoder().decode(sign0)));


            System.out.println("\n===== ecc test =====");
            // Load pre-existing key (Interop)
            Bencrypt youECC = new Bencrypt();
            youECC.ECCloadkey(Base64.getDecoder().decode(pub1), Base64.getDecoder().decode(pri1));

            // Generate new key
            Bencrypt meECC = new Bencrypt();
            meECC.ECCgenkey();

            // Encrypt using receiver's public key
            byte[] eccEnc = meECC.ECCencrypt(plain, youECC.ECCpub);
            System.out.println(new String(youECC.ECCdecrypt(eccEnc), StandardCharsets.UTF_8));

            // Sign
            byte[] eccSig = meECC.ECCsign(plain); // Using meECC.private (ECCpri)
            System.out.println(meECC.ECCverify(plain, eccSig));

            // Interop: decrypt enc1, verify sign1
            p(youECC.ECCdecrypt(Base64.getDecoder().decode(enc1))); // Should be "0000"
            System.out.println(youECC.ECCverify("0000".getBytes(), Base64.getDecoder().decode(sign1)));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}