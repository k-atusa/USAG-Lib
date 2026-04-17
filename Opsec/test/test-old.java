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
      System.out.println(Opsec.Crc32("test".getBytes(StandardCharsets.UTF_8))); // Expected output: 0c7e7fd8

      // 2. Key Generation
      Bencrypt.AsymMaster b = new Bencrypt.AsymMaster("rsa1");
      byte[][] rsaKeys = b.Genkey();
      byte[] pub0 = rsaKeys[0];
      byte[] pri0 = rsaKeys[1];
      b = new Bencrypt.AsymMaster("rsa2");
      rsaKeys = b.Genkey();
      byte[] pub1 = rsaKeys[0];
      byte[] pri1 = rsaKeys[1];
      b = new Bencrypt.AsymMaster("ecc1");
      rsaKeys = b.Genkey();
      byte[] pub2 = rsaKeys[0];
      byte[] pri2 = rsaKeys[1];
      Opsec m = new Opsec();

      // 3. Read/Write Test
      ByteArrayOutputStream w = new ByteArrayOutputStream();
      w.write(new byte[128 * 4]);
      m.Write(w, "Hello, world!".getBytes(StandardCharsets.UTF_8));
      ByteArrayInputStream r = new ByteArrayInputStream(w.toByteArray());
      byte[] readBack = m.Read(r, 65535);
      System.out.println(new String(readBack, StandardCharsets.UTF_8)); // Expected: Hello, world!

      // 4-1. SHA3 Test
      m.Msg = "msg-test";
      m.Smsg = "smsg-test";
      m.Size = 1024;
      m.Name = "name-test";
      m.BodyAlgo = "gcm1";
      m.ContAlgo = "zip1";

      byte[] encSha3 = m.Encpw("sha3", "password".getBytes(StandardCharsets.UTF_8),
          "keyfile".getBytes(StandardCharsets.UTF_8));
      m.View(encSha3);
      m.Decpw("password".getBytes(StandardCharsets.UTF_8), "keyfile".getBytes(StandardCharsets.UTF_8));
      printStatus(m);
      m.Reset();

      // 4-2. PBKDF2 Test
      m.Msg = "msg-test";
      m.Smsg = "smsg-test";
      m.Size = 1024;
      m.Name = "name-test";
      m.BodyAlgo = "gcm1";
      m.ContAlgo = "zip1";

      byte[] encPbk = m.Encpw("pbk1", "password".getBytes(StandardCharsets.UTF_8),
          "keyfile".getBytes(StandardCharsets.UTF_8));
      m.View(encPbk);
      m.Decpw("password".getBytes(StandardCharsets.UTF_8), "keyfile".getBytes(StandardCharsets.UTF_8));
      printStatus(m);
      m.Reset();

      // 5. Argon2 Test
      m.Msg = "msg-test";
      m.Smsg = "smsg-test";

      byte[] encArg = m.Encpw("arg1", "password".getBytes(StandardCharsets.UTF_8), null);
      m.View(encArg);
      m.Decpw("password".getBytes(StandardCharsets.UTF_8), null);
      printStatus(m);
      m.Reset();

      // 6-1. RSA1 Test
      m.Msg = "msg-test";
      m.Smsg = "smsg-test";
      m.Size = 1024;
      m.Name = "name-test";
      m.BodyAlgo = "gcm1";
      m.ContAlgo = "zip1";

      byte[] encRSA = m.Encpub("rsa1", pub0, pri0);
      m.View(encRSA);
      m.Decpub(pri0, pub0);
      printStatus(m);
      m.Reset();

      // 6-1. RSA2 Test
      m.Msg = "msg-test";
      m.Smsg = "smsg-test";
      m.Size = 1024;
      m.Name = "name-test";
      m.BodyAlgo = "gcm1";
      m.ContAlgo = "zip1";

      byte[] encRSA2 = m.Encpub("rsa2", pub1, pri1);
      m.View(encRSA2);
      m.Decpub(pri1, pub1);
      printStatus(m);
      m.Reset();

      // 7. ECC Test
      m.Msg = "msg-test";
      m.Smsg = "smsg-test";

      byte[] encECC = m.Encpub("ecc1", pub2, pri2);
      m.View(encECC);
      m.Decpub(pri2, pub2);
      printStatus(m);
      m.Reset();

    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  // Helper to print object status
  private static void printStatus(Opsec m) {
    System.out.println(
        m.Msg + " " +
            m.Smsg + " " +
            m.Size + " " +
            m.Name + " " +
            m.BodyAlgo + " " +
            m.ContAlgo + " " +
            m.BodyKey.length);
  }
}