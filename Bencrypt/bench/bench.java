// javac -cp ".;lib/*" Bencrypt.java bench.java
// java -cp ".;lib/*" bench

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.util.Arrays;

public class bench {
    // ========== Settings ==========
    static final int DATA_SIZE = 16 * 1048576;      // 16 MiB (Hash, Random)
    static final int DATA_SIZE_BIG = 256 * 1048576; // 256 MiB (AES)

    // Iterations
    static final int ITER_KDF = 5;       // Slow functions
    static int ITER_KEYGEN = 12;          // Key Gen
    static final int ITER_FAST = 65;     // Enc/Dec ops

    public static String fmtSpeed(long sizeBytes, long durationNs) {
        double mb = sizeBytes / (1024.0 * 1024.0);
        double sec = durationNs / 1_000_000_000.0;
        double speed = mb / sec;
        return String.format("%.2f MiB/s", speed);
    }

    public static String fmtTime(int count, long durationNs) {
        double totalMs = durationNs / 1_000_000.0;
        double avgMs = totalMs / count;
        return String.format("%.2f ms/op", avgMs);
    }

    public static void main(String[] args) {
        try {
            Bencrypt ben = new Bencrypt();
            long start, end;

            System.out.println("=== Bencrypt Performance Benchmark (Java) ===");

            // 1. Random Generation
            start = System.nanoTime();
            ben.random(DATA_SIZE);
            end = System.nanoTime();
            System.out.println("[Random] Gen: " + fmtSpeed(DATA_SIZE, end - start));

            // Prepare Data
            byte[] dummyData = new byte[DATA_SIZE]; // Zero filled by default

            // 2. SHA3 Functions
            start = System.nanoTime();
            ben.sha3256(dummyData);
            end = System.nanoTime();
            System.out.println("[SHA3-256]    " + fmtSpeed(DATA_SIZE, end - start));

            start = System.nanoTime();
            ben.sha3512(dummyData);
            end = System.nanoTime();
            System.out.println("[SHA3-512]    " + fmtSpeed(DATA_SIZE, end - start));

            System.out.println("----------------------------------------");

            // 3. KDF Functions
            // PBKDF2
            start = System.nanoTime();
            for (int i = 0; i < ITER_KDF; i++) {
                ben.pbkdf2("password".getBytes(), "salt_bytes_16_".getBytes(), 100000, 64);
            }
            end = System.nanoTime();
            System.out.println("[PBKDF2]      " + fmtTime(ITER_KDF, end - start) + " (iter=100000)");

            // Argon2
            // Check if BouncyCastle is loaded (Assuming yes since Bencrypt compiled)
            start = System.nanoTime();
            for (int i = 0; i < ITER_KDF; i++) {
                ben.argon2Hash("password".getBytes(), "salt_bytes_16_".getBytes());
            }
            end = System.nanoTime();
            System.out.println("[Argon2id]    " + fmtTime(ITER_KDF, end - start) + " (m=256MB, t=3, p=4)");

            System.out.println("----------------------------------------");
            
            // AES Data Prep (256 MB)
            byte[] dummyDataBig = new byte[DATA_SIZE_BIG];
            byte[] key = new byte[44]; // Zero key
            byte[] encData;

            // 4. AES-GCM (Memory)
            // Encrypt
            start = System.nanoTime();
            encData = ben.enAESGCM(key, dummyDataBig);
            end = System.nanoTime();
            System.out.println("[AES-GCM] Mem Enc: " + fmtSpeed(DATA_SIZE_BIG, end - start));

            // Decrypt
            start = System.nanoTime();
            ben.deAESGCM(key, encData);
            end = System.nanoTime();
            System.out.println("[AES-GCM] Mem Dec: " + fmtSpeed(DATA_SIZE_BIG, end - start));

            // 5. AES-GCMx (Memory Stream)
            ByteArrayInputStream memIn = new ByteArrayInputStream(dummyDataBig);
            ByteArrayOutputStream memOut = new ByteArrayOutputStream();

            start = System.nanoTime();
            ben.enAESGCMx(key, memIn, DATA_SIZE_BIG, memOut, 0); // 0 for default chunk
            end = System.nanoTime();
            System.out.println("[AES-GCMx] Mem Enc: " + fmtSpeed(DATA_SIZE_BIG, end - start));

            byte[] encStreamData = memOut.toByteArray();
            memIn = new ByteArrayInputStream(encStreamData);
            memOut = new ByteArrayOutputStream();

            start = System.nanoTime();
            ben.deAESGCMx(key, memIn, encStreamData.length, memOut, 0);
            end = System.nanoTime();
            System.out.println("[AES-GCMx] Mem Dec: " + fmtSpeed(DATA_SIZE_BIG, end - start));

            // 6. AES-GCMx (File Stream)
            File tempDir = Files.createTempDirectory("bench_java").toFile();
            File fSrc = new File(tempDir, "source.bin");
            File fDst = new File(tempDir, "dest.bin");
            File fDec = new File(tempDir, "decrypted.bin");

            try {
                // Create dummy file
                try (FileOutputStream fos = new FileOutputStream(fSrc)) {
                    fos.write(dummyDataBig);
                }

                // Encrypt File
                try (FileInputStream fis = new FileInputStream(fSrc);
                     FileOutputStream fos = new FileOutputStream(fDst)) {
                    start = System.nanoTime();
                    ben.enAESGCMx(key, fis, fSrc.length(), fos, 0);
                    end = System.nanoTime();
                    System.out.println("[AES-GCMx] File Enc: " + fmtSpeed(DATA_SIZE_BIG, end - start));
                }

                // Decrypt File
                try (FileInputStream fis = new FileInputStream(fDst);
                     FileOutputStream fos = new FileOutputStream(fDec)) {
                    start = System.nanoTime();
                    ben.deAESGCMx(key, fis, fDst.length(), fos, 0);
                    end = System.nanoTime();
                    System.out.println("[AES-GCMx] File Dec: " + fmtSpeed(DATA_SIZE_BIG, end - start));
                }

            } finally {
                // Cleanup
                fSrc.delete();
                fDst.delete();
                fDec.delete();
                tempDir.delete();
            }

            System.out.println("----------------------------------------");

            // 7. RSA
            byte[] payload = new byte[64];
            Arrays.fill(payload, (byte) 'A');
            int[] bitSizes = {2048, 4096};
            byte[] rsaEnc = null;

            for (int bits : bitSizes) {
                if (bits == 4096) ITER_KEYGEN = 2;
                Bencrypt rsa = new Bencrypt();

                // Key Gen
                start = System.nanoTime();
                for (int i = 0; i < ITER_KEYGEN; i++) {
                    rsa.RSAgenkey(bits);
                }
                end = System.nanoTime();
                System.out.println("[RSA-" + bits + "] GenKey : " + fmtTime(ITER_KEYGEN, end - start));

                // Prepare for Enc/Dec
                rsa.RSAgenkey(bits);

                // Encrypt
                start = System.nanoTime();
                for (int i = 0; i < ITER_FAST; i++) {
                    rsaEnc = rsa.RSAencrypt(payload);
                }
                end = System.nanoTime();
                System.out.println("[RSA-" + bits + "] Encrypt: " + fmtTime(ITER_FAST, end - start));

                // Decrypt
                start = System.nanoTime();
                for (int i = 0; i < ITER_FAST; i++) {
                    rsa.RSAdecrypt(rsaEnc);
                }
                end = System.nanoTime();
                System.out.println("[RSA-" + bits + "] Decrypt: " + fmtTime(ITER_FAST, end - start));
                System.out.println("[RSA-" + bits + "] Sign   : (Similar to Decrypt)");
            }

            System.out.println("----------------------------------------");
            ITER_KEYGEN = 20;

            // 8. ECC (Curve448)
            Bencrypt ecc = new Bencrypt();
            byte[] eccEnc = null;

            // Key Gen
            start = System.nanoTime();
            for (int i = 0; i < ITER_KEYGEN; i++) {
                ecc.ECCgenkey();
            }
            end = System.nanoTime();
            System.out.println("[ECC-448]  GenKey : " + fmtTime(ITER_KEYGEN, end - start));

            // Encrypt (Includes AES Gen + Enc)
            start = System.nanoTime();
            for (int i = 0; i < ITER_FAST; i++) {
                eccEnc = ecc.ECCencrypt(payload);
            }
            end = System.nanoTime();
            System.out.println("[ECC-448]  Encrypt: " + fmtTime(ITER_FAST, end - start) + " (Includes AES gen)");

            // Decrypt
            start = System.nanoTime();
            for (int i = 0; i < ITER_FAST; i++) {
                ecc.ECCdecrypt(eccEnc);
            }
            end = System.nanoTime();
            System.out.println("[ECC-448]  Decrypt: " + fmtTime(ITER_FAST, end - start) + " (Includes AES gen)");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}