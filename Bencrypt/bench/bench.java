// javac -cp ".;lib/*" Bencrypt.java bench.java
// java -cp ".;lib/*" bench
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class bench {
    private static String fmt_speed(long size_bytes, double duration_sec) {
        double mb = size_bytes / (1024.0 * 1024.0);
        double speed = mb / duration_sec;
        return String.format("%.2f MiB/s", speed);
    }

    private static String fmt_time(int count, double duration_sec) {
        double avg_ms = (duration_sec / count) * 1000.0;
        return String.format("%.2f ms/op", avg_ms);
    }

    private static byte[] repeat(byte val, int length) {
        byte[] arr = new byte[length];
        for (int i = 0; i < length; i++) arr[i] = val;
        return arr;
    }

    public static void main(String[] args) {
        try {
            System.out.println("Bencrypt Benchmarks (Java)");

            Thread.sleep(1000);
            System.out.println("\n\n===== Basic Functions =====");
            long[] p = {100L * 1048576, 100L * 1048576, 100L * 1048576};
            Bencrypt bc = new Bencrypt();
            
            long start = System.nanoTime();
            bc.Random((int)p[0]);
            long end = System.nanoTime();
            System.out.println("RandGen: " + fmt_speed(p[0], (end - start) / 1e9));

            byte[] dataBasic = new byte[(int)p[1]];
            start = System.nanoTime();
            Bencrypt.SHA3256(dataBasic);
            end = System.nanoTime();
            System.out.println("SHA3256: " + fmt_speed(p[1], (end - start) / 1e9));

            dataBasic = new byte[(int)p[2]];
            start = System.nanoTime();
            Bencrypt.SHA3512(dataBasic);
            end = System.nanoTime();
            System.out.println("SHA3512: " + fmt_speed(p[2], (end - start) / 1e9));

            Thread.sleep(1000);
            System.out.println("\n\n===== Hash Functions =====");
            String[] hashm = {"sha3", "arg2low", "arg2st"};
            int[] iters_h = {100000, 5, 5};
            byte[] pw = new byte[64];
            byte[] salt = new byte[32];

            for (int i = 0; i < hashm.length; i++) {
                Bencrypt.HashMaster w = new Bencrypt.HashMaster(hashm[i]);
                start = System.nanoTime();
                for (int j = 0; j < iters_h[i]; j++) {
                    w.KDF(pw, salt);
                }
                end = System.nanoTime();
                System.out.println(hashm[i] + ": " + fmt_time(iters_h[i], (end - start) / 1e9));
            }

            Thread.sleep(1000);
            System.out.println("\n\n===== Symmetric Functions =====");
            int symSize = 512 * 1048576; // 512 MiB
            byte[] symData = new byte[symSize]; // fill 0x00
            
            // Create temp file
            File tempBin = new File("temp.bin");
            BufferedOutputStream tempOut = new BufferedOutputStream(new FileOutputStream(tempBin));
            byte[] ffBlock = repeat((byte)0xFF, 1048576);
            for(int i=0; i<512; i++) {
                tempOut.write(ffBlock);
            }
            tempOut.close();

            String[] symm = {"gcm1", "gcmx1"};
            byte[] symKey = repeat((byte)'0', 32);

            for (String algo : symm) {
                Bencrypt.SymMaster w = new Bencrypt.SymMaster(algo, symKey);
                
                // In-Memory Benchmark
                start = System.nanoTime();
                w.EnBin(symData);
                end = System.nanoTime();
                System.out.println(algo + " (in-memory): " + fmt_speed(symSize, (end - start) / 1e9));

                // File Benchmark
                File tempOutFile = new File("temp.out");
                BufferedInputStream fis = new BufferedInputStream(new FileInputStream(tempBin));
                BufferedOutputStream fos = new BufferedOutputStream(new FileOutputStream(tempOutFile));
                
                start = System.nanoTime();
                w.EnFile(fis, symSize, fos);
                end = System.nanoTime();
                
                fis.close();
                fos.close();
                System.out.println(algo + " (file): " + fmt_speed(symSize, (end - start) / 1e9));
                System.out.println();
            }

            Thread.sleep(1000);
            System.out.println("\n\n===== Asymmetric Functions =====");
            String[] asymm = {"ecc1", "pqc1"};
            int[] iters_g = {20, 20};
            int[] iters_c = {50, 50};
            byte[] asymData = new byte[64];

            for (int i = 0; i < asymm.length; i++) {
                Bencrypt.AsymMaster w = new Bencrypt.AsymMaster(asymm[i]);
                
                start = System.nanoTime();
                for (int j = 0; j < iters_g[i]; j++) {
                    w.Genkey();
                }
                end = System.nanoTime();
                System.out.println(asymm[i] + " (genkey): " + fmt_time(iters_g[i], (end - start) / 1e9));

                start = System.nanoTime();
                for (int j = 0; j < iters_c[i]; j++) {
                    w.Encrypt(asymData);
                }
                end = System.nanoTime();
                System.out.println(asymm[i] + " (encrypt): " + fmt_time(iters_c[i], (end - start) / 1e9));

                start = System.nanoTime();
                for (int j = 0; j < iters_c[i]; j++) {
                    w.Sign(asymData);
                }
                end = System.nanoTime();
                System.out.println(asymm[i] + " (sign): " + fmt_time(iters_c[i], (end - start) / 1e9));
                System.out.println();
            }

            // Cleanup
            Thread.sleep(1000);
            new File("temp.bin").delete();
            new File("temp.out").delete();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
