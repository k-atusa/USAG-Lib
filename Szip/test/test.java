// javac -encoding UTF-8 Szip.java test.java
// java -cp . test

import java.io.*;
import java.util.Arrays;

public class test {
    public static void main(String[] args) {
        try {
            // generate big file if not exists
            File bigFile = new File("big.bin");
            if (!bigFile.exists()) {
                System.out.println("Generating big.bin...");
                try (FileOutputStream fos = new FileOutputStream(bigFile)) {
                    byte[] buffer = new byte[1024 * 1024];
                    Arrays.fill(buffer, (byte) 0);
                    for (int i = 0; i < 5 * 1024; i++) {
                        fos.write(buffer);
                    }
                }
                System.out.println("big.bin generated.");
            }

            // ZipWriter
            Szip writer = new Szip();
            writer.openWriter(new File("test.zip"), false);

            // write data
            writer.write("이진 데이터", "Hello, world!".getBytes());
            writer.write("file", bigFile);

            // close writer
            writer.closeZip();
            System.out.println("Zip writing completed.");

            // ZipReader
            Szip reader = new Szip();
            reader.openReader(new File("test.zip"));

            // print file names and sizes
            System.out.println("Files: " + reader.names);
            System.out.println("Sizes: " + reader.sizes);
            
            // read first file
            byte[] data = reader.read(0);
            System.out.println("Read[0] content: " + new String(data));
            reader.closeZip();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}