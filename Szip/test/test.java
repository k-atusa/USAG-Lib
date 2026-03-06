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
            Szip.ZipWriter writer = new Szip.ZipWriter();
            writer.Open(new File("test.zip"), true);

            // write data
            writer.Write("이진 데이터", "Hello, world!".getBytes());
            writer.Write("file", bigFile);

            // close writer
            writer.close();
            System.out.println("Zip writing completed.");

            // ZipReader
            Szip.ZipReader reader = new Szip.ZipReader();
            reader.Open(new File("test.zip"));

            // print file names and sizes
            System.out.println("Files: " + reader.Names);
            System.out.println("Sizes: " + reader.Sizes);
            
            // read first file
            byte[] data = reader.Read(0);
            System.out.println("Read[0] content: " + new String(data));
            reader.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
