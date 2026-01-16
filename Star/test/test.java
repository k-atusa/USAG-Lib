// javac -encoding UTF-8 Star.java test.java
// java -cp . test

import java.io.*;
import java.nio.charset.StandardCharsets;

public class test {
    public static void main(String[] args) {
        try {
            // 100MiB dummy file
            File smallBin = new File("small.bin");
            if (!smallBin.exists()) {
                try (FileOutputStream fos = new FileOutputStream(smallBin)) {
                    byte[] buffer = new byte[1024 * 1024]; // 1MB buffer
                    for (int i = 0; i < 100; i++) {
                        fos.write(buffer);
                    }
                }
            }

            // TarWriter
            Star writer = new Star();
            writer.openWriter(null); // memory output

            writer.write("test/", (InputStream) null, 0, 0755, true); // write "test/"
            String longName = "test/";
            for (int i = 0; i < 100; i++) longName += "_";
            longName += "small.bin";
            writer.write(longName, smallBin, 0644); // write long name
            writer.write("이진 데이터", "Hello, world!".getBytes(StandardCharsets.UTF_8), 0644); // write binary

            byte[] tarData = writer.closeTar();
            try (FileOutputStream fos = new FileOutputStream("test.tar")) {
                fos.write(tarData); // write to file
            }
            System.out.println("Created test.tar");

            // TarReader
            Star reader = new Star();
            reader.openReader(new FileInputStream("test.tar"));

            while (reader.next()) {
                System.out.printf("Name: %s, Size: %d, Mode: %o IsDir: %b\n", reader.name, reader.size, reader.mode, reader.isDir);
                if (reader.name.equals("이진 데이터")) {
                    byte[] data = reader.read();
                    System.out.println("Data: " + new String(data, StandardCharsets.UTF_8));
                } else if (!reader.isDir) {
                    FileOutputStream fos = new FileOutputStream("output.bin");
                    reader.mkfile(fos);
                    fos.close();
                }
            }
            reader.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}