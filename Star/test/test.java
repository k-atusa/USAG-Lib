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
            Star.TarWriter writer = new Star.TarWriter();
            writer.Open(null); // memory output

            writer.Write("test/", (InputStream) null, 0, 0755, true); // write "test/"
            String longName = "test/";
            for (int i = 0; i < 100; i++) longName += "가";
            longName += "파일.bin";
            writer.Write(longName, smallBin, 0644); // write long name
            writer.Write("이진 데이터", "Hello, world!".getBytes(StandardCharsets.UTF_8), 0644); // write binary

            byte[] tarData = writer.Close();
            try (FileOutputStream fos = new FileOutputStream("test.tar")) {
                fos.write(tarData); // write to file
            }
            System.out.println("Created test.tar");

            // TarReader
            Star.TarReader reader = new Star.TarReader();
            reader.Open(new FileInputStream("test.tar"));

            while (reader.Next()) {
                System.out.printf("Name: %s, Size: %d, Mode: %o IsDir: %b\n", reader.Name, reader.Size, reader.Mode, reader.IsDir);
                if (reader.Name.equals("이진 데이터")) {
                    byte[] data = reader.Read();
                    System.out.println("Data: " + new String(data, StandardCharsets.UTF_8));
                } else if (!reader.IsDir) {
                    FileOutputStream fos = new FileOutputStream("output.bin");
                    reader.Mkfile(fos);
                    fos.close();
                }
            }
            reader.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}