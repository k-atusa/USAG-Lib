// javac Icons.java test.java
// java -cp . test

import java.io.FileOutputStream;

public class test {
    public static void main(String[] args) {
        Icons i = new Icons();
        byte[] data;
        FileOutputStream fos;

        try {
            data = i.zip_png();
            fos = new FileOutputStream("zip.png");
            fos.write(data);
            fos.close();

            data = i.zip_webp();
            fos = new FileOutputStream("zip.webp");
            fos.write(data);
            fos.close();

            data = i.aes_png();
            fos = new FileOutputStream("aes.png");
            fos.write(data);
            fos.close();

            data = i.aes_webp();
            fos = new FileOutputStream("aes.webp");
            fos.write(data);
            fos.close();

            data = i.cloud_png();
            fos = new FileOutputStream("cloud.png");
            fos.write(data);
            fos.close();

            data = i.cloud_webp();
            fos = new FileOutputStream("cloud.webp");
            fos.write(data);
            fos.close();
            
        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
        }
    }
}
