// javac Icons.java test.java
// java -cp . test

import java.io.FileOutputStream;

public class test {
    public static void main(String[] args) {
        FileOutputStream fos;

        try {
            fos = new FileOutputStream("zip.png");
            fos.write(Icons.ZipPng);
            fos.close();

            fos = new FileOutputStream("zip.webp");
            fos.write(Icons.ZipWebp);
            fos.close();

            fos = new FileOutputStream("aes.png");
            fos.write(Icons.AesPng);
            fos.close();

            fos = new FileOutputStream("aes.webp");
            fos.write(Icons.AesWebp);
            fos.close();

            fos = new FileOutputStream("cloud.png");
            fos.write(Icons.CloudPng);
            fos.close();

            fos = new FileOutputStream("cloud.webp");
            fos.write(Icons.CloudWebp);
            fos.close();
            
        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
        }
    }
}
