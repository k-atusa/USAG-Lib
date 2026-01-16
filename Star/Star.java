// test792d : USAG-Lib star

import java.io.*;
import java.nio.charset.StandardCharsets;

public class Star implements Closeable {
    // TarWriter
    private OutputStream out;

    // TarReader
    private InputStream in;
    private boolean isEOF;

    // Entry metadata
    public String name;
    public long size;
    public int mode;
    public boolean isDir;

    public Star() {
        this.out = null;
        this.in = null;
        this.isEOF = false;
        this.name = "";
        this.size = 0;
        this.mode = 0644;
        this.isDir = false;
    }

    // ========== Writer Methods ==========
    public void openWriter(OutputStream out) {
        if (out == null) { // memory stream
            this.out = new ByteArrayOutputStream();
        } else {
            this.out = out;
        }
    }

    public void write(String name, byte[] data, int mode) throws IOException {
        write(name, new ByteArrayInputStream(data), data.length, mode, false);
    }

    public void write(String name, File data, int mode) throws IOException {
        write(name, new FileInputStream(data), data.length(), mode, false);
    }

    public void write(String name, InputStream data, long size, int mode, boolean isDir) throws IOException {
        if (isDir) {
            name = name.replace('\\', '/');
            if (!name.endsWith("/")) name += "/";
        }
        if (name.getBytes(StandardCharsets.UTF_8).length > 99 || size > 077777777777L) { // needs PAX
            byte[] pax = paxHeader(name, size);
            this.out.write(pax);
        }
        this.out.write(tarHeader(name, size, mode, isDir ? '5' : '0'));
        if (!isDir) {
            copy(data, this.out, size);
            this.out.write(pad(size));
        }
    }

    private byte[] pad(long size) {
        int pad = (int) (512 - (size % 512));
        return new byte[pad % 512];
    }

    private byte[] tarHeader(String name, long size, int mode, char type) {
        byte[] h = new byte[512];
        if (size > 077777777777L) {
            size = 0;
        }

        // Name (0-100)
        writeStr(h, 0, name, 100);

        // Mode (100-108)
        writeOct(h, 100, mode, 8);

        // Size (124-136)
        writeOct(h, 124, size, 12);

        // MTime (136-148)
        writeOct(h, 136, System.currentTimeMillis() / 1000, 12);

        // Checksum (148-156) - Initially spaces
        for(int i=148; i<156; i++) h[i] = 32;

        // Typeflag (156)
        h[156] = (byte) type;

        // Magic (257) "ustar\0"
        writeStr(h, 257, "ustar", 6);

        // Version (263) "00"
        writeStr(h, 263, "00", 2);

        // Calculate Checksum
        long checksum = 0;
        for (byte b : h) checksum += (b & 0xFF); // unsigned sum
        String chkStr = String.format("%06o", checksum);
        System.arraycopy(chkStr.getBytes(StandardCharsets.UTF_8), 0, h, 148, 6);
        h[154] = 0;
        h[155] = 32;
        return h;
    }

    private byte[] paxHeader(String name, long size) {
        String result = "";
        String[] keys = {"path", "size"};
        String[] vals = {name, String.valueOf(size)};

        for(int i=0; i<2; i++) {
            String key = keys[i];
            String val = vals[i];
            String lineData = " " + key + "=" + val + "\n";
            
            // Calculate length iteratively
            int len = lineData.getBytes(StandardCharsets.UTF_8).length + 1;
            int currentLen = len;
            while(true) {
                String fullLine = currentLen + lineData;
                int actualLen = fullLine.getBytes(StandardCharsets.UTF_8).length;
                if (actualLen == currentLen) {
                    result += fullLine;
                    break;
                }
                currentLen = actualLen;
            }
        }
        
        // Return Header + Data + Padding
        byte[] paxData = result.getBytes(StandardCharsets.UTF_8);
        byte[] header = tarHeader("PaxHeader/" + name, paxData.length, 0644, 'x');
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(header);
            baos.write(paxData);
            baos.write(pad(paxData.length));
        } catch (IOException e) { /* impossible */ }
        return baos.toByteArray();
    }

    // ========== Reader Methods ==========
    public void openReader(InputStream in) {
        this.in = in;
        this.isEOF = false;
        this.name = "";
        this.size = 0;
        this.mode = 0644;
        this.isDir = false;
    }

    private void unpad(long size) throws IOException {
        long pad = ((512 - (size % 512)) % 512);
        if (pad > 0) {
            byte[] temp = new byte[(int)pad];
            this.in.read(temp);
        }
    }

    private void parse(byte[] pax) {
        String data = new String(pax, StandardCharsets.UTF_8);
        String[] lines = data.split("\n");
        for (String line : lines) {
            int spaceIdx = line.indexOf(' ');
            if (spaceIdx == -1) continue;
            int eqIdx = line.indexOf('=');
            if (eqIdx == -1) continue;
            
            String key = line.substring(spaceIdx + 1, eqIdx);
            String value = line.substring(eqIdx + 1);
            if (key.equals("path")) this.name = value;
            else if (key.equals("size")) this.size = Long.parseLong(value);
        }
    }

    public boolean next() throws IOException {
        if (this.isEOF) return false;
        byte[] header = new byte[512];
        if (this.in.read(header, 0, 512) != 512) {
            this.isEOF = true;
            return false;
        }
        boolean isZero = true; // EOF check
        for (byte b : header) { if (b != 0) { isZero = false; break; } }
        if (isZero) {
            this.isEOF = true;
            return false;
        }

        // Parse Standard Header
        this.name = readStr(header, 0, 100).replace("\0", "");
        this.mode = (int) readOct(header, 100, 8);
        this.size = readOct(header, 124, 12);
        char type = (char) header[156];
        this.isDir = (type == '5');

        // Parse PAX
        if (type == 'x') {
            byte[] paxData = new byte[(int)this.size];
            this.in.read(paxData, 0, (int)this.size);
            unpad(this.size);
            parse(paxData);
            String paxName = this.name;
            long paxSize = this.size;

            boolean hasNext = next();
            this.name = paxName; // restore name
            this.size = paxSize;
            return hasNext;
        }
        return true;
    }

    public byte[] read() throws IOException {
        if (this.size > Integer.MAX_VALUE) throw new IOException("File too large for byte array");
        byte[] data = new byte[(int)this.size];
        int total = 0;
        while(total < this.size) {
            int r = this.in.read(data, total, (int)(this.size - total));
            if (r == -1) break;
            total += r;
        }
        unpad(this.size);
        return data;
    }

    public void mkfile(OutputStream dst) throws IOException {
        if (this.isDir) return;
        copy(this.in, dst, this.size);
        unpad(this.size);
    }

    public void skip() throws IOException {
        byte[] buffer = new byte[65536];
        long total = 0;
        while (total < this.size) {
            int toRead = (int)Math.min(buffer.length, this.size - total);
            int r = this.in.read(buffer, 0, toRead);
            if (r == -1) break;
            total += r;
        }
        unpad(this.size);
    }

    // ========== Common Methods ==========
    public byte[] closeTar() throws IOException {
        byte[] result = null;
        if (this.out != null) {
            this.out.write(new byte[1024]); // Two 512-byte blocks of zeros
            this.out.close();
            if (this.out instanceof ByteArrayOutputStream) {
                result = ((ByteArrayOutputStream)this.out).toByteArray();
            }
            this.out = null;
        }
        if (this.in != null) {
            this.in.close();
            this.in = null;
        }
        return result;
    }

    @Override public void close() throws IOException { closeTar(); }

    private void writeStr(byte[] b, int off, String s, int len) {
        byte[] strBytes = s.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(strBytes, 0, b, off, Math.min(strBytes.length, len));
    }

    private void writeOct(byte[] b, int off, long v, int len) {
        String s = String.format("%0" + (len - 1) + "o", v); // octal format filled with 0s
        System.arraycopy(s.getBytes(StandardCharsets.UTF_8), 0, b, off, s.length());
    }

    private String readStr(byte[] b, int off, int len) {
        return new String(b, off, len, StandardCharsets.UTF_8);
    }

    private long readOct(byte[] b, int off, int len) {
        String s = new String(b, off, len, StandardCharsets.UTF_8).trim().replace("\0", "");
        return s.isEmpty() ? 0 : Long.parseLong(s, 8);
    }

    private void copy(InputStream in, OutputStream out, long size) throws IOException {
        byte[] buf = new byte[65536];
        int len;
        long total = 0;
        while (total < size && (len = in.read(buf, 0, (int)Math.min(buf.length, size-total))) != -1) {
            out.write(buf, 0, len);
            total += len;
        }
    }
}