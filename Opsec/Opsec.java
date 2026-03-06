
// test794d : USAG-Lib opsec
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.CRC32;

/*
Opsec header handler, !!! DO NOT REUSE THIS OBJECT !!! reset after reading body key
pw: (msg), headAlgo, salt, pwHash, encHeadData
rsa: (msg), headAlgo, encHeadKey, encHeadData
ecc: (msg), headAlgo, encHeadData
header: (smsg), (size), (name), (bodyKey), (bodyAlgo), (contAlgo), (sign)
*/
public class Opsec {
    // Outer Layer
    public String Msg; // non-secured message
    private String headAlgo; // header algorithm, [arg1 pbk1 rsa1 ecc1]
    private byte[] salt; // salt
    private byte[] pwHash; // pw hash
    private byte[] encHeadKey; // encrypted header key
    private byte[] encHeadData; // encrypted header data

    // Inner Layer
    public String Smsg; // secured message
    public long Size; // full body size, flag for bodyKey generation
    public String Name; // body name
    public byte[] BodyKey; // body key
    public String BodyAlgo; // body algorithm, [gcm1 gcmx1]
    public String ContAlgo; // container algorithm, [zip1 tar1]
    private byte[] sign; // signature to bodyKey/smsg

    public Opsec() {
        Reset();
    }

    public void Reset() {
        Msg = "";
        headAlgo = "";
        salt = new byte[0];
        pwHash = new byte[0];
        encHeadKey = new byte[0];
        encHeadData = new byte[0];

        Smsg = "";
        Size = -1;
        Name = "";
        BodyKey = new byte[0];
        BodyAlgo = "";
        ContAlgo = "";
        sign = new byte[0];
    }

    // ========== Helper Functions ==========
    public static String Crc32(byte[] data) {
        CRC32 crc = new CRC32();
        crc.update(data);
        long value = crc.getValue();
        return String.format("%02x%02x%02x%02x", (value & 0xFF), (value >> 8) & 0xFF, (value >> 16) & 0xFF,
                (value >> 24) & 0xFF); // 8 chars hex string
    }

    public byte[] EncodeInt(long data, int size) {
        ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
        if (size == 1)
            buf.put((byte) data);
        else if (size == 2)
            buf.putShort((short) data);
        else if (size == 4)
            buf.putInt((int) data);
        else if (size == 8)
            buf.putLong(data);
        return buf.array();
    }

    public long DecodeInt(byte[] data) {
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        if (data.length == 1)
            return Byte.toUnsignedInt(buf.get());
        if (data.length == 2)
            return Short.toUnsignedInt(buf.getShort());
        if (data.length == 4)
            return Integer.toUnsignedLong(buf.getInt());
        if (data.length == 8)
            return buf.getLong(); // Java long is signed, but bits are same
        return 0;
    }

    private byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] a : arrays)
            len += a.length;
        byte[] res = new byte[len];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, res, pos, a.length);
            pos += a.length;
        }
        return res;
    }

    private byte[] strToBytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private String bytesToStr(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    // Config Encoding
    public byte[] EncodeCfg(Map<String, byte[]> data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Map.Entry<String, byte[]> entry : data.entrySet()) {
            byte[] keyBytes = strToBytes(entry.getKey());
            byte[] valBytes = entry.getValue();
            int keyLen = keyBytes.length;
            int dataLen = valBytes.length;
            if (keyLen > 127)
                throw new IllegalArgumentException("Key length too long: " + keyLen);
            if (dataLen > 65535)
                throw new IllegalArgumentException("Data size too big: " + dataLen);

            if (dataLen > 255) {
                out.write(keyLen + 128);
                out.write(keyBytes);
                out.write(EncodeInt(dataLen, 2));
            } else {
                out.write(keyLen);
                out.write(keyBytes);
                out.write(dataLen);
            }
            out.write(valBytes);
        }
        return out.toByteArray();
    }

    // Config Decoding
    public Map<String, byte[]> DecodeCfg(byte[] data) {
        Map<String, byte[]> result = new HashMap<>();
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        while (buf.hasRemaining()) {
            int keyLen = Byte.toUnsignedInt(buf.get());
            boolean isLongData = false;
            if (keyLen > 127) {
                keyLen -= 128;
                isLongData = true;
            }
            byte[] keyBytes = new byte[keyLen];
            buf.get(keyBytes);
            String key = bytesToStr(keyBytes);

            int dataLen;
            if (isLongData) {
                dataLen = Short.toUnsignedInt(buf.getShort());
            } else {
                dataLen = Byte.toUnsignedInt(buf.get());
            }
            byte[] valBytes = new byte[dataLen];
            buf.get(valBytes);
            result.put(key, valBytes);
        }
        return result;
    }

    // read stream, return opsec header
    public byte[] Read(InputStream ins, int cut) throws IOException {
        int c = 0;
        while (true) {
            byte[] buf4 = ins.readNBytes(4);
            c += 4;

            if (Arrays.equals(buf4, strToBytes("YAS2"))) {
                byte[] buf2 = ins.readNBytes(2);
                long size = DecodeInt(buf2);
                if (size == 65535) {
                    buf2 = ins.readNBytes(2);
                    size += DecodeInt(buf2);
                }
                byte[] packet = new byte[(int) size];
                int totalRead = 0;
                while (totalRead < size) {
                    int r = ins.readNBytes(packet, totalRead, (int) size - totalRead);
                    if (r == -1 || (r == 0 && totalRead < size))
                        throw new java.io.EOFException("Unexpected EOF while reading opsec header");
                    totalRead += r;
                }
                return packet;

            } else {
                ins.readNBytes(124);
                c += 124;
            }
            if (cut > 0 && c > cut)
                return new byte[0];
        }
    }

    // write opsec header to stream
    public void Write(OutputStream outs, byte[] head) throws IOException {
        outs.write(strToBytes("YAS2"));
        int size = head.length;
        if (size < 65535) {
            outs.write(EncodeInt(size, 2));
        } else if (size <= 65535 * 2) {
            outs.write(EncodeInt(65535, 2));
            outs.write(EncodeInt(size - 65535, 2));
        } else {
            throw new IOException("Data size too big: " + size);
        }
        outs.write(head);
    }

    private byte[] wrapHead() throws IOException {
        Map<String, byte[]> cfg = new HashMap<>();
        if (!Smsg.isEmpty())
            cfg.put("smsg", strToBytes(Smsg));
        if (Size >= 0) {
            if (Size < 65536)
                cfg.put("sz", EncodeInt(Size, 2));
            else if (Size < 4294967296L)
                cfg.put("sz", EncodeInt(Size, 4));
            else
                cfg.put("sz", EncodeInt(Size, 8));
        }
        if (!Name.isEmpty())
            cfg.put("nm", strToBytes(Name));
        if (BodyKey.length > 0)
            cfg.put("bkey", BodyKey);
        if (!BodyAlgo.isEmpty())
            cfg.put("bodyal", strToBytes(BodyAlgo));
        if (!ContAlgo.isEmpty())
            cfg.put("contal", strToBytes(ContAlgo));
        if (sign.length > 0)
            cfg.put("sgn", sign);
        return EncodeCfg(cfg);
    }

    private void unwrapHead(byte[] data) {
        Map<String, byte[]> cfg = DecodeCfg(data);
        if (cfg.containsKey("smsg"))
            Smsg = bytesToStr(cfg.get("smsg"));
        if (cfg.containsKey("sz"))
            Size = DecodeInt(cfg.get("sz"));
        if (cfg.containsKey("nm"))
            Name = bytesToStr(cfg.get("nm"));
        if (cfg.containsKey("bkey"))
            BodyKey = cfg.get("bkey");
        if (cfg.containsKey("bodyal"))
            BodyAlgo = bytesToStr(cfg.get("bodyal"));
        if (cfg.containsKey("contal"))
            ContAlgo = bytesToStr(cfg.get("contal"));
        if (cfg.containsKey("sgn"))
            sign = cfg.get("sgn");
    }

    // encrypt with password
    public byte[] Encpw(String method, byte[] pw, byte[] kf) throws Exception {
        Bencrypt worker = new Bencrypt();
        headAlgo = method;
        salt = worker.Random(16);
        if (Size >= 0) {
            BodyKey = worker.Random(44);
        }
        byte[] combinedPw = (kf == null || kf.length == 0) ? pw : concat(pw, kf);
        byte[] mkey;
        String verifyLbl, keygenLbl;

        // generate password hash, encrypt header
        if (method.equals("sha3")) {
            mkey = Bencrypt.SHA3512(concat(salt, combinedPw));
            verifyLbl = "PWHASH_OPSEC_SHA3512";
            keygenLbl = "KEYGEN_OPSEC_SHA3512";
        } else if (method.equals("pbk1")) {
            mkey = Bencrypt.pbkdf2(combinedPw, salt, 1000000, 64);
            verifyLbl = "PWHASH_OPSEC_PBKDF2";
            keygenLbl = "KEYGEN_OPSEC_PBKDF2";
        } else if (method.equals("arg1")) {
            String hashStr = worker.argon2Hash(combinedPw, salt);
            mkey = strToBytes(hashStr);
            verifyLbl = "PWHASH_OPSEC_ARGON2";
            keygenLbl = "KEYGEN_OPSEC_ARGON2";
        } else {
            throw new IllegalArgumentException("Unsupported method: " + method);
        }
        pwHash = Bencrypt.genkey(mkey, verifyLbl, 32);
        byte[] hkey = Bencrypt.genkey(mkey, keygenLbl, 44);

        // Encrypt Header using SymMaster
        byte[] headData = wrapHead();
        Bencrypt.SymMaster sm = new Bencrypt.SymMaster("gcm1", hkey);
        encHeadData = sm.EnBin(headData);

        // wrap header
        Map<String, byte[]> cfg = new HashMap<>();
        if (!Msg.isEmpty())
            cfg.put("msg", strToBytes(Msg));
        cfg.put("headal", strToBytes(headAlgo));
        cfg.put("salt", salt);
        cfg.put("pwh", pwHash);
        cfg.put("ehd", encHeadData);
        return EncodeCfg(cfg);
    }

    // encrypt with public key, sign if private key is not null
    public byte[] Encpub(String method, byte[] publicBytes, byte[] privateBytes) throws Exception {
        Bencrypt worker = new Bencrypt();
        headAlgo = method;
        if (Size >= 0) {
            BodyKey = worker.Random(44);
        }

        // Init Master & Sign
        Bencrypt.AsymMaster am = new Bencrypt.AsymMaster(method);
        am.Loadkey(publicBytes, privateBytes);

        if (privateBytes != null) {
            byte[] s = (BodyKey.length > 0) ? BodyKey : strToBytes(Smsg);
            sign = am.Sign(s);
        }

        // encrypt header
        byte[] headData = wrapHead();
        if (method.equals("rsa1") || method.equals("rsa2")) {
            // RSA Hybrid: Encrypt Key with RSA, Data with AES
            byte[] hkey = worker.Random(44);
            encHeadKey = am.Encrypt(hkey);

            Bencrypt.SymMaster sm = new Bencrypt.SymMaster("gcm1", hkey);
            encHeadData = sm.EnBin(headData);
        } else if (method.equals("ecc1")) {
            // ECC Hybrid: Handled internally by ECC1 class
            encHeadData = am.Encrypt(headData);
        } else {
            throw new IllegalArgumentException("Unsupported method: " + method);
        }

        // wrap header
        Map<String, byte[]> cfg = new HashMap<>();
        if (!Msg.isEmpty())
            cfg.put("msg", strToBytes(Msg));
        cfg.put("headal", strToBytes(headAlgo));
        if (encHeadKey.length > 0)
            cfg.put("ehk", encHeadKey);
        cfg.put("ehd", encHeadData);
        return EncodeCfg(cfg);
    }

    // load outer layer of header
    public void View(byte[] data) {
        Reset();
        Map<String, byte[]> cfg = DecodeCfg(data);
        if (cfg.containsKey("msg"))
            Msg = bytesToStr(cfg.get("msg"));
        if (cfg.containsKey("headal"))
            headAlgo = bytesToStr(cfg.get("headal"));
        if (cfg.containsKey("salt"))
            salt = cfg.get("salt");
        if (cfg.containsKey("pwh"))
            pwHash = cfg.get("pwh");
        if (cfg.containsKey("ehk"))
            encHeadKey = cfg.get("ehk");
        if (cfg.containsKey("ehd"))
            encHeadData = cfg.get("ehd");
    }

    // decrypt with password
    public void Decpw(byte[] pw, byte[] kf) throws Exception {
        Bencrypt worker = new Bencrypt();
        if (headAlgo.isEmpty())
            throw new IllegalStateException("Call view() first");
        byte[] combinedPw = (kf == null || kf.length == 0) ? pw : concat(pw, kf);
        byte[] mkey;
        String verifyLbl, keygenLbl;

        // check password
        if (headAlgo.equals("sha3")) {
            mkey = Bencrypt.SHA3512(concat(salt, combinedPw));
            verifyLbl = "PWHASH_OPSEC_SHA3512";
            keygenLbl = "KEYGEN_OPSEC_SHA3512";
        } else if (headAlgo.equals("pbk1")) {
            mkey = Bencrypt.pbkdf2(combinedPw, salt, 1000000, 64);
            verifyLbl = "PWHASH_OPSEC_PBKDF2";
            keygenLbl = "KEYGEN_OPSEC_PBKDF2";
        } else if (headAlgo.equals("arg1")) {
            String hashStr = worker.argon2Hash(combinedPw, salt);
            mkey = strToBytes(hashStr);
            verifyLbl = "PWHASH_OPSEC_ARGON2";
            keygenLbl = "KEYGEN_OPSEC_ARGON2";
        } else {
            throw new IllegalArgumentException("Unsupported method: " + headAlgo);
        }
        byte[] calcHash = Bencrypt.genkey(mkey, verifyLbl, 32);
        if (!Arrays.equals(calcHash, pwHash))
            throw new SecurityException("Incorrect password");

        // decrypt header
        byte[] hkey = Bencrypt.genkey(mkey, keygenLbl, 44);
        Bencrypt.SymMaster sm = new Bencrypt.SymMaster("gcm1", hkey);
        byte[] decryptedHead = sm.DeBin(encHeadData);
        if (decryptedHead == null)
            throw new SecurityException("AES decryption failed");
        unwrapHead(decryptedHead);
    }

    // decrypt with private key, verify if public key is not null
    public void Decpub(byte[] privateBytes, byte[] publicBytes) throws Exception {
        if (headAlgo.isEmpty())
            throw new IllegalStateException("Call view() first");
        Bencrypt.AsymMaster am = new Bencrypt.AsymMaster(headAlgo);
        am.Loadkey(publicBytes, privateBytes);

        // decrypt header
        byte[] decryptedHead;
        if (headAlgo.equals("rsa1") || headAlgo.equals("rsa2")) {
            byte[] hkey = am.Decrypt(encHeadKey);
            Bencrypt.SymMaster sm = new Bencrypt.SymMaster("gcm1", hkey);
            decryptedHead = sm.DeBin(encHeadData);
        } else if (headAlgo.equals("ecc1")) {
            decryptedHead = am.Decrypt(encHeadData);
        } else {
            throw new IllegalArgumentException("Unsupported method: " + headAlgo);
        }
        if (decryptedHead == null)
            throw new SecurityException("Decryption failed");
        unwrapHead(decryptedHead);

        // verify if public key is not null
        if (publicBytes != null) {
            byte[] s = (BodyKey.length > 0) ? BodyKey : strToBytes(Smsg);
            if (!am.Verify(s, sign)) {
                throw new SecurityException("Signature verification failed");
            }
        }
    }
}
