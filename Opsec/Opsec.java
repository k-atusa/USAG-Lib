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
    public String msg; // non-secured message
    public String headAlgo; // header algorithm, [arg1 pbk1 rsa1 ecc1]
    public byte[] salt; // salt
    public byte[] pwHash; // pw hash
    public byte[] encHeadKey; // encrypted header key
    public byte[] encHeadData; // encrypted header data

    // Inner Layer
    public String smsg; // secured message
    public long size; // full body size, flag for bodyKey generation
    public String name; // body name
    public byte[] bodyKey; // body key
    public String bodyAlgo; // body algorithm, [gcm1 gcmx1]
    public String contAlgo; // container algorithm, [zip1 tar1]
    public byte[] sign; // signature to bodyKey/smsg

    public Opsec() {
        reset();
    }

    public void reset() {
        msg = "";
        headAlgo = "";
        salt = new byte[0];
        pwHash = new byte[0];
        encHeadKey = new byte[0];
        encHeadData = new byte[0];

        smsg = "";
        size = -1;
        name = "";
        bodyKey = new byte[0];
        bodyAlgo = "";
        contAlgo = "";
        sign = new byte[0];
    }

    // ========== Helper Functions ==========
    public byte[] crc32(byte[] data) {
        CRC32 crc = new CRC32();
        crc.update(data);
        long value = crc.getValue();
        ByteBuffer buf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) value);
        return buf.array();
    }

    public byte[] encodeInt(long data, int size) {
        ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
        if (size == 1) buf.put((byte) data);
        else if (size == 2) buf.putShort((short) data);
        else if (size == 4) buf.putInt((int) data);
        else if (size == 8) buf.putLong(data);
        return buf.array();
    }

    public long decodeInt(byte[] data) {
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        if (data.length == 1) return Byte.toUnsignedInt(buf.get());
        if (data.length == 2) return Short.toUnsignedInt(buf.getShort());
        if (data.length == 4) return Integer.toUnsignedLong(buf.getInt());
        if (data.length == 8) return buf.getLong(); // Java long is signed, but bits are same
        return 0;
    }

    private byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] a : arrays) len += a.length;
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
    public byte[] encodeCfg(Map<String, byte[]> data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Map.Entry<String, byte[]> entry : data.entrySet()) {
            byte[] keyBytes = strToBytes(entry.getKey());
            byte[] valBytes = entry.getValue();
            int keyLen = keyBytes.length;
            int dataLen = valBytes.length;
            if (keyLen > 127) throw new IllegalArgumentException("Key length too long: " + keyLen);
            if (dataLen > 65535) throw new IllegalArgumentException("Data size too big: " + dataLen);

            if (dataLen > 255) {
                out.write(keyLen + 128);
                out.write(keyBytes);
                out.write(encodeInt(dataLen, 2));
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
    public Map<String, byte[]> decodeCfg(byte[] data) {
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
    public byte[] read(InputStream ins, int cut) throws IOException {
        int c = 0;
        byte[] buf4 = new byte[4];
        byte[] buf2 = new byte[2];
        byte[] buf124 = new byte[124];
        while (true) {
            int read = ins.read(buf4);
            c += 4;
            if (read < 4) return new byte[0];

            if (Arrays.equals(buf4, strToBytes("YAS2"))) {
                ins.read(buf2);
                long size = decodeInt(buf2);
                if (size == 65535) {
                    ins.read(buf2);
                    size += decodeInt(buf2);
                }
                byte[] packet = new byte[(int)size];
                int totalRead = 0;
                while (totalRead < size) {
                    int r = ins.read(packet, totalRead, (int)size - totalRead);
                    if (r == -1) break;
                    totalRead += r;
                }
                return packet;

            } else {
                ins.read(buf124);
                c += 124;
            }
            if (cut > 0 && c > cut) return new byte[0];
        }
    }

    // write opsec header to stream
    public void write(OutputStream outs, byte[] head) throws IOException {
        outs.write(strToBytes("YAS2"));
        int size = head.length;
        if (size < 65535) {
            outs.write(encodeInt(size, 2));
        } else if (size <= 65535 * 2) {
            outs.write(encodeInt(65535, 2));
            outs.write(encodeInt(size - 65535, 2));
        } else {
            throw new IOException("Data size too big: " + size);
        }
        outs.write(head);
    }

    private byte[] wrapHead() throws IOException {
        Map<String, byte[]> cfg = new HashMap<>();
        if (!smsg.isEmpty()) cfg.put("smsg", strToBytes(smsg));
        if (size >= 0) {
            if (size < 65536) cfg.put("sz", encodeInt(size, 2));
            else if (size < 4294967296L) cfg.put("sz", encodeInt(size, 4));
            else cfg.put("sz", encodeInt(size, 8));
        }
        if (!name.isEmpty()) cfg.put("nm", strToBytes(name));
        if (bodyKey.length > 0) cfg.put("bkey", bodyKey);
        if (!bodyAlgo.isEmpty()) cfg.put("bodyal", strToBytes(bodyAlgo));
        if (!contAlgo.isEmpty()) cfg.put("contal", strToBytes(contAlgo));
        if (sign.length > 0) cfg.put("sgn", sign);
        return encodeCfg(cfg);
    }

    private void unwrapHead(byte[] data) {
        Map<String, byte[]> cfg = decodeCfg(data);
        if (cfg.containsKey("smsg")) smsg = bytesToStr(cfg.get("smsg"));
        if (cfg.containsKey("sz")) size = decodeInt(cfg.get("sz"));
        if (cfg.containsKey("nm")) name = bytesToStr(cfg.get("nm"));
        if (cfg.containsKey("bkey")) bodyKey = cfg.get("bkey");
        if (cfg.containsKey("bodyal")) bodyAlgo = bytesToStr(cfg.get("bodyal"));
        if (cfg.containsKey("contal")) contAlgo = bytesToStr(cfg.get("contal"));
        if (cfg.containsKey("sgn")) sign = cfg.get("sgn");
    }

    // encrypt with password
    public byte[] encpw(String method, byte[] pw, byte[] kf) throws Exception {
        if (!method.equals("arg1") && !method.equals("pbk1")) {
            throw new IllegalArgumentException("Unsupported method: " + method);
        }
        this.headAlgo = method;
        Bencrypt b = new Bencrypt();
        this.salt = b.random(16);
        if (this.size >= 0) {
            this.bodyKey = b.random(44);
        }
        byte[] combinedPw = (kf == null || kf.length == 0) ? pw : concat(pw, kf);
        byte[] mkey;
        String verifyLbl, keygenLbl;

        // generate password hash, encrypt header
        if (method.equals("arg1")) {
            String hashStr = b.argon2Hash(combinedPw, this.salt);
            mkey = strToBytes(hashStr);
            verifyLbl = "PWHASH_OPSEC_ARGON2";
            keygenLbl = "KEYGEN_OPSEC_ARGON2";
        } else {
            mkey = b.pbkdf2(combinedPw, this.salt, 1000000, 64); // default values from readme
            verifyLbl = "PWHASH_OPSEC_PBKDF2";
            keygenLbl = "KEYGEN_OPSEC_PBKDF2";
        }
        this.pwHash = b.genkey(mkey, verifyLbl, 32);
        byte[] hkey = b.genkey(mkey, keygenLbl, 44);
        byte[] headData = wrapHead();
        this.encHeadData = b.enAESGCM(hkey, headData);

        // wrap header
        Map<String, byte[]> cfg = new HashMap<>();
        if (!msg.isEmpty()) cfg.put("msg", strToBytes(msg));
        cfg.put("headal", strToBytes(headAlgo));
        cfg.put("salt", salt);
        cfg.put("pwh", pwHash);
        cfg.put("ehd", encHeadData);
        return encodeCfg(cfg);
    }

    // encrypt with public key, sign if private key is not null
    public byte[] encpub(String method, byte[] publicBytes, byte[] privateBytes) throws Exception {
        if (!method.equals("rsa1") && !method.equals("ecc1")) {
            throw new IllegalArgumentException("Unsupported method: " + method);
        }
        this.headAlgo = method;
        Bencrypt b = new Bencrypt();
        if (this.size >= 0) {
            this.bodyKey = b.random(44);
        }

        // sign if private key is not null
        if (privateBytes != null) {
            Bencrypt signer = new Bencrypt();
            byte[] s = (bodyKey.length > 0) ? bodyKey : strToBytes(smsg);
            if (method.equals("rsa1")) {
                signer.RSAloadkey(null, privateBytes);
                this.sign = signer.RSAsign(s);
            } else {
                signer.ECCloadkey(null, privateBytes);
                this.sign = signer.ECCsign(s);
            }
        }

        // encrypt header
        byte[] headData = wrapHead();
        if (method.equals("rsa1")) {
            Bencrypt rsa = new Bencrypt();
            rsa.RSAloadkey(publicBytes, null);
            byte[] hkey = b.random(44);
            this.encHeadKey = rsa.RSAencrypt(hkey);
            this.encHeadData = b.enAESGCM(hkey, headData);
        } else {
            Bencrypt ecc = new Bencrypt();
            ecc.ECCloadkey(publicBytes, null);
            this.encHeadData = ecc.ECCencrypt(headData);
        }

        // wrap header
        Map<String, byte[]> cfg = new HashMap<>();
        if (!msg.isEmpty()) cfg.put("msg", strToBytes(msg));
        cfg.put("headal", strToBytes(headAlgo));
        if (encHeadKey.length > 0) cfg.put("ehk", encHeadKey);
        cfg.put("ehd", encHeadData);
        return encodeCfg(cfg);
    }

    // load outer layer of header
    public void view(byte[] data) {
        reset();
        Map<String, byte[]> cfg = decodeCfg(data);
        if (cfg.containsKey("msg")) msg = bytesToStr(cfg.get("msg"));
        if (cfg.containsKey("headal")) headAlgo = bytesToStr(cfg.get("headal"));
        if (cfg.containsKey("salt")) salt = cfg.get("salt");
        if (cfg.containsKey("pwh")) pwHash = cfg.get("pwh");
        if (cfg.containsKey("ehk")) encHeadKey = cfg.get("ehk");
        if (cfg.containsKey("ehd")) encHeadData = cfg.get("ehd");
    }

    // decrypt with password
    public void decpw(byte[] pw, byte[] kf) throws Exception {
        if (headAlgo.isEmpty()) throw new IllegalStateException("Call view() first");
        if (!headAlgo.equals("arg1") && !headAlgo.equals("pbk1")) {
            throw new IllegalArgumentException("Unsupported method: " + headAlgo);
        }
        byte[] combinedPw = (kf == null || kf.length == 0) ? pw : concat(pw, kf);
        Bencrypt b = new Bencrypt();
        byte[] mkey;
        String verifyLbl, keygenLbl;

        // check password
        if (headAlgo.equals("arg1")) {
            String hashStr = b.argon2Hash(combinedPw, salt);
            mkey = strToBytes(hashStr);
            verifyLbl = "PWHASH_OPSEC_ARGON2";
            keygenLbl = "KEYGEN_OPSEC_ARGON2";
        } else {
            mkey = b.pbkdf2(combinedPw, salt, 1000000, 64);
            verifyLbl = "PWHASH_OPSEC_PBKDF2";
            keygenLbl = "KEYGEN_OPSEC_PBKDF2";
        }
        byte[] calcHash = b.genkey(mkey, verifyLbl, 32);
        if (!Arrays.equals(calcHash, pwHash)) throw new SecurityException("Incorrect password");

        // decrypt header
        byte[] hkey = b.genkey(mkey, keygenLbl, 44);
        byte[] decryptedHead = b.deAESGCM(hkey, encHeadData);
        if (decryptedHead == null) throw new SecurityException("AES decryption failed");
        unwrapHead(decryptedHead);
    }

    // decrypt with private key, verify if public key is not null
    public void decpub(byte[] privateBytes, byte[] publicBytes) throws Exception {
        if (headAlgo.isEmpty()) throw new IllegalStateException("Call view() first");
        if (!headAlgo.equals("rsa1") && !headAlgo.equals("ecc1")) {
            throw new IllegalArgumentException("Unsupported method: " + headAlgo);
        }

        // decrypt header
        byte[] decryptedHead;
        if (headAlgo.equals("rsa1")) {
            Bencrypt rsa = new Bencrypt();
            rsa.RSAloadkey(null, privateBytes);
            byte[] hkey = rsa.RSAdecrypt(encHeadKey);
            decryptedHead = rsa.deAESGCM(hkey, encHeadData);
        } else {
            Bencrypt ecc = new Bencrypt();
            ecc.ECCloadkey(null, privateBytes);
            decryptedHead = ecc.ECCdecrypt(encHeadData);
        }
        if (decryptedHead == null) throw new SecurityException("Decryption failed");
        unwrapHead(decryptedHead);

        // verify if public key is not null
        if (publicBytes != null) {
            byte[] s = (bodyKey.length > 0) ? bodyKey : strToBytes(smsg);
            boolean verified;
            if (headAlgo.equals("rsa1")) {
                Bencrypt rsa = new Bencrypt();
                rsa.RSAloadkey(publicBytes, null);
                verified = rsa.RSAverify(s, sign);
            } else {
                Bencrypt ecc = new Bencrypt();
                ecc.ECCloadkey(publicBytes, null);
                verified = ecc.ECCverify(s, sign);
            }
            if (!verified) throw new SecurityException("Signature verification failed");
        }
    }
}
