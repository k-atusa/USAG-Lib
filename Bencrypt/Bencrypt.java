// test793d : USAG-Lib bencrypt

/*
* external library BouncyCastle is required
* desktop: lib/bclib.jar
* android: gradle dependency org.bouncycastle:bcprov-jdk15to18:1.70
*/
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.signers.Ed448Signer;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedList;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Bencrypt {
    // ========== Basic Functions ==========
    private final SecureRandom randSrc = new SecureRandom();

    private static byte[] mkiv(byte[] g, long c) {
        byte[] iv = Arrays.copyOf(g, 12); // base IV 12B
        byte[] counterBytes = ByteBuffer.allocate(8) // counter 8B little endian
                .order(ByteOrder.LITTLE_ENDIAN)
                .putLong(c)
                .array();
        for (int i = 0; i < 8; i++) {
            iv[4 + i] ^= counterBytes[i]; // XOR
        }
        return iv;
    }

    private static byte[] decodeB64(String src) {
        String padded = src;
        int pad = src.length() % 4;
        if (pad > 0) {
            for (int i = 0; i < 4 - pad; i++)
                padded += "=";
        }
        return Base64.getDecoder().decode(padded);
    }

    public byte[] Random(int size) {
        byte[] bytes = new byte[size];
        this.randSrc.nextBytes(bytes);
        return bytes;
    }

    public static byte[] SHA3256(byte[] data) {
        SHA3Digest digest = new SHA3Digest(256);
        byte[] result = new byte[digest.getDigestSize()];
        digest.update(data, 0, data.length);
        digest.doFinal(result, 0);
        return result;
    }

    public static byte[] SHA3512(byte[] data) {
        SHA3Digest digest = new SHA3Digest(512);
        byte[] result = new byte[digest.getDigestSize()];
        digest.update(data, 0, data.length);
        digest.doFinal(result, 0);
        return result;
    }

    // set iter, outsize to 0 for default (1000000, 64)
    public static byte[] pbkdf2(byte[] pw, byte[] salt, int iter, int outsize) {
        if (iter <= 0)
            iter = 1000000;
        if (outsize <= 0)
            outsize = 64;
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA512Digest());
        gen.init(pw, salt, iter);
        KeyParameter params = (KeyParameter) gen.generateDerivedParameters(outsize * 8); // byte -> bit
        return params.getKey();
    }

    // Argon2 Parameters: Type=Argon2id, Time=3, Mem=262144(256MiB), Parallel=4,
    // Len=32, Salt=16
    public String argon2Hash(byte[] pw, byte[] salt) {
        if (salt == null) {
            salt = this.Random(16);
        }
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(3)
                .withMemoryAsKB(262144)
                .withParallelism(4)
                .withSalt(salt);
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(builder.build());
        byte[] result = new byte[32];
        gen.generateBytes(pw, result, 0, result.length);

        // generate formatted string ( $argon2id$v=19$m=262144,t=3,p=4$saltB64$hashB64 )
        String b64Salt = Base64.getEncoder().withoutPadding().encodeToString(salt); // base64 without padding
        String b64Hash = Base64.getEncoder().withoutPadding().encodeToString(result);
        return String.format("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", 262144, 3, 4, b64Salt, b64Hash);
    }

    public boolean argon2Verify(String hashed, byte[] pw) {
        try {
            // make simple parser
            String[] parts = hashed.split("\\$");
            if (parts.length != 6)
                return false;
            if (!parts[1].equals("argon2id"))
                return false;

            // get parameters
            String[] params = parts[3].split(",");
            int memory = 0, iterations = 0, parallelism = 0;
            for (String p : params) {
                String[] kv = p.split("=");
                int val = Integer.parseInt(kv[1]);
                if (kv[0].equals("m"))
                    memory = val;
                else if (kv[0].equals("t"))
                    iterations = val;
                else if (kv[0].equals("p"))
                    parallelism = val;
            }
            byte[] salt = decodeB64(parts[4]);
            byte[] originalHash = decodeB64(parts[5]);

            // rehash
            Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withIterations(iterations)
                    .withMemoryAsKB(memory)
                    .withParallelism(parallelism)
                    .withSalt(salt);

            Argon2BytesGenerator gen = new Argon2BytesGenerator();
            gen.init(builder.build());
            byte[] newHash = new byte[originalHash.length];
            gen.generateBytes(pw, newHash, 0, newHash.length);
            return Arrays.equals(originalHash, newHash);

        } catch (Exception e) {
            return false;
        }
    }

    // HMAC-SHA3-512
    public static byte[] genkey(byte[] data, String lbl, int size) {
        HMac hmac = new HMac(new SHA3Digest(512));
        byte[] key = lbl.getBytes(StandardCharsets.UTF_8);
        hmac.init(new KeyParameter(data)); // Key is data
        hmac.update(key, 0, key.length); // Message is label
        byte[] result = new byte[hmac.getMacSize()];
        hmac.doFinal(result, 0);
        if (size > result.length) {
            throw new IllegalArgumentException("key size too large");
        }
        return Arrays.copyOf(result, size);
    }

    // ========== Symmetric Encryption Master ==========
    public static class SymMaster {
        private String algo;
        private byte[] key;
        private Bencrypt.AES1 worker;

        /**
         * @param algo "gcm1" or "gcmx1"
         * @param key  44 bytes (12B IV + 32B Key)
         */
        public SymMaster(String algo, byte[] key) {
            if (!algo.equals("gcm1") && !algo.equals("gcmx1")) {
                throw new IllegalArgumentException("Unsupported algorithm: " + algo);
            }
            if (key.length != 44) {
                throw new IllegalArgumentException("Key length must be 44 bytes (12B IV + 32B Key)");
            }
            this.algo = algo;
            this.key = key;
            this.worker = new Bencrypt.AES1();
        }

        // Calculate expected output size
        public long AfterSize(long size) {
            if (this.algo.equals("gcm1")) {
                return size + 16;
            } else if (this.algo.equals("gcmx1")) {
                long chunkSize = 1048576;
                long c = size / chunkSize + 1;
                if (size != 0 && size % chunkSize == 0) {
                    c -= 1;
                }
                return size + (16 * c);
            }
            return 0;
        }

        public long Processed() {
            return this.worker.Processed();
        }

        // Encrypt binary data (Memory)
        public byte[] EnBin(byte[] data) throws Exception {
            if (this.algo.equals("gcm1")) {
                return this.worker.enAESGCM(this.key, data);
            } else {
                java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(data);
                java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
                this.worker.enAESGCMx(this.key, in, data.length, out, 1048576);
                return out.toByteArray();
            }
        }

        // Decrypt binary data (Memory)
        public byte[] DeBin(byte[] data) throws Exception {
            if (this.algo.equals("gcm1")) {
                return this.worker.deAESGCM(this.key, data);
            } else {
                java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(data);
                java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
                this.worker.deAESGCMx(this.key, in, data.length, out, 1048576);
                return out.toByteArray();
            }
        }

        // Encrypt Stream/File
        public void EnFile(InputStream src, long size, OutputStream dst) throws Exception {
            if (this.algo.equals("gcm1")) {
                byte[] buf = src.readAllBytes();
                byte[] enc = this.worker.enAESGCM(this.key, buf);
                dst.write(enc);
            } else {
                this.worker.enAESGCMx(this.key, src, size, dst, 1048576);
            }
        }

        // Decrypt Stream/File
        public void DeFile(InputStream src, long size, OutputStream dst) throws Exception {
            if (this.algo.equals("gcm1")) {
                byte[] buf = src.readAllBytes();
                byte[] dec = this.worker.deAESGCM(this.key, buf);
                dst.write(dec);
            } else {
                this.worker.deAESGCMx(this.key, src, size, dst, 1048576);
            }
        }
    }

    // ========== AES Encryption ==========
    public static class AES1 {
        private final AtomicLong processed = new AtomicLong(0);

        private byte[] inlineEnc(byte[] key, byte[] iv, byte[] data) throws Exception {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            return cipher.doFinal(data);
        }

        private byte[] inlineDec(byte[] key, byte[] iv, byte[] data) throws Exception {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            return cipher.doFinal(data);
        }

        // get processed bytes
        public long Processed() {
            return this.processed.get();
        }

        // encrypt single block with 44B key, output: [Ciphertext][Tag 16B]
        public byte[] enAESGCM(byte[] key, byte[] data) throws Exception {
            this.processed.set(0);
            if (key.length != 44)
                throw new IllegalArgumentException("key size must be 44 bytes");
            byte[] iv = Arrays.copyOfRange(key, 0, 12);
            byte[] keyBytes = Arrays.copyOfRange(key, 12, 44);
            byte[] result = inlineEnc(keyBytes, iv, data);
            this.processed.set(data.length);
            return result;
        }

        // decrypt single block with 44B key
        public byte[] deAESGCM(byte[] key, byte[] data) throws Exception {
            this.processed.set(0);
            if (key.length != 44)
                throw new IllegalArgumentException("key size must be 44 bytes");
            if (data.length < 16)
                throw new IllegalArgumentException("data size must be at least 16 bytes");
            byte[] iv = Arrays.copyOfRange(key, 0, 12);
            byte[] keyBytes = Arrays.copyOfRange(key, 12, 44);
            byte[] result = inlineDec(keyBytes, iv, data);
            this.processed.set(data.length);
            return result;
        }

        // encrypt stream with 44B key, default chunkSize=1048576
        public void enAESGCMx(byte[] key, InputStream src, long size, OutputStream dst, int chunkSize)
                throws Exception {
            this.processed.set(0);
            if (key.length != 44)
                throw new IllegalArgumentException("key size must be 44 bytes");
            if (chunkSize <= 0)
                chunkSize = 1048576;
            byte[] globalIV = Arrays.copyOfRange(key, 0, 12);
            byte[] globalKey = Arrays.copyOfRange(key, 12, 44);

            // 1. Generate Thread x8 Pool
            ExecutorService executor = Executors.newFixedThreadPool(8);
            LinkedList<Future<byte[]>> futures = new LinkedList<>();
            long counter = 0;
            long remaining = size;

            try {
                while (true) {
                    // 2. Read Chunk
                    long toRead = Math.min(chunkSize, remaining);
                    byte[] buffer = src.readNBytes((int) toRead);
                    remaining -= toRead;

                    // 3. Submit Task
                    final long ctr = counter++;
                    Callable<byte[]> task = () -> {
                        byte[] iv = mkiv(globalIV, ctr); // make iv, add counter
                        return inlineEnc(globalKey, iv, buffer);
                    };
                    futures.add(executor.submit(task));

                    // 4. Writeback if task is more than 8
                    while (futures.size() > 8) {
                        byte[] result = futures.poll().get();
                        dst.write(result);
                        this.processed.addAndGet(result.length - 16);
                    }
                    if (remaining <= 0)
                        break;
                }

                // 5. Writeback remaining tasks
                while (futures.size() > 0) {
                    byte[] result = futures.poll().get();
                    dst.write(result);
                    this.processed.addAndGet(result.length - 16);
                }

            } finally { // 6. Close Thread x8 Pool
                executor.shutdown();
            }
        }

        // decrypt stream with 44B key, default chunkSize=1048576
        public void deAESGCMx(byte[] key, InputStream src, long size, OutputStream dst, int chunkSize)
                throws Exception {
            this.processed.set(0);
            if (key.length != 44)
                throw new IllegalArgumentException("key size must be 44 bytes");
            if (chunkSize <= 0)
                chunkSize = 1048576;
            byte[] globalIV = Arrays.copyOfRange(key, 0, 12);
            byte[] globalKey = Arrays.copyOfRange(key, 12, 44);

            // 1. Generate Thread x8 Pool
            ExecutorService executor = Executors.newFixedThreadPool(8);
            LinkedList<Future<byte[]>> futures = new LinkedList<>();
            long counter = 0;
            long remaining = size;

            try {
                while (remaining >= 16) {
                    // 2. Read Chunk
                    long toRead = Math.min(chunkSize + 16, remaining);
                    byte[] buffer = src.readNBytes((int) toRead);
                    remaining -= toRead;

                    // 3. Submit Task
                    final long ctr = counter++;
                    Callable<byte[]> task = () -> {
                        byte[] iv = mkiv(globalIV, ctr); // make iv, add counter
                        return inlineDec(globalKey, iv, buffer);
                    };
                    futures.add(executor.submit(task));

                    // 4. Writeback if task is more than 8
                    while (futures.size() > 8) {
                        byte[] result = futures.poll().get();
                        dst.write(result);
                        this.processed.addAndGet(result.length + 16);
                    }
                }

                // 5. Writeback remaining tasks
                while (futures.size() > 0) {
                    byte[] result = futures.poll().get();
                    dst.write(result);
                    this.processed.addAndGet(result.length + 16);
                }

            } finally { // 6. Close Thread x8 Pool
                executor.shutdown();
            }
        }
    }

    // ========== Asymmetric Encryption Master ==========
    public static class AsymMaster {
        private String algo;
        private Bencrypt.RSA1 worker0;
        private Bencrypt.ECC1 worker1;

        /**
         * @param algo "rsa1", "rsa2", "ecc1"
         */
        public AsymMaster(String algo) {
            switch (algo) {
                case "rsa1": case "rsa2":
                    this.algo = algo;
                    this.worker0 = new Bencrypt.RSA1();
                    break;
                case "ecc1":
                    this.algo = algo;
                    this.worker1 = new Bencrypt.ECC1();
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported algorithm: " + algo);
            }
        }

        // Generate key pair, {public, private}
        public byte[][] Genkey() throws Exception {
            if (this.algo.equals("rsa1")) {
                return this.worker0.genkey(2048);
            } else if (this.algo.equals("rsa2")) {
                return this.worker0.genkey(4096);
            } else if (this.algo.equals("ecc1")) {
                return this.worker1.genkey();
            }
            return null;
        }

        public void Loadkey(byte[] publicBuf, byte[] privateBuf) throws Exception {
            if (this.algo.equals("rsa1") || this.algo.equals("rsa2")) {
                this.worker0.loadkey(publicBuf, privateBuf);
            } else if (this.algo.equals("ecc1")) {
                this.worker1.loadkey(publicBuf, privateBuf);
            }
        }

        public byte[] Encrypt(byte[] data) throws Exception {
            if (this.algo.equals("rsa1") || this.algo.equals("rsa2")) {
                return this.worker0.encrypt(data);
            } else {
                return this.worker1.encrypt(data);
            }
        }

        public byte[] Decrypt(byte[] data) throws Exception {
            if (this.algo.equals("rsa1") || this.algo.equals("rsa2")) {
                return this.worker0.decrypt(data);
            } else {
                return this.worker1.decrypt(data);
            }
        }

        public byte[] Sign(byte[] data) throws Exception {
            if (this.algo.equals("rsa1") || this.algo.equals("rsa2")) {
                return this.worker0.sign(data);
            } else {
                return this.worker1.sign(data);
            }
        }

        public boolean Verify(byte[] data, byte[] signature) {
            if (this.algo.equals("rsa1") || this.algo.equals("rsa2")) {
                return this.worker0.verify(data, signature);
            } else {
                return this.worker1.verify(data, signature);
            }
        }
    }

    // ========== RSA Encryption ==========
    public static class RSA1 {
        public PublicKey RSApub = null;
        public PrivateKey RSApri = null;

        // Generate RSA key (public, private), DER(PKIX, PKCS8) format
        public byte[][] genkey(int bits) throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(bits); // 2048, 3072, 4096
            KeyPair kp = kpg.generateKeyPair();
            this.RSApub = kp.getPublic();
            this.RSApri = kp.getPrivate();
            return new byte[][] {
                    this.RSApub.getEncoded(),
                    this.RSApri.getEncoded()
            };
        }

        // Load RSA key if not null (public, private), DER(PKIX, PKCS8) format
        public void loadkey(byte[] pubBytes, byte[] priBytes) throws Exception {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            if (pubBytes != null) {
                this.RSApub = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
            }
            if (priBytes != null) {
                this.RSApri = kf.generatePrivate(new PKCS8EncodedKeySpec(priBytes));
            }
        }

        // RSA encrypt: OAEP-SHA-512
        public byte[] encrypt(byte[] data) throws Exception {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
                    "SHA-512",
                    "MGF1",
                    MGF1ParameterSpec.SHA512,
                    PSource.PSpecified.DEFAULT);
            cipher.init(Cipher.ENCRYPT_MODE, this.RSApub, oaepSpec);
            return cipher.doFinal(data);
        }

        // RSA decrypt: OAEP-SHA-512
        public byte[] decrypt(byte[] data) throws Exception {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
                    "SHA-512",
                    "MGF1",
                    MGF1ParameterSpec.SHA512,
                    PSource.PSpecified.DEFAULT); // set OAEP, MGF1 to SHA-512
            cipher.init(Cipher.DECRYPT_MODE, this.RSApri, oaepSpec);
            return cipher.doFinal(data);
        }

        // RSA sign: PKCS#1 v1.5 SHA-256
        public byte[] sign(byte[] data) throws Exception {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(this.RSApri);
            sig.update(data);
            return sig.sign();
        }

        // RSA verify: PKCS#1 v1.5 SHA-256
        public boolean verify(byte[] data, byte[] signature) {
            try {
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(this.RSApub);
                sig.update(data);
                return sig.verify(signature);
            } catch (Exception e) {
                return false;
            }
        }
    }

    // ========== ECC Encryption ==========
    public static class ECC1 {
        public X448PublicKeyParameters pubX = null;
        public X448PrivateKeyParameters priX = null;
        public Ed448PublicKeyParameters pubEd = null;
        public Ed448PrivateKeyParameters priEd = null;

        // Generate ECC key (public, private), [X448 56B][Ed448 57B] format
        public byte[][] genkey() throws Exception {
            SecureRandom rnd = new SecureRandom();

            // 1. Generate X448
            X448KeyPairGenerator xGen = new X448KeyPairGenerator();
            xGen.init(new X448KeyGenerationParameters(rnd));
            AsymmetricCipherKeyPair xKp = xGen.generateKeyPair();
            this.pubX = (X448PublicKeyParameters) xKp.getPublic();
            this.priX = (X448PrivateKeyParameters) xKp.getPrivate();

            // 2. Generate Ed448
            Ed448KeyPairGenerator edGen = new Ed448KeyPairGenerator();
            edGen.init(new Ed448KeyGenerationParameters(rnd));
            AsymmetricCipherKeyPair edKp = edGen.generateKeyPair();
            this.pubEd = (Ed448PublicKeyParameters) edKp.getPublic();
            this.priEd = (Ed448PrivateKeyParameters) edKp.getPrivate();

            // 3. Get Raw Bytes & Concatenate
            byte[] xPubB = this.pubX.getEncoded(); // 56 bytes
            byte[] xPriB = this.priX.getEncoded(); // 56 bytes
            byte[] edPubB = this.pubEd.getEncoded(); // 57 bytes
            byte[] edPriB = this.priEd.getEncoded(); // 57 bytes

            byte[] pubFull = new byte[113];
            System.arraycopy(xPubB, 0, pubFull, 0, 56);
            System.arraycopy(edPubB, 0, pubFull, 56, 57);

            byte[] priFull = new byte[113];
            System.arraycopy(xPriB, 0, priFull, 0, 56);
            System.arraycopy(edPriB, 0, priFull, 56, 57);

            return new byte[][] { pubFull, priFull };
        }

        // Load ECC key if not null (public, private), [X448 56B][Ed448 57B] format
        public void loadkey(byte[] pubBytes, byte[] priBytes) throws Exception {
            if (pubBytes != null) {
                if (pubBytes.length != 113)
                    throw new IllegalArgumentException("Invalid Curve448 public key length");
                byte[] xPubB = Arrays.copyOfRange(pubBytes, 0, 56);
                byte[] edPubB = Arrays.copyOfRange(pubBytes, 56, 113);
                this.pubX = new X448PublicKeyParameters(xPubB, 0);
                this.pubEd = new Ed448PublicKeyParameters(edPubB, 0);
            }
            if (priBytes != null) {
                if (priBytes.length != 113)
                    throw new IllegalArgumentException("Invalid Curve448 private key length");
                byte[] xPriB = Arrays.copyOfRange(priBytes, 0, 56);
                byte[] edPriB = Arrays.copyOfRange(priBytes, 56, 113);
                this.priX = new X448PrivateKeyParameters(xPriB, 0);
                this.priEd = new Ed448PrivateKeyParameters(edPriB, 0);
            }
        }

        // ECC encrypt with public key, output: [1B KeyLen][PubKey][Ciphertext]
        public byte[] encrypt(byte[] data) throws Exception {
            // 1. Generate Temp Ephemeral Key
            X448KeyPairGenerator xGen = new X448KeyPairGenerator();
            xGen.init(new X448KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair ephKp = xGen.generateKeyPair();
            X448PublicKeyParameters ephPub = (X448PublicKeyParameters) ephKp.getPublic();
            X448PrivateKeyParameters ephPri = (X448PrivateKeyParameters) ephKp.getPrivate();

            // 2. ECDH Agreement
            X448Agreement agreement = new X448Agreement();
            agreement.init(ephPri);
            byte[] sharedSecret = new byte[agreement.getAgreementSize()];
            agreement.calculateAgreement(this.pubX, sharedSecret, 0);

            // 3. KDF & Encrypt
            byte[] gcmKey = Bencrypt.genkey(sharedSecret, "KEYGEN_ECC1_ENCRYPT", 44);
            Bencrypt.SymMaster worker = new Bencrypt.SymMaster("gcm1", gcmKey);
            byte[] enc = worker.EnBin(data);

            // 4. Pack
            byte[] ephPubRaw = ephPub.getEncoded(); // 56 bytes
            byte[] res = new byte[1 + ephPubRaw.length + enc.length];
            res[0] = (byte) ephPubRaw.length;
            System.arraycopy(ephPubRaw, 0, res, 1, ephPubRaw.length);
            System.arraycopy(enc, 0, res, 1 + ephPubRaw.length, enc.length);
            return res;
        }

        // ECC decrypt with my private key
        public byte[] decrypt(byte[] data) throws Exception {
            // 1. Parse
            int keyLen = data[0] & 0xFF;
            byte[] ephPubRaw = Arrays.copyOfRange(data, 1, 1 + keyLen);
            byte[] enc = Arrays.copyOfRange(data, 1 + keyLen, data.length);

            // 2. Load Eph Public Key
            X448PublicKeyParameters ephPub = new X448PublicKeyParameters(ephPubRaw, 0);

            // 3. ECDH Agreement
            X448Agreement agreement = new X448Agreement();
            agreement.init(this.priX);
            byte[] sharedSecret = new byte[agreement.getAgreementSize()];
            agreement.calculateAgreement(ephPub, sharedSecret, 0);

            // 4. KDF & Decrypt
            byte[] gcmKey = Bencrypt.genkey(sharedSecret, "KEYGEN_ECC1_ENCRYPT", 44);
            Bencrypt.SymMaster worker = new Bencrypt.SymMaster("gcm1", gcmKey);
            return worker.DeBin(enc);
        }

        // ECC sign: Ed448
        public byte[] sign(byte[] data) throws Exception {
            Ed448Signer signer = new Ed448Signer(new byte[0]); // context empty
            signer.init(true, this.priEd);
            signer.update(data, 0, data.length);
            return signer.generateSignature();
        }

        // ECC verify: Ed448
        public boolean verify(byte[] data, byte[] signature) {
            try {
                Ed448Signer signer = new Ed448Signer(new byte[0]); // context empty
                signer.init(false, this.pubEd);
                signer.update(data, 0, data.length);
                return signer.verifySignature(signature);
            } catch (Exception e) {
                return false;
            }
        }
    }
}