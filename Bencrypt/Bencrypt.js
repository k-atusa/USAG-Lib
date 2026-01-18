// test793b : USAG-Lib bencrypt

/*
* !!! JS version is  not designed for big data !!!
* require js-sha3: npm install js-sha3, <script src="https://cdn.jsdelivr.net/npm/js-sha3@0.9.3/src/sha3.min.js"></script>
* require argon2: npm install argon2, <script src="https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-bundled.min.js"></script>
*/

const isNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null;
const deps = {
    crypto: null,
    argon2: null,
    sha3256: null,
    sha3512: null
};
if (isNode) {
    try {
        deps.crypto = require('crypto');
    } catch (e) {
        console.error('crypto module not found');
    }
    try {
        const sha3 = require('js-sha3');
        deps.sha3256 = sha3.sha3_256;
        deps.sha3512 = sha3.sha3_512;
    } catch (e) {
        console.error('js-sha3 module not installed');
    }
    try {
        deps.argon2 = require('argon2');
    } catch (e) {
        console.error('argon2 module not installed');
    }
} else {
    if (typeof self.crypto !== 'undefined') {
        deps.crypto = self.crypto; // Web Crypto API (Standard)
    } else if (typeof window !== 'undefined' && window.crypto) {
        deps.crypto = window.crypto;
    } else {
        console.error('web crypto api not found');
    }
    if (window.sha3_256 && window.sha3_512) {
        deps.sha3256 = window.sha3_256;
        deps.sha3512 = window.sha3_512;
    } else {
        console.error('sha3 module not installed');
    }
    if (window.argon2) {
        deps.argon2 = window.argon2;
    } else {
        console.error('argon2 module not installed');
    }
}

function toU8(data) {
    if (typeof data === 'string') return new TextEncoder().encode(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    return data;
}

/**
 * @param {Uint8Array} g - Base IV 12B
 * @param {number} c - Counter
 * @returns {Uint8Array} - Modified IV 12B
 */
function mkiv(g, c) {
    const iv = new Uint8Array(g); // Copy input
    const counterBuf = new ArrayBuffer(8);
    const view = new DataView(counterBuf);
    view.setBigUint64(0, BigInt(c), true); // Little Endian
    const counterBytes = new Uint8Array(counterBuf);
    for (let i = 0; i < 8; i++) {
        iv[4 + i] ^= counterBytes[i];
    }
    return iv;
}

function hmac_sha3_512(key, msg) {
    const B = 72; // Block size for SHA3-512 (rate = 576 bits = 72 bytes)
    let k = toU8(key);
    const m = toU8(msg);

    // 1. Key reduction / padding
    if (k.length > B) {
        k = sha3512(k); // Key is too long, hash it
    }
    if (k.length < B) {
        const newK = new Uint8Array(B);
        newK.set(k);
        k = newK; // Zero padding
    }

    // 2. Inner and Outer pads
    const o_key_pad = new Uint8Array(B);
    const i_key_pad = new Uint8Array(B);
    for (let i = 0; i < B; i++) {
        o_key_pad[i] = k[i] ^ 0x5c;
        i_key_pad[i] = k[i] ^ 0x36;
    }

    // 3. Inner hash: H(i_key_pad || msg)
    const innerData = new Uint8Array(B + m.length);
    innerData.set(i_key_pad);
    innerData.set(m, B);
    const innerHash = sha3512(innerData);

    // 4. Outer hash: H(o_key_pad || innerHash)
    const outerData = new Uint8Array(B + innerHash.length);
    outerData.set(o_key_pad);
    outerData.set(innerHash, B);
    return sha3512(outerData);
}

function toDER(rawSig, curveBits) {
    const n = Math.ceil(curveBits / 8); // 66 for P-521
    const r = rawSig.slice(0, n);
    const s = rawSig.slice(n);

    function trimAndPad(buf) {
        // Remove leading zeros
        let i = 0;
        while (i < buf.length - 1 && buf[i] === 0) i++;
        let res = buf.slice(i);
        // If MSB is 1, prepend 0x00 (DER Integer rule)
        if ((res[0] & 0x80) !== 0) {
            const temp = new Uint8Array(res.length + 1);
            temp[0] = 0x00;
            temp.set(res, 1);
            res = temp;
        }
        return res;
    }
    const rDer = trimAndPad(r);
    const sDer = trimAndPad(s);
    
    // Construct Sequence
    const totalLen = rDer.length + sDer.length + 4; // 2 tags + 2 lengths
    const res = new Uint8Array(totalLen + 2); // + Sequence tag + len
    
    let offset = 0;
    res[offset++] = 0x30; // Sequence
    res[offset++] = totalLen;
    
    res[offset++] = 0x02; // Integer
    res[offset++] = rDer.length;
    res.set(rDer, offset);
    offset += rDer.length;
    
    res[offset++] = 0x02; // Integer
    res[offset++] = sDer.length;
    res.set(sDer, offset);
    
    return res;
}

function fromDER(derSig, curveBits) {
    // Basic ASN.1 Parser for SEQUENCE { INTEGER r, INTEGER s }
    let offset = 0;
    if (derSig[offset++] !== 0x30) throw new Error("Invalid DER");
    
    // Length (simplified, assuming short form < 128 for signatures)
    let len = derSig[offset++];
    if (len & 0x80) { // Long form length
        const bytes = len & 0x7f;
        offset += bytes; 
    }

    function readInt() {
        if (derSig[offset++] !== 0x02) throw new Error("Invalid DER Integer");
        let len = derSig[offset++];
        let val = derSig.slice(offset, offset + len);
        offset += len;
        // Remove DER padding (0x00) if exists
        if (val[0] === 0x00) val = val.slice(1);
        return val;
    }
    const r = readInt();
    const s = readInt();
    const n = Math.ceil(curveBits / 8);
    const res = new Uint8Array(n * 2);
    
    // Pad or trim to fit n bytes (Big Endian)
    function copyTo(src, destOffset) {
        const srcLen = src.length;
        if (srcLen > n) { // Should rarely happen if valid, but just in case
            res.set(src.slice(srcLen - n), destOffset);
        } else {
            res.set(src, destOffset + (n - srcLen));
        }
    }
    copyTo(r, 0);
    copyTo(s, n);
    return res;
}

class TestReader {
    constructor(u8Array) {
        this.data = u8Array; // Uint8Array
        this.pos = 0;
    }
    async read(size) {
        if (this.pos >= this.data.length) {
            return new Uint8Array(0); // EOF
        }
        const end = Math.min(this.pos + size, this.data.length);
        const chunk = this.data.slice(this.pos, end);
        this.pos = end;
        return chunk;
    }
}

class TestWriter {
    constructor() {
        this.chunks = [];
        this.length = 0;
    }
    async write(chunk) {
        if (chunk && chunk.length > 0) {
            const c = new Uint8Array(chunk);
            this.chunks.push(c);
            this.length += c.length;
        }
    }
    getValue() {
        const res = new Uint8Array(this.length);
        let offset = 0;
        for (const c of this.chunks) {
            res.set(c, offset);
            offset += c.length;
        }
        return res;
    }
}

// ========== Basic Functions ==========

/**
 * random: Generate secure random bytes
 * @param {number} size 
 * @returns {Uint8Array}
 */
function random(size) {
    if (isNode) {
        return deps.crypto.randomBytes(size);
    } else {
        const buf = new Uint8Array(size);
        deps.crypto.getRandomValues(buf);
        return buf;
    }
}

/**
 * sha3256
 * @param {Uint8Array|string} data 
 * @returns {Uint8Array}
 */
function sha3256(data) {
    return new Uint8Array(deps.sha3256.create().update(data).arrayBuffer());
}

/**
 * sha3512
 * @param {Uint8Array|string} data 
 * @returns {Uint8Array}
 */
function sha3512(data) {
    return new Uint8Array(deps.sha3512.create().update(data).arrayBuffer());
}

/**
 * pbkdf2
 * @param {Uint8Array|string} pw 
 * @param {Uint8Array|string} salt 
 * @param {number} iter 
 * @param {number} outsize 
 * @returns {Promise<Uint8Array>}
 */
async function pbkdf2(pw, salt, iter = 1000000, outsize = 64) {
    const passBytes = toU8(pw);
    const saltBytes = toU8(salt);

    if (isNode) {
        return new Promise((resolve, reject) => { // make promise wrapper
            deps.crypto.pbkdf2(passBytes, saltBytes, iter, outsize, 'sha512', (err, key) => {
                if (err) reject(err);
                else resolve(new Uint8Array(key));
            });
        });

    } else { // Browser API returns promise
        const keyMaterial = await deps.crypto.subtle.importKey(
            "raw", 
            passBytes, 
            "PBKDF2", 
            false, 
            ["deriveBits"]
        );
        const derivedBits = await deps.crypto.subtle.deriveBits(
            {
                name: "PBKDF2",
                salt: saltBytes,
                iterations: iter,
                hash: "SHA-512"
            },
            keyMaterial,
            outsize * 8
        );
        return new Uint8Array(derivedBits);
    }
}

/**
 * argon2Hash
 * @param {Uint8Array|string} pw - Password (or binary data)
 * @param {Uint8Array|string} salt - Salt (Optional, but recommended)
 * @returns {Promise<string>} Encoded hash string
 */
async function argon2Hash(pw, salt = null) {
    const pwBuf = toU8(pw);
    const saltBuf = salt ? toU8(salt) : undefined;
    const type = isNode ? deps.argon2.argon2id : deps.argon2.Argon2id;

    // set same parameters as python argon2-cffi
    if (isNode) {
        const options = {
            type: type || 2,
            timeCost: 3,
            memoryCost: 65536,
            parallelism: 4,
            hashLength: 32,
            raw: false // Return encoded string
        };
        if (saltBuf) options.salt = saltBuf;
        return await deps.argon2.hash(pwBuf, options);
        
    } else {
        const options = {
            pass: pwBuf,
            type: type || 2,
            time: 3,
            mem: 65536,
            parallelism: 4,
            hashLen: 32
        };
        if (saltBuf) {
            options.salt = saltBuf;
        }
        const res = await deps.argon2.hash(options);
        return res.encoded;
    }
}

/**
 * argon2Verify
 * @param {string} hashed - The encoded hash string to verify against
 * @param {Uint8Array|string} pw - Password (or binary data)
 * @returns {Promise<boolean>}
 */
async function argon2Verify(hashed, pw) {
    const pwBuf = toU8(pw);
    try {
        if (isNode) {
            return await deps.argon2.verify(hashed, pwBuf);
        } else {
            await deps.argon2.verify({ pass: pwBuf, encoded: hashed });
            return true;
        }
    } catch (e) {
        return false;
    }
}

/**
 * genkey: HMAC-SHA3-512 based key generation
 * @param {Uint8Array} data 
 * @param {string} lbl 
 * @param {number} size 
 * @returns {Uint8Array}
 */
function genkey(data, lbl, size) {
    const digest = hmac_sha3_512(data, lbl);
    if (size > digest.length) {
        throw new Error("key size too large");
    }
    return digest.slice(0, size);
}

// Encrypting Functions (AES1)
class AES1 {
    constructor() {
        this.processed = 0;
    }

    /**
     * enAESGCM: Simple AES-GCM Encryption
     * @param {Uint8Array} key - 44 bytes (12 bytes IV + 32 bytes Key)
     * @param {Uint8Array} data 
     * @returns {Promise<Uint8Array>} ciphertext + tag(16 bytes)
     */
    async enAESGCM(key, data) {
        this.processed = 0;
        const k = toU8(key);
        const d = toU8(data);
        if (k.length !== 44) throw new Error("key size must be 44 bytes");
        const iv = k.slice(0, 12);
        const aesKey = k.slice(12);

        if (isNode) {
            const cipher = deps.crypto.createCipheriv('aes-256-gcm', aesKey, iv);
            const encrypted = Buffer.concat([cipher.update(d), cipher.final()]);
            const tag = cipher.getAuthTag();
            this.processed = d.length;
            return new Uint8Array(Buffer.concat([encrypted, tag]));

        } else {
            const importedKey = await deps.crypto.subtle.importKey(
                "raw", aesKey, "AES-GCM", false, ["encrypt"]
            );
            const res = await deps.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv }, importedKey, d
            ); // res = ciphertext + tag
            this.processed = d.length;
            return new Uint8Array(res);
        }
    }

    /**
     * deAESGCM: Simple AES-GCM Decryption
     * @param {Uint8Array} key - 44 bytes
     * @param {Uint8Array} data - ciphertext + tag
     * @returns {Promise<Uint8Array>} plaintext
     */
    async deAESGCM(key, data) {
        this.processed = 0;
        const k = toU8(key);
        const d = toU8(data);
        if (k.length !== 44) throw new Error("key size must be 44 bytes");
        const iv = k.slice(0, 12);
        const aesKey = k.slice(12);

        if (isNode) {
            const tag = d.slice(d.length - 16);
            const ciphertext = d.slice(0, d.length - 16);
            const decipher = deps.crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
            decipher.setAuthTag(tag);
            const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
            this.processed = d.length;
            return new Uint8Array(plaintext);

        } else {
            const importedKey = await deps.crypto.subtle.importKey(
                "raw", aesKey, "AES-GCM", false, ["decrypt"]
            );
            try {
                const res = await deps.crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv }, importedKey, d
                ); // input is ciphertext + tag
                this.processed = d.length;
                return new Uint8Array(res);
            } catch (e) {
                throw new Error("Decryption failed (MAC check failed)");
            }
        }
    }

    /**
     * enAESGCMx: Stream/Chunked Encryption
     * @param {Uint8Array} key 
     * @param {Object} src - Must have `async read(size)` returning Uint8Array
     * @param {number} size - Total size of input
     * @param {Object} dst - Must have `async write(chunk)`
     * @param {number} chunkSize 
     */
    async enAESGCMx(key, src, size, dst, chunkSize = 1048576) {
        this.processed = 0;
        const k = toU8(key);
        if (k.length !== 44) throw new Error("key size must be 44 bytes");
        const globalIV = k.slice(0, 12);
        const aesKeyBytes = k.slice(12);
        let count = 0;

        // Pre-import key (Browser optimization)
        let webKey = null;
        if (!isNode) {
            webKey = await deps.crypto.subtle.importKey("raw", aesKeyBytes, "AES-GCM", false, ["encrypt"]);
        }

        // Setup Pipeline
        let writeChain = Promise.resolve(); // Ensures sequential writes
        let nextChunkPromise = src.read(chunkSize > size ? size : chunkSize); // Start First Read
        let remaining = size;

        do {
            // A. Wait for Read (Current)
            const chunk = await nextChunkPromise;
            remaining -= chunk.length; // Update remaining

            // B. Trigger Next Read
            if (remaining > 0) {
                nextChunkPromise = src.read(Math.min(chunkSize, remaining));
            } else {
                nextChunkPromise = Promise.resolve(null);
            }

            // C. Prepare IV (Synchronous, order-sensitive)
            const iv = mkiv(globalIV, count);
            count++;

            // D. Encrypt (Async - runs parallel to Next Read)
            let encryptedDataPromise;
            if (isNode) {
                const cipher = deps.crypto.createCipheriv('aes-256-gcm', aesKeyBytes, iv);
                const enc = cipher.update(chunk);
                const final = cipher.final();
                const tag = cipher.getAuthTag();
                encryptedDataPromise = Promise.resolve(Buffer.concat([enc, final, tag])); // wrap in promise
            } else {
                encryptedDataPromise = deps.crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: iv }, webKey, chunk
                ).then(buf => new Uint8Array(buf));
            }

            // E. Wait for Encryption to finish (CPU task)
            const encryptedData = await encryptedDataPromise;
            this.processed += chunk.length;

            // F. Schedule Write (Write-Behind)
            writeChain = writeChain.then(() => dst.write(encryptedData));
        } while (remaining > 0);

        // G. Finalize: Wait for all pending writes to finish
        await writeChain;
    }

    /**
     * deAESGCMx: Stream/Chunked Decryption
     * @param {Uint8Array} key 
     * @param {Object} src - Must have `async read(size)`
     * @param {number} size - Total size of ciphertext (including tags)
     * @param {Object} dst - Must have `async write(chunk)`
     * @param {number} chunkSize 
     */
    async deAESGCMx(key, src, size, dst, chunkSize = 1048576) {
        this.processed = 0;
        const k = toU8(key);
        if (k.length !== 44) throw new Error("key size must be 44 bytes");
        const globalIV = k.slice(0, 12);
        const aesKeyBytes = k.slice(12);
        let count = 0;

        // Pre-import key (Browser optimization)
        let webKey = null;
        if (!isNode) {
            webKey = await deps.crypto.subtle.importKey("raw", aesKeyBytes, "AES-GCM", false, ["decrypt"]);
        }

        // helper to read block (chunk + tag), and return { chunk, tag }
        const readBlock = async (cSize) => {
            const c = await src.read(cSize);
            const t = await src.read(16); // Tag is always 16
            if (!t || t.length !== 16) throw new Error("Unexpected EOF reading tag");
            return { chunk: c, tag: t };
        };

        // Setup Pipeline
        let writeChain = Promise.resolve();
        let remaining = size;
        let nextBlockPromise = readBlock(Math.min(chunkSize, remaining - 16)); // read first block

        do { // Must have at least tag bytes
            // A. Wait for Read
            const block = await nextBlockPromise;
            if (!block) break;
            remaining -= block.chunk.length + 16;

            // B. Trigger Next Read
            if (remaining > 16) {
                nextBlockPromise = readBlock(Math.min(chunkSize, remaining - 16));
            } else {
                nextBlockPromise = Promise.resolve(null);
            }

            // C. Prepare IV
            const iv = mkiv(globalIV, count);
            count++;

            // D. Decrypt
            let plaintextPromise;
            if (isNode) {
                const decipher = deps.crypto.createDecipheriv('aes-256-gcm', aesKeyBytes, iv);
                decipher.setAuthTag(block.tag);
                plaintextPromise = Promise.resolve(
                    Buffer.concat([decipher.update(block.chunk), decipher.final()])
                ); // wrap in promise
            } else {
                const combined = new Uint8Array(block.chunk.length + 16); // WebCrypto needs Combined buffer
                combined.set(block.chunk);
                combined.set(block.tag, block.chunk.length);
                plaintextPromise = deps.crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv }, webKey, combined
                ).then(buf => new Uint8Array(buf));
            }

            // E. Wait for Decryption to finish (CPU task)
            const plaintext = await plaintextPromise;
            this.processed += block.chunk.length + 16;

            // E. Schedule Write
            writeChain = writeChain.then(() => dst.write(plaintext));
        } while (remaining > 16);

        // F. Finalize
        await writeChain;
    }
}

// ========== Signing Functions ==========
class RSA1 {
    constructor() {
        this.pub = null; // Node: KeyObject, Browser: CryptoKey
        this.pri = null; // Node: KeyObject, Browser: CryptoKey (OAEP)
        this.signPub = null;  // Browser only: CryptoKey (PKCS1)
        this.signPri = null;  // Browser only: CryptoKey (PKCS1)
    }

    /**
     * Generate RSA 2048/3072/4096 bits key pair, Returns DER(PKIX, PKCS8) formatted [publicKey, privateKey]
     * @param {number} bits
     * @returns {Promise<[Uint8Array, Uint8Array]>}
     */
    async genkey(bits = 2048) {
        if (isNode) {
            return new Promise((resolve, reject) => { // wrap in promise
                deps.crypto.generateKeyPair('rsa', {
                    modulusLength: bits,
                    publicKeyEncoding: { type: 'spki', format: 'der' },
                    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
                }, (err, publicKey, privateKey) => {
                    if (err) reject(err);
                    else { // load keys
                        this.loadkey(new Uint8Array(publicKey), new Uint8Array(privateKey));
                        resolve([new Uint8Array(publicKey), new Uint8Array(privateKey)]);
                    }
                });
            });

        } else {
            const keyPair = await deps.crypto.subtle.generateKey( // make generic key
                {
                    name: "RSA-OAEP",
                    modulusLength: bits,
                    publicExponent: new Uint8Array([1, 0, 1]), // 65537
                    hash: "SHA-512"
                },
                true, // extractable
                ["encrypt", "decrypt"]
            );

            // Export to DER (SPKI/PKCS8)
            const pubDer = await deps.crypto.subtle.exportKey("spki", keyPair.publicKey);
            const priDer = await deps.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
            const pubU8 = new Uint8Array(pubDer);
            const priU8 = new Uint8Array(priDer);

            // Load keys
            await this.loadkey(pubU8, priU8);
            return [pubU8, priU8];
        }
    }

    /**
     * loadkey: Import DER(PKIX, PKCS8) keys
     * @param {Uint8Array} publicBuf 
     * @param {Uint8Array} privateBuf 
     */
    async loadkey(publicBuf, privateBuf) {
        const pub = publicBuf ? toU8(publicBuf) : null;
        const pri = privateBuf ? toU8(privateBuf) : null;
        if (isNode) {
            if (pub) {
                this.pub = deps.crypto.createPublicKey({ key: pub, format: 'der', type: 'spki' });
            }
            if (pri) {
                this.pri = deps.crypto.createPrivateKey({ key: pri, format: 'der', type: 'pkcs8' });
            }

        } else { // double import in browser
            if (pub) {
                this.pub = await deps.crypto.subtle.importKey(
                    "spki", pub,
                    { name: "RSA-OAEP", hash: "SHA-512" },
                    true, ["encrypt"]
                );
                this.signPub = await deps.crypto.subtle.importKey(
                    "spki", pub,
                    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                    true, ["verify"]
                );
            }
            if (pri) {
                this.pri = await deps.crypto.subtle.importKey(
                    "pkcs8", pri,
                    { name: "RSA-OAEP", hash: "SHA-512" },
                    true, ["decrypt"]
                );
                this.signPri = await deps.crypto.subtle.importKey(
                    "pkcs8", pri,
                    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                    true, ["sign"]
                );
            }
        }
    }

    /**
     * encrypt: OAEP-SHA-512
     * @param {Uint8Array} data 
     * @returns {Promise<Uint8Array>}
     */
    async encrypt(data) {
        const d = toU8(data);
        if (isNode) {
            const buf = deps.crypto.publicEncrypt({
                key: this.pub,
                padding: deps.crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha512'
            }, d);
            return new Uint8Array(buf);
        } else {
            const buf = await deps.crypto.subtle.encrypt(
                { name: "RSA-OAEP" },
                this.pub, // SHA-512 set during import
                d
            );
            return new Uint8Array(buf);
        }
    }

    /**
     * decrypt: OAEP-SHA-512
     * @param {Uint8Array} data 
     * @returns {Promise<Uint8Array>}
     */
    async decrypt(data) {
        const d = toU8(data);
        if (isNode) {
            const buf = deps.crypto.privateDecrypt({
                key: this.pri,
                padding: deps.crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha512'
            }, d);
            return new Uint8Array(buf);
        } else {
            const buf = await deps.crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                this.pri, // SHA-512 set during import
                d
            );
            return new Uint8Array(buf);
        }
    }

    /**
     * sign: PKCS#1 v1.5 with SHA-256
     * @param {Uint8Array} data 
     * @returns {Promise<Uint8Array>}
     */
    async sign(data) {
        const d = toU8(data);
        if (isNode) {
            const buf = deps.crypto.sign("sha256", d, this.pri); // 'sha256' implies PKCS1 v1.5 padding by default in Node
            return new Uint8Array(buf);
        } else {
            const buf = await deps.crypto.subtle.sign(
                "RSASSA-PKCS1-v1_5", // SHA-256 set during import
                this.signPri,
                d
            );
            return new Uint8Array(buf);
        }
    }

    /**
     * verify: PKCS#1 v1.5 with SHA-256
     * @param {Uint8Array} data 
     * @param {Uint8Array} signature 
     * @returns {Promise<boolean>}
     */
    async verify(data, signature) {
        const d = toU8(data);
        const s = toU8(signature);
        if (isNode) {
            return deps.crypto.verify("sha256", d, this.pub, s); // 'sha256' implies PKCS1 v1.5 padding by default in Node
        } else {
            return await deps.crypto.subtle.verify(
                "RSASSA-PKCS1-v1_5", // SHA-256 set during import
                this.signPub,
                s,
                d
            );
        }
    }
}

class ECC1 {
    constructor() {
        this.pub = null; // Node: KeyObject, Browser: CryptoKey
        this.pri = null; // Node: KeyObject, Browser: CryptoKey
        this.signPub = null; // Browser only: CryptoKey
        this.signPri = null; // Browser only: CryptoKey
        this.em = new AES1();
        // encryption format: [1B PubLen][PubKey][encdata][tag]
    }

    /**
     * Generate P-521 Key Pair: DER(PKIX, PKCS8) format
     * @returns {Promise<[Uint8Array, Uint8Array]>} (public, private)
     */
    async genkey() {
        if (isNode) {
            return new Promise((resolve, reject) => { // wrap in promise
                deps.crypto.generateKeyPair('ec', {
                    namedCurve: 'P-521',
                    publicKeyEncoding: { type: 'spki', format: 'der' },
                    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
                }, (err, pub, pri) => {
                    if (err) reject(err);
                    else {
                        this.loadkey(new Uint8Array(pub), new Uint8Array(pri));
                        resolve([new Uint8Array(pub), new Uint8Array(pri)]);
                    }
                });
            });
        } else {
            const keyPair = await deps.crypto.subtle.generateKey(
                { name: "ECDH", namedCurve: "P-521" },
                true,
                ["deriveBits"]
            );
            const pub = new Uint8Array(await deps.crypto.subtle.exportKey("spki", keyPair.publicKey));
            const pri = new Uint8Array(await deps.crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
            await this.loadkey(pub, pri);
            return [pub, pri];
        }
    }

    /**
     * Load P-521 Key Pair: DER(PKIX, PKCS8) format
     * @param {Uint8Array} pub 
     * @param {Uint8Array} pri 
     */
    async loadkey(pub, pri) {
        if (isNode) {
            if (pub != null) this.pub= deps.crypto.createPublicKey({ key: pub, format: 'der', type: 'spki' });
            if (pri != null) this.pri = deps.crypto.createPrivateKey({ key: pri, format: 'der', type: 'pkcs8' });
        } else { // double import in browser
            if (pub != null) {
                this.pub = await deps.crypto.subtle.importKey(
                    "spki", pub, { name: "ECDH", namedCurve: "P-521" }, true, []
                );
                this.signPub = await deps.crypto.subtle.importKey(
                    "spki", pub, 
                    { name: "ECDSA", namedCurve: "P-521" }, 
                    false, ["verify"]
                );
            }
            if (pri != null) {
                this.pri = await deps.crypto.subtle.importKey(
                    "pkcs8", pri, { name: "ECDH", namedCurve: "P-521" }, true, ["deriveBits"]
                );
                this.signPri = await deps.crypto.subtle.importKey(
                    "pkcs8", pri, 
                    { name: "ECDSA", namedCurve: "P-521" }, 
                    false, ["sign"]
                );
            }
        }
    }

    /**
     * encrypt with receiver's public key
     * @param {Uint8Array} data
     * @param {Object} receiver // Node: KeyObject, Browser: CryptoKey
     * @returns {Promise<Uint8Array>}
     */
    async encrypt(data, receiver) {
        if (isNode) {
            const ecdh = deps.crypto.createECDH('secp521r1'); // P-521
            ecdh.generateKeys();
            ephPub = ecdh;

            const tempKey = deps.crypto.generateKeyPairSync('ec', { namedCurve: 'P-521' });
            const sharedRaw = deps.crypto.diffieHellman({
                privateKey: tempKey.privateKey,
                publicKey: receiver
            }); // sharedRaw is the X coordinate (Big Endian) for EC
            const ephPubDer = tempKey.publicKey.export({ format: 'der', type: 'spki' }); // export tempKey public
            
            // Big Endian X -> Little Endian 128 Bytes
            const sharedValue = new Uint8Array(128);
            const rawRev = Uint8Array.from(sharedRaw).reverse();
            sharedValue.set(rawRev, 0);
            
            // KDF, Encrypt
            const gcmKey = genkey(sharedValue, "KEYGEN_ECC1_ENCRYPT", 44);
            const enc = await this.em.enAESGCM(gcmKey, data);

            // Return
            const lenBuf = new Uint8Array([ephPubDer.length]);
            if (ephPubDer.length > 255) throw new Error("key too long");
            return Buffer.concat([lenBuf, ephPubDer, enc]);

        } else {
            // Generate temp ephemeral key
            const tempKey = await deps.crypto.subtle.generateKey(
                { name: "ECDH", namedCurve: "P-521" }, true, ["deriveBits"]
            );
            const sharedBits = await deps.crypto.subtle.deriveBits(
                { name: "ECDH", public: receiver },
                tempKey.privateKey,
                528 // 66 bytes
            ); // sharedBits is the X coordinate (Big Endian)
            
            // Big Endian X -> Little Endian 128 Bytes
            const sharedRaw = new Uint8Array(sharedBits);
            const sharedValue = new Uint8Array(128);
            for(let i=0; i<sharedRaw.length; i++) {
                sharedValue[i] = sharedRaw[sharedRaw.length - 1 - i];
            }

            // KDF, Encrypt
            const gcmKey = genkey(sharedValue, "KEYGEN_ECC1_ENCRYPT", 44);
            const enc = await this.em.enAESGCM(gcmKey, data);
            
            // return
            const pubBytes = new Uint8Array(await deps.crypto.subtle.exportKey("spki", ephKey.publicKey));
            if (pubBytes.length > 255) throw new Error("key too long");
            const res = new Uint8Array(1 + pubBytes.length + enc.length);
            res[0] = pubBytes.length;
            res.set(pubBytes, 1);
            res.set(enc, 1 + pubBytes.length);
            return res;
        }
    }

    /**
     * decrypt with private key
     * @param {Uint8Array} data
     * @returns {Promise<Uint8Array>}
     */
    async decrypt(data) {
        // parse data
        const d = toU8(data);
        const keyLen = d[0];
        const ephPubBytes = d.slice(1, 1 + keyLen);
        const enc = d.slice(1 + keyLen);
        
        let sharedValue; // make shared value (128B, little endian)
        if (isNode) {
            const ephPub = deps.crypto.createPublicKey({ key: ephPubBytes, format: 'der', type: 'spki' });
            const sharedRaw = deps.crypto.diffieHellman({
                privateKey: this.pri,
                publicKey: ephPub
            });
            sharedValue = new Uint8Array(128);
            const rawRev = Uint8Array.from(sharedRaw).reverse();
            sharedValue.set(rawRev, 0);

        } else {
            const ephPub = await deps.crypto.subtle.importKey(
                "spki", ephPubBytes, { name: "ECDH", namedCurve: "P-521" }, false, []
            );
            const sharedBits = await deps.crypto.subtle.deriveBits(
                { name: "ECDH", public: ephPub },
                this.pri,
                528
            );
            const sharedRaw = new Uint8Array(sharedBits);
            sharedValue = new Uint8Array(128);
            for(let i=0; i<sharedRaw.length; i++) {
                sharedValue[i] = sharedRaw[sharedRaw.length - 1 - i];
            }
        }

        // KDF, Decrypt
        const gcmKey = genkey(sharedValue, "KEYGEN_ECC1_ENCRYPT", 44);
        return await this.em.deAESGCM(gcmKey, enc);
    }

    /** 
     * sign with private key
     * @param {Uint8Array} data
     * @returns {Promise<Uint8Array>}
     */
    async sign(data) {
        const d = toU8(data);
        if (isNode) {
            const sign = deps.crypto.createSign('SHA256');
            sign.update(d);
            const sig = sign.sign(this.pri);
            return new Uint8Array(sig);

        } else {
            const rawSig = await deps.crypto.subtle.sign(
                { name: "ECDSA", hash: "SHA-256" },
                this.signPri,
                d
            );
            return toDER(new Uint8Array(rawSig), 521); // Convert P1363 (Raw) to DER
        }
    }

    /** 
     * verify with public key
     * @param {Uint8Array} data
     * @param {Uint8Array} signature
     * @returns {Promise<boolean>}
     */
    async verify(data, signature) {
        const d = toU8(data);
        const sig = toU8(signature);
        if (isNode) {
            const verify = deps.crypto.createVerify('SHA256');
            verify.update(d);
            return verify.verify(this.pub, sig);

        } else {
            try {
                const rawSig = fromDER(sig, 521); // Convert DER to P1363 (Raw)
                return await deps.crypto.subtle.verify(
                    { name: "ECDSA", hash: "SHA-256" },
                    this.signPub,
                    rawSig,
                    d
                );
            } catch (e) {
                return false;
            }
        }
    }
}