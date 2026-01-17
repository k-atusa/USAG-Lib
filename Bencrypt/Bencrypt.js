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