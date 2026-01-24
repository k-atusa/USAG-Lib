// test794b : USAG-Lib opsec
// require Bencrypt: <script src="Bencrypt.js"></script>

// Helper: Concatenate Uint8Arrays
function concat(arrays) {
    let totalLength = 0;
    for (const arr of arrays) {
        totalLength += arr.length;
    }
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

// Helper: String to Uint8Array / Uint8Array to String
const enc = new TextEncoder();
const dec = new TextDecoder();
function strToU8(str) { return enc.encode(str); }
function u8ToStr(u8) { return dec.decode(u8); }

// Helper: CRC32 Implementation
const crcTable = (() => {
    let c;
    const table = [];
    for (let n = 0; n < 256; n++) {
        c = n;
        for (let k = 0; k < 8; k++) {
            c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
        }
        table[n] = c >>> 0;
    }
    return table;
})();


/**
 * CRC32 Implementation
 * @param {Uint8Array | string} data
 */
function crc32(data) {
    const u8 = typeof data === 'string' ? strToU8(data) : data;
    let crc = -1;
    for (let i = 0; i < u8.length; i++) {
        crc = (crc >>> 8) ^ crcTable[(crc ^ u8[i]) & 0xFF];
    }
    crc = (crc ^ (-1)) >>> 0;
    
    // Return as 4 bytes Little Endian
    const view = new DataView(new ArrayBuffer(4));
    view.setUint32(0, crc, true);
    return new Uint8Array(view.buffer);
}

/**
 * Little Endian Integer Encoding
 * @param {number} data 
 * @param {number} size 
 * @returns {Uint8Array}
 */
function encodeInt(data, size) {
    const buf = new ArrayBuffer(size);
    const view = new DataView(buf);
    if (size === 1) view.setUint8(0, data);
    else if (size === 2) view.setUint16(0, data, true);
    else if (size === 4) view.setUint32(0, data, true);
    else if (size === 8) view.setBigUint64(0, BigInt(data), true);
    return new Uint8Array(buf);
}

/**
 * Little Endian Integer Decoding
 * @param {Uint8Array} data 
 * @returns {number}
 */
function decodeInt(data) {
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    if (data.length === 1) return view.getUint8(0);
    if (data.length === 2) return view.getUint16(0, true);
    if (data.length === 4) return view.getUint32(0, true);
    if (data.length === 8) return Number(view.getBigUint64(0, true)); // Check logic if > safe integer
    return 0;
}

/**
 * Config Encoder, keysize max 127, datasize max 65535
 * @param {Object} data 
 * @returns {Uint8Array}
 */
function encodeCfg(data) {
    const chunks = [];
    for (const [key, val] of Object.entries(data)) {
        const valU8 = (typeof val === 'string') ? strToU8(val) : val;
        const keyBytes = strToU8(key);
        const keyLen = keyBytes.length;
        const dataLen = valU8.length;
        if (keyLen > 127) throw new Error(`Key length too long: ${keyLen}`);
        if (dataLen > 65535) throw new Error(`Data size too big: ${dataLen}`);

        if (dataLen > 255) { // DataLen > 255, datasize is 2B, keyLen Flag set (keyLen + 128)
            chunks.push(new Uint8Array([keyLen + 128]));
            chunks.push(keyBytes);
            chunks.push(encodeInt(dataLen, 2));
        } else { // DataLen <= 255, datasize is 1B
            chunks.push(new Uint8Array([keyLen]));
            chunks.push(keyBytes);
            chunks.push(new Uint8Array([dataLen]));
        }
        chunks.push(valU8);
    }
    return concat(chunks);
}

/**
 * Config Decoder
 * @param {Uint8Array} data 
 * @returns {Object}
 */
function decodeCfg(data) {
    const result = {};
    let offset = 0;
    const totalLen = data.length;
    while (offset < totalLen) {
        // get key
        let keyLen = data[offset];
        let isLongData = false;
        offset += 1;
        if (keyLen > 127) {
            keyLen -= 128;
            isLongData = true;
        }
        const keyBytes = data.slice(offset, offset + keyLen);
        const key = u8ToStr(keyBytes);
        offset += keyLen;

        // get data
        let dataLen = 0;
        if (isLongData) {
            const lenBytes = data.slice(offset, offset + 2);
            dataLen = decodeInt(lenBytes);
            offset += 2;
        } else {
            dataLen = data[offset];
            offset += 1;
        }
        result[key] = data.slice(offset, offset + dataLen);
        offset += dataLen;
    }
    return result;
}

/*
Opsec Header Handler, !!! DO NOT REUSE THIS OBJECT !!! reset after reading body key
  pw: (msg), headAlgo, salt, pwHash, encHeadData
  rsa: (msg), headAlgo, encHeadKey, encHeadData
  ecc: (msg), headAlgo, encHeadData
  header: (smsg), (size), (name), (bodyKey), (bodyAlgo), (contAlgo), (sign)
*/
class Opsec {
    constructor() {
        this.reset();
    }

    reset() {
        // Outer Layer
        this.msg = "";                        // non-secured message
        this.headAlgo = "";                   // header algorithm, [arg1 pbk1 rsa1 ecc1]
        this.salt = new Uint8Array(0);        // salt
        this.pwHash = new Uint8Array(0);      // pw hash
        this.encHeadKey = new Uint8Array(0);  // encrypted header key
        this.encHeadData = new Uint8Array(0); // encrypted header data

        // Inner Layer
        this.smsg = "";                   // secured message
        this.size = -1;                   // full body size, flag for bodyKey generation
        this.name = "";                   // body name
        this.bodyKey = new Uint8Array(0); // body key
        this.bodyAlgo = "";               // body algorithm, [gcm1 gcmx1]
        this.contAlgo = "";               // container algorithm, [zip1 tar1]
        this.sign = new Uint8Array(0);    // signature
    }

    /**
     * read stream, returns Opsec header
     * @param {Object} ins // Object with async read(size)
     * @param {number} cut 
     * @returns {Uint8Array}
     */
    async read(ins, cut = 65535) {
        let c = 0;
        while (true) {
            const data = await ins.read(4);
            c += 4;
            if (data.length === 0) return new Uint8Array(0);
            
            const magic = u8ToStr(data);
            if (magic === "YAS2") {
                const sizeBuf = await ins.read(2);
                let size = decodeInt(sizeBuf);
                if (size === 65535) {
                    const extSizeBuf = await ins.read(2);
                    size += decodeInt(extSizeBuf);
                }
                return await ins.read(size);
            } else {
                await ins.read(124);
                c += 124;
            }
            if (cut > 0 && c > cut) return new Uint8Array(0);
        }
    }

    /**
     * write opsec header to stream
     * @param {Object} outs // Object with async write(data)
     * @param {Uint8Array} head
     */
    async write(outs, head) {
        await outs.write(strToU8("YAS2"));
        const size = head.length;
        if (size < 65535) {
            await outs.write(encodeInt(size, 2));
        } else if (size <= 65535 * 2) {
            await outs.write(encodeInt(65535, 2));
            await outs.write(encodeInt(size - 65535, 2));
        } else {
            throw new Error(`Data size too big: ${size}`);
        }
        await outs.write(head);
    }

    _wrapHead() {
        const cfg = {};
        if (this.smsg !== "") cfg["smsg"] = this.smsg;
        if (this.size >= 0) {
            if (this.size < 65536) cfg["sz"] = encodeInt(this.size, 2);
            else if (this.size < 4294967296) cfg["sz"] = encodeInt(this.size, 4);
            else cfg["sz"] = encodeInt(this.size, 8);
        }
        if (this.name !== "") cfg["nm"] = this.name;
        if (this.bodyKey.length > 0) cfg["bkey"] = this.bodyKey;
        if (this.bodyAlgo !== "") cfg["bodyal"] = this.bodyAlgo;
        if (this.contAlgo !== "") cfg["contal"] = this.contAlgo;
        if (this.sign.length > 0) cfg["sgn"] = this.sign;
        return encodeCfg(cfg);
    }

    _unwrapHead(data) {
        const cfg = decodeCfg(data);
        if (cfg["smsg"]) this.smsg = u8ToStr(cfg["smsg"]);
        if (cfg["sz"]) this.size = decodeInt(cfg["sz"]);
        if (cfg["nm"]) this.name = u8ToStr(cfg["nm"]);
        if (cfg["bkey"]) this.bodyKey = cfg["bkey"];
        if (cfg["bodyal"]) this.bodyAlgo = u8ToStr(cfg["bodyal"]);
        if (cfg["contal"]) this.contAlgo = u8ToStr(cfg["contal"]);
        if (cfg["sgn"]) this.sign = cfg["sgn"];
    }

    /**
     * Encrypt with password, returns header
     * @param {string} method 
     * @param {Uint8Array} pw 
     * @param {Uint8Array} kf 
     * @returns {Uint8Array}
     */
    async encpw(method, pw, kf = new Uint8Array(0)) {
        // basic setup
        if (method !== "arg1" && method !== "pbk1") {
            throw new Error(`Unsupported method: ${method}`);
        }
        this.headAlgo = method;
        this.salt = random(16);
        if (this.size >= 0) {
            this.bodyKey = random(44);
        }
        const pwBytes = (typeof pw === 'string') ? strToU8(pw) : pw;
        const kfBytes = (typeof kf === 'string') ? strToU8(kf) : kf;
        const combinedPw = concat([pwBytes, kfBytes]);

        // get master key, make pwHash, hkey
        let mkey, hkey;
        if (method === "arg1") {
            const mkeyHashStr = await argon2Hash(combinedPw, this.salt);
            mkey = strToU8(mkeyHashStr);
            this.pwHash = genkey(mkey, "PWHASH_OPSEC_ARGON2", 32);
            hkey = genkey(mkey, "KEYGEN_OPSEC_ARGON2", 44);
        } else if (method === "pbk1") {
            mkey = await pbkdf2(combinedPw, this.salt);
            this.pwHash = genkey(mkey, "PWHASH_OPSEC_PBKDF2", 32);
            hkey = genkey(mkey, "KEYGEN_OPSEC_PBKDF2", 44);
        }

        // encrypt header
        const headData = this._wrapHead();
        const m = new AES1();
        this.encHeadData = await m.enAESGCM(hkey, headData);

        // wrap message
        const cfg = {};
        if (this.msg !== "") cfg["msg"] = this.msg;
        cfg["headal"] = this.headAlgo;
        cfg["salt"] = this.salt;
        cfg["pwh"] = this.pwHash;
        cfg["ehd"] = this.encHeadData;
        return encodeCfg(cfg);
    }

    /**
     * Encrypt with public key, returns header
     * @param {string} method 
     * @param {Uint8Array} publicBytes 
     * @param {Uint8Array|null} privateBytes // sign if privateBytes is not null
     * @returns {Uint8Array}
     */
    async encpub(method, publicBytes, privateBytes = null) {
        if (method !== "rsa1" && method !== "ecc1") {
            throw new Error(`Unsupported method: ${method}`);
        }
        this.headAlgo = method;
        if (this.size >= 0) {
            this.bodyKey = random(44);
        }

        // Sign if private key exists
        if (privateBytes !== null) {
            if (method === "rsa1") {
                const m = new RSA1();
                await m.loadkey(null, privateBytes);
                if (this.bodyKey.length > 0) this.sign = await m.sign(this.bodyKey);
                else if (this.smsg !== "") this.sign = await m.sign(strToU8(this.smsg));
            } else {
                const m = new ECC1();
                await m.loadkey(null, privateBytes);
                if (this.bodyKey.length > 0) this.sign = await m.sign(this.bodyKey);
                else if (this.smsg !== "") this.sign = await m.sign(strToU8(this.smsg));
            }
        }

        // Encrypt Header
        const headData = this._wrapHead();
        if (method === "rsa1") {
            const m = new RSA1();
            await m.loadkey(publicBytes, null);
            const hkey = random(44);
            this.encHeadKey = await m.encrypt(hkey);
            
            const aes = new AES1();
            this.encHeadData = await aes.enAESGCM(hkey, headData);
        } else if (method === "ecc1") {
            const m = new ECC1();
            await m.loadkey(publicBytes, null);
            this.encHeadData = await m.encrypt(headData);
        }

        // wrap message
        const cfg = {};
        if (this.msg !== "") cfg["msg"] = this.msg;
        cfg["headal"] = this.headAlgo;
        if (this.encHeadKey.length > 0) cfg["ehk"] = this.encHeadKey;
        cfg["ehd"] = this.encHeadData;
        return encodeCfg(cfg);
    }

    /**
     * load outer layer of header
     * @param {Uint8Array} data
     */
    view(data) {
        this.reset();
        const cfg = decodeCfg(data);
        if (cfg["msg"]) this.msg = u8ToStr(cfg["msg"]);
        if (cfg["headal"]) this.headAlgo = u8ToStr(cfg["headal"]);
        if (cfg["salt"]) this.salt = cfg["salt"];
        if (cfg["pwh"]) this.pwHash = cfg["pwh"];
        if (cfg["ehk"]) this.encHeadKey = cfg["ehk"];
        if (cfg["ehd"]) this.encHeadData = cfg["ehd"];
    }

    /**
     * Decrypt with password
     * @param {Uint8Array} pw 
     * @param {Uint8Array} kf 
     */
    async decpw(pw, kf = new Uint8Array(0)) {
        if (this.headAlgo === "") throw new Error("Call view() first");
        if (this.headAlgo !== "arg1" && this.headAlgo !== "pbk1") {
             throw new Error(`Unsupported method: ${this.headAlgo}`);
        }
        const pwBytes = (typeof pw === 'string') ? strToU8(pw) : pw;
        const kfBytes = (typeof kf === 'string') ? strToU8(kf) : kf;
        const combinedPw = concat([pwBytes, kfBytes]);

        // Derive key
        let mkey;
        let verify_lbl = "";
        let keygen_lbl = "";
        if (this.headAlgo === "arg1") {
            const mkeyHashStr = await argon2Hash(combinedPw, this.salt);
            mkey = strToU8(mkeyHashStr);
            verify_lbl = "PWHASH_OPSEC_ARGON2";
            keygen_lbl = "KEYGEN_OPSEC_ARGON2";
        } else {
            mkey = await pbkdf2(combinedPw, this.salt);
            verify_lbl = "PWHASH_OPSEC_PBKDF2";
            keygen_lbl = "KEYGEN_OPSEC_PBKDF2";
        }

        // check password
        const calc_hash = genkey(mkey, verify_lbl, 32);
        if (calc_hash.length !== this.pwHash.length) throw new Error("Incorrect password");
        let diff = 0;
        for(let i=0; i<calc_hash.length; i++) diff |= calc_hash[i] ^ this.pwHash[i];
        if (diff !== 0) throw new Error("Incorrect password");

        // decrypt header
        const hkey = genkey(mkey, keygen_lbl, 44);
        const m = new AES1();
        this._unwrapHead(await m.deAESGCM(hkey, this.encHeadData));
    }

    /**
     * Decrypt with private key
     * @param {Uint8Array} privateBytes 
     * @param {Uint8Array|null} publicBytes // verify sign if publicBytes is not null
     */
    async decpub(privateBytes, publicBytes = null) {
        if (this.headAlgo === "") throw new Error("Call view() first");
        if (this.headAlgo !== "rsa1" && this.headAlgo !== "ecc1") {
             throw new Error(`Unsupported method: ${this.headAlgo}`);
        }

        // decrypt header
        let decrypted_head;
        if (this.headAlgo === "rsa1") {
            const rsa = new RSA1();
            const aes = new AES1();
            await rsa.loadkey(null, privateBytes);
            const hkey = await rsa.decrypt(this.encHeadKey);
            decrypted_head = await aes.deAESGCM(hkey, this.encHeadData);
        } else {
            const ecc = new ECC1();
            await ecc.loadkey(null, privateBytes);
            decrypted_head = await ecc.decrypt(this.encHeadData);
        }
        this._unwrapHead(decrypted_head);

        // verify sign
        if (publicBytes !== null) {
            let s = new Uint8Array(0);
            if (this.bodyKey.length > 0) s = this.bodyKey;
            else if (this.smsg !== "") s = strToU8(this.smsg);

            let verified = false;
            if (this.headAlgo === "rsa1") {
                const m = new RSA1();
                await m.loadkey(publicBytes, null);
                verified = await m.verify(s, this.sign);
            } else {
                const m = new ECC1();
                await m.loadkey(publicBytes, null);
                verified = await m.verify(s, this.sign);
            }
            if (!verified) throw new Error(`${this.headAlgo.toUpperCase()} signature verification failed`);
        }
    }
}