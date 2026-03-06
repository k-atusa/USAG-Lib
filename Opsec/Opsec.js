// test794b : USAG-Lib opsec
const BencryptURL = 'https://cdn.jsdelivr.net/gh/k-atusa/USAG-Lib/Bencrypt/Bencrypt.js';
const { Random, SHA3512, pbkdf2, argon2Hash, genkey, SymMaster, AsymMaster } = await import(BencryptURL);

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
export function Crc32(data) {
    const u8 = typeof data === 'string' ? strToU8(data) : data;
    let crc = -1;
    for (let i = 0; i < u8.length; i++) {
        crc = (crc >>> 8) ^ crcTable[(crc ^ u8[i]) & 0xFF];
    }
    crc = (crc ^ (-1)) >>> 0;

    // Return as Hex String (8 chars)
    const buf = new ArrayBuffer(4);
    const view = new DataView(buf);
    view.setUint32(0, crc, true); // little endian
    let hexStr = "";
    for (let i = 0; i < 4; i++) {
        hexStr += view.getUint8(i).toString(16).padStart(2, '0');
    }
    return hexStr;
}

/**
 * Little Endian Integer Encoding
 * @param {number} data 
 * @param {number} size 
 * @returns {Uint8Array}
 */
export function EncodeInt(data, size) {
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
export function DecodeInt(data) {
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
export function EncodeCfg(data) {
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
            chunks.push(EncodeInt(dataLen, 2));
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
export function DecodeCfg(data) {
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
            dataLen = DecodeInt(lenBytes);
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
export class Opsec {
    constructor() {
        this.Reset();
    }

    Reset() {
        // Outer Layer
        this.Msg = "";                        // non-secured message
        this._headAlgo = "";                   // header algorithm, [arg1 pbk1 rsa1 ecc1]
        this._salt = new Uint8Array(0);        // salt
        this._pwHash = new Uint8Array(0);      // pw hash
        this._encHeadKey = new Uint8Array(0);  // encrypted header key
        this._encHeadData = new Uint8Array(0); // encrypted header data

        // Inner Layer
        this.Smsg = "";                   // secured message
        this.Size = -1;                   // full body size, flag for bodyKey generation
        this.Name = "";                   // body name
        this.BodyKey = new Uint8Array(0); // body key
        this.BodyAlgo = "";               // body algorithm, [gcm1 gcmx1]
        this.ContAlgo = "";               // container algorithm, [zip1 tar1]
        this._sign = new Uint8Array(0);    // signature
    }

    /**
     * read stream, returns Opsec header
     * @param {Object} ins // Object with async read(size)
     * @param {number} cut 
     * @returns {Uint8Array}
     */
    async Read(ins, cut = 65535) {
        let c = 0;
        while (true) {
            const data = await ins.read(4);
            c += 4;
            if (data.length === 0) return new Uint8Array(0);

            const magic = u8ToStr(data);
            if (magic === "YAS2") {
                const sizeBuf = await ins.read(2);
                let size = DecodeInt(sizeBuf);
                if (size === 65535) {
                    const extSizeBuf = await ins.read(2);
                    size += DecodeInt(extSizeBuf);
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
    async Write(outs, head) {
        await outs.write(strToU8("YAS2"));
        const size = head.length;
        if (size < 65535) {
            await outs.write(EncodeInt(size, 2));
        } else if (size <= 65535 * 2) {
            await outs.write(EncodeInt(65535, 2));
            await outs.write(EncodeInt(size - 65535, 2));
        } else {
            throw new Error(`Data size too big: ${size}`);
        }
        await outs.write(head);
    }

    _wrapHead() {
        const cfg = {};
        if (this.Smsg !== "") cfg["smsg"] = this.Smsg;
        if (this.Size >= 0) {
            if (this.Size < 65536) cfg["sz"] = EncodeInt(this.Size, 2);
            else if (this.Size < 4294967296) cfg["sz"] = EncodeInt(this.Size, 4);
            else cfg["sz"] = EncodeInt(this.Size, 8);
        }
        if (this.Name !== "") cfg["nm"] = this.Name;
        if (this.BodyKey.length > 0) cfg["bkey"] = this.BodyKey;
        if (this.BodyAlgo !== "") cfg["bodyal"] = this.BodyAlgo;
        if (this.ContAlgo !== "") cfg["contal"] = this.ContAlgo;
        if (this._sign.length > 0) cfg["sgn"] = this._sign;
        return EncodeCfg(cfg);
    }

    _unwrapHead(data) {
        const cfg = DecodeCfg(data);
        if (cfg["smsg"]) this.Smsg = u8ToStr(cfg["smsg"]);
        if (cfg["sz"]) this.Size = DecodeInt(cfg["sz"]);
        if (cfg["nm"]) this.Name = u8ToStr(cfg["nm"]);
        if (cfg["bkey"]) this.BodyKey = cfg["bkey"];
        if (cfg["bodyal"]) this.BodyAlgo = u8ToStr(cfg["bodyal"]);
        if (cfg["contal"]) this.ContAlgo = u8ToStr(cfg["contal"]);
        if (cfg["sgn"]) this._sign = cfg["sgn"];
    }

    /**
     * Encrypt with password, returns header
     * @param {string} method 
     * @param {Uint8Array} pw 
     * @param {Uint8Array} kf 
     * @returns {Uint8Array}
     */
    async Encpw(method, pw, kf = new Uint8Array(0)) {
        // basic setup
        this._headAlgo = method;
        this._salt = Random(16);
        if (this.Size >= 0) {
            this.BodyKey = Random(44);
        }
        const pwBytes = (typeof pw === 'string') ? strToU8(pw) : pw;
        const kfBytes = (typeof kf === 'string') ? strToU8(kf) : kf;
        const combinedPw = concat([pwBytes, kfBytes]);

        // get master key, make pwHash, hkey
        let mkey, hkey;
        if (method === "sha3") {
            mkey = SHA3512(concat(this._salt, combinedPw));
            this._pwHash = genkey(mkey, "PWHASH_OPSEC_SHA3512", 32);
            hkey = genkey(mkey, "KEYGEN_OPSEC_SHA3512", 44);
        } else if (method === "pbk1") {
            mkey = await pbkdf2(combinedPw, this._salt);
            this._pwHash = genkey(mkey, "PWHASH_OPSEC_PBKDF2", 32);
            hkey = genkey(mkey, "KEYGEN_OPSEC_PBKDF2", 44);
        } else if (method === "arg1") {
            const mkeyHashStr = await argon2Hash(combinedPw, this._salt);
            mkey = strToU8(mkeyHashStr);
            this._pwHash = genkey(mkey, "PWHASH_OPSEC_ARGON2", 32);
            hkey = genkey(mkey, "KEYGEN_OPSEC_ARGON2", 44);
        } else {
            throw new Error(`Unsupported method: ${method}`);
        }

        // encrypt header
        const headData = this._wrapHead();
        const sm = new SymMaster("gcm1", hkey);
        this._encHeadData = await sm.EnBin(headData);

        // wrap message
        const cfg = {};
        if (this.Msg !== "") cfg["msg"] = this.Msg;
        cfg["headal"] = this._headAlgo;
        cfg["salt"] = this._salt;
        cfg["pwh"] = this._pwHash;
        cfg["ehd"] = this._encHeadData;
        return EncodeCfg(cfg);
    }

    /**
     * Encrypt with public key, returns header
     * @param {string} method 
     * @param {Uint8Array} publicBytes 
     * @param {Uint8Array|null} privateBytes // sign if privateBytes is not null
     * @returns {Uint8Array}
     */
    async Encpub(method, publicBytes, privateBytes = null) {
        this._headAlgo = method;
        if (this.Size >= 0) {
            this.BodyKey = Random(44);
        }

        // Init Master & Sign
        const am = new AsymMaster(method);
        await am.Loadkey(publicBytes, privateBytes);
        if (privateBytes !== null) {
            if (this.BodyKey.length > 0) this._sign = await am.Sign(this.BodyKey);
            else if (this.Smsg !== "") this._sign = await am.Sign(strToU8(this.Smsg));
        }

        // Encrypt Header
        const headData = this._wrapHead();
        if (method === "rsa1" || method === "rsa2") {
            // RSA Hybrid: Encrypt Key with RSA, Data with AES
            const hkey = Random(44);
            this._encHeadKey = await am.Encrypt(hkey);
            const sm = new SymMaster("gcm1", hkey);
            this._encHeadData = await sm.EnBin(headData);
        } else if (method === "ecc1") {
            // ECC Hybrid: Handled internally by ECC1 class
            this._encHeadData = await am.Encrypt(headData);
        } else {
            throw new Error(`Unsupported method: ${method}`);
        }

        // wrap message
        const cfg = {};
        if (this.Msg !== "") cfg["msg"] = this.Msg;
        cfg["headal"] = this._headAlgo;
        if (this._encHeadKey.length > 0) cfg["ehk"] = this._encHeadKey;
        cfg["ehd"] = this._encHeadData;
        return EncodeCfg(cfg);
    }

    /**
     * load outer layer of header
     * @param {Uint8Array} data
     */
    View(data) {
        this.Reset();
        const cfg = DecodeCfg(data);
        if (cfg["msg"]) this.Msg = u8ToStr(cfg["msg"]);
        if (cfg["headal"]) this._headAlgo = u8ToStr(cfg["headal"]);
        if (cfg["salt"]) this._salt = cfg["salt"];
        if (cfg["pwh"]) this._pwHash = cfg["pwh"];
        if (cfg["ehk"]) this._encHeadKey = cfg["ehk"];
        if (cfg["ehd"]) this._encHeadData = cfg["ehd"];
    }

    /**
     * Decrypt with password
     * @param {Uint8Array} pw 
     * @param {Uint8Array} kf 
     */
    async Decpw(pw, kf = new Uint8Array(0)) {
        if (this._headAlgo === "") throw new Error("Call view() first");
        const pwBytes = (typeof pw === 'string') ? strToU8(pw) : pw;
        const kfBytes = (typeof kf === 'string') ? strToU8(kf) : kf;
        const combinedPw = concat([pwBytes, kfBytes]);

        // Derive key
        let mkey;
        let verify_lbl = "";
        let keygen_lbl = "";
        if (this._headAlgo === "sha3") {
            mkey = SHA3512(concat(this._salt, combinedPw));
            verify_lbl = "PWHASH_OPSEC_SHA3512";
            keygen_lbl = "KEYGEN_OPSEC_SHA3512";
        } else if (this._headAlgo === "pbk1") {
            mkey = await pbkdf2(combinedPw, this._salt);
            verify_lbl = "PWHASH_OPSEC_PBKDF2";
            keygen_lbl = "KEYGEN_OPSEC_PBKDF2";
        } else if (this._headAlgo === "arg1") {
            const mkeyHashStr = await argon2Hash(combinedPw, this._salt);
            mkey = strToU8(mkeyHashStr);
            verify_lbl = "PWHASH_OPSEC_ARGON2";
            keygen_lbl = "KEYGEN_OPSEC_ARGON2";
        } else {
            throw new Error(`Unsupported method: ${this._headAlgo}`);
        }

        // check password
        const calc_hash = genkey(mkey, verify_lbl, 32);
        if (calc_hash.length !== this._pwHash.length) throw new Error("Incorrect password");
        let diff = 0;
        for (let i = 0; i < calc_hash.length; i++) diff |= calc_hash[i] ^ this._pwHash[i];
        if (diff !== 0) throw new Error("Incorrect password");

        // decrypt header
        const hkey = genkey(mkey, keygen_lbl, 44);
        const sm = new SymMaster("gcm1", hkey);
        this._unwrapHead(await sm.DeBin(this._encHeadData));
    }

    /**
     * Decrypt with private key
     * @param {Uint8Array} privateBytes 
     * @param {Uint8Array|null} publicBytes // verify sign if publicBytes is not null
     */
    async Decpub(privateBytes, publicBytes = null) {
        if (this._headAlgo === "") throw new Error("Call view() first");
        const am = new AsymMaster(this._headAlgo);
        await am.Loadkey(publicBytes, privateBytes);
        let decrypted_head;

        // decrypt header
        if (this._headAlgo === "rsa1" || this._headAlgo === "rsa2") {
            const hkey = await am.Decrypt(this._encHeadKey);
            const sm = new SymMaster("gcm1", hkey);
            decrypted_head = await sm.DeBin(this._encHeadData);
        } else if (this._headAlgo === "ecc1") {
            decrypted_head = await am.Decrypt(this._encHeadData);
        } else {
            throw new Error(`Unsupported method: ${this._headAlgo}`);
        }
        this._unwrapHead(decrypted_head);

        // verify sign
        if (publicBytes !== null) {
            let s = new Uint8Array(0);
            if (this.BodyKey.length > 0) s = this.BodyKey;
            else if (this.Smsg !== "") s = strToU8(this.Smsg);
            const verified = await am.Verify(s, this._sign);
            if (!verified) throw new Error(`${this._headAlgo.toUpperCase()} signature verification failed`);
        }
    }
}