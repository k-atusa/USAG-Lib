// test792b : USAG-Lib star
// !!! JS version is not designed for big data !!!

const isNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null;
let fs;
if (isNode) {
    fs = require('fs');
}

class TarWriter {
    /**
     * @param {string} output set empty for memory, filepath(Node) or filename(Browser)
     */
    constructor(output) {
        this.outputStr = output;
        this.blocks = [];
        this.isMemory = (output === "");
        this.encoder = new TextEncoder();
    }

    /**
     * @param {string} name file name in tar
     * @param {string|Blob|File|Uint8Array} src file path (Node) or Blob/File object (Browser)
     * @param {boolean} isDir set true for directory
     */
    async write(name, src, isDir) {
        let data;
        
        // load data from src if not directory
        if (isDir) {
            name = name.replace(/\/?$/, '/');
            if (!name.endsWith('/')) name += '/';
            data = new Uint8Array(0);
        } else if (isNode) {
            if (typeof src === 'string') {
                data = await fs.promises.readFile(src);
            } else {
                data = src; 
            }
        } else {
            if (src instanceof Blob) {
                const arrayBuffer = await src.arrayBuffer();
                data = new Uint8Array(arrayBuffer);
            } else if (src instanceof Uint8Array) {
                data = src;
            } else {
                throw new Error("write in browser needs Blob or Uint8Array");
            }
        }
        
        if (isNode && Buffer.isBuffer(data)) {
            data = new Uint8Array(data);
        }
        this._add(name, data, isDir);
    }

    async close() {
        // Two 512-byte blocks of zeroes to mark end of archive
        this.blocks.push(new Uint8Array(512));
        this.blocks.push(new Uint8Array(512));

        let totalSize = 0; // join blocks
        for (const b of this.blocks) {
            totalSize += b.length;
        }
        const result = new Uint8Array(totalSize);
        let offset = 0;
        for (const b of this.blocks) {
            result.set(b, offset);
            offset += b.length;
        }
        this.blocks = [];

        if (this.isMemory) {
            return result;
        } else {
            if (isNode) {
                fs.writeFileSync(this.outputStr, result);
            } else {
                this._browserDownload(result, this.outputStr || "archive.tar");
            }
        }
        return null;
    }

    _add(name, data, isDir) {
        let needPax = false; // PAX condition check
        if (this.encoder.encode(name).length > 99 || data.length > 0o77777777777) {
            needPax = true;
        }

        if (needPax) { // Write PAX Header if needed
            let pax = this._createPax(name, data.length)
            this.blocks.push(this._createHeader("PaxHeader/" + name, pax.length, 'x'));
            this.blocks.push(pax);
            let pad = this._createPad(pax.length);
            if (pad != null) {
                this.blocks.push(pad);
            }
        }
        this.blocks.push(this._createHeader(name, data.length, isDir ? '5' : '0')); // Write USTAR Header
        if (!isDir) {
            this.blocks.push(data); // Write File Data
            let pad = this._createPad(data.length);
            if (pad != null) {
                this.blocks.push(pad);
            }
        }
    }

    _createPad(size) {
        const padSize = (512 - (size % 512)) % 512;
        let data = null;
        if (padSize > 0) {
            data = new Uint8Array(padSize);
        }
        return data;
    }

    _createPax(name, size) {
        let records = ""; // Format: "length keyword=value\n"
        let data = [["path", name], ["size", size.toString()]];
        for (const pair of data) {
            const key = pair[0];
            const value = pair[1];
            let lenStr = "0"; 
            let totalLen = 0;
            
            while (true) { // retry until length is valid
                totalLen = lenStr.length + 1 + key.length + 1 + value.length + 1;
                const newLenStr = totalLen.toString();
                if (newLenStr.length === lenStr.length) {
                    lenStr = newLenStr;
                    break;
                }
                lenStr = newLenStr; // retry with new length
            }
            records += `${lenStr} ${key}=${value}\n`;
        }
        return this.encoder.encode(records);
    }

    _createHeader(name, size, typeflag) {
        const header = new Uint8Array(512);
        header.fill(0);
        const mtime = Math.floor(Date.now() / 1000);
        if (size > 0o77777777777) {
            size = 0 // Will be set by PAX
        }
        
        // Name (0-100)
        this._writeString(header, 0, name, 100);

        // Mode (100-108) - 0644
        this._writeOctal(header, 100, 0o644, 8);

        // Size (124-136)
        this._writeOctal(header, 124, size, 12);

        // MTime (136-148)
        this._writeOctal(header, 136, mtime, 12);

        // Checksum (148-156) - calculated later
        for(let i=148; i<156; i++) header[i] = 32; // Spaces

        // Typeflag (156)
        header[156] = typeflag.charCodeAt(0);

        // Magic (257-263) - "ustar"
        this._writeString(header, 257, "ustar", 6);
        
        // Version (263-265) - "00"
        this._writeString(header, 263, "00", 2);

        // Calculate Checksum
        let sum = 0;
        for (let i = 0; i < 512; i++) sum += header[i];
        const chksumStr = sum.toString(8).padStart(6, '0');
        for(let i=0; i<6; i++) header[148+i] = chksumStr.charCodeAt(i);
        header[154] = 0;
        header[155] = 32;
        return header;
    }

    _writeString(buf, offset, str, len) {
        const encoded = this.encoder.encode(str);
        for (let i = 0; i < len; i++) {
            buf[offset + i] = (i < encoded.length) ? encoded[i] : 0;
        }
    }

    _writeOctal(buf, offset, num, len) {
        const str = num.toString(8).padStart(len - 1, '0');
        for (let i = 0; i < len - 1; i++) {
            buf[offset + i] = str.charCodeAt(i);
        }
        buf[offset + len - 1] = 0;
    }

    _browserDownload(data, filename) {
        const blob = new Blob([data], { type: "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.style.display = "none";
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        
        setTimeout(() => {
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }, 100);
    }
}

class TarReader {
    /**
     * @param {string|Blob|Uint8Array} input set empty for memory, filepath(Node) or filename(Browser)
     */
    constructor(input) {
        this.input = input;
        this.data = null;
        this.decoder = new TextDecoder();
        this.files = null; // {name, size, offset, isDir}
    }

    async init() {
        // load data
        if (isNode && typeof this.input === 'string') {
            this.data = await fs.promises.readFile(this.input);
        } else if (typeof this.input === 'object' && this.input instanceof Blob) {
            const buffer = await this.input.arrayBuffer();
            this.data = new Uint8Array(buffer);
        } else if (this.input instanceof Uint8Array) {
            this.data = this.input;
        } else {
            throw new Error("Invalid input type");
        }
        let current = 0;
        this.files = [];

        // metadata
        let wasPax = false;
        let name = "";
        let size = 0;
        let isDir = false;

        while (current + 512 <= this.data.length) {
            let isZero = true;
            for(let i=0; i<512; i++) {
                if (this.data[current + i] !== 0) {
                    isZero = false;
                    break;
                }
            }
            if (isZero) break; // End of archive

            // name, size info
            let tsize = this._readOctal(this.data.subarray(current + 124, current + 136));
            if (!wasPax) {
                name = this._readString(this.data.subarray(current, current + 100));
                size = tsize;
            }

            // typeflag info
            const typeflag = String.fromCharCode(this.data[current + 156]);
            if (typeflag === 'x') { // PAX header
                const paxData = this.data.subarray(current + 512, current + 512 + tsize);
                const pax = this._parsePax(paxData);
                name = pax.name;
                size = pax.size;
                current += 512 + Math.ceil(tsize / 512) * 512;
                wasPax = true;
                continue; // Skip to next header
            } else if (typeflag === '5') { // Directory
                isDir = true;
            }
            this.files.push({
                name: name,
                size: size,
                offset: current + 512,
                isDir: isDir
            });

            // Move to next header
            current += 512 + Math.ceil(size / 512) * 512;
            wasPax = false;
            name = "";
            size = 0;
            isDir = false;
        }
    }

    read(idx) {
        if (idx < 0 || idx >= this.files.length) throw new Error("Index out of bounds");
        const file = this.files[idx];
        return this.data.subarray(file.offset, file.offset + file.size);
    }

    close() {
        this.input = null;
        this.data = null;
        this.files = [];
    }

    _readString(bytes) {
        let end = bytes.indexOf(0);
        if (end === -1) end = bytes.length;
        return this.decoder.decode(bytes.subarray(0, end));
    }

    _readOctal(bytes) {
        let str = this.decoder.decode(bytes);
        str = str.replace(/\0/g, '').trim(); 
        return parseInt(str, 8) || 0;
    }

    _parsePax(data) {
        const str = this.decoder.decode(data); // Format: length keyword=value\n
        let path = "";
        let size = 0;
        let pos = 0;
        while (pos < str.length) {
            const spaceIdx = str.indexOf(' ', pos);
            if (spaceIdx === -1) break;
            const eqIdx = str.indexOf('=', spaceIdx);
            if (eqIdx === -1) break;
            const lfIdx = str.indexOf('\n', eqIdx);
            if (lfIdx === -1) break;
            pos = lfIdx + 1;

            const key = str.substring(spaceIdx + 1, eqIdx);
            const value = str.substring(eqIdx + 1, lfIdx);
            if (key === 'path') path = value;
            else if (key === 'size') size = parseInt(value, 10);
        }
        return { name: path, size: size };
    }
}