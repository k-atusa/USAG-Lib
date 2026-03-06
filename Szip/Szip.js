// test790b : USAG-Lib szip
// !!! JS version is  not designed for big data !!!
const isNode = (typeof window === 'undefined');
const fs = isNode ? (await import('fs')).default : null;
const JSZip = isNode ? (await import('jszip')).default : (await import('https://cdn.skypack.dev/jszip')).default;

export class ZipWriter { // Zip64 Writer
    /**
     * @param {string} output set empty for memory, filepath(Node) or filename(Browser)
     * @param {boolean} compress compress flag
    */
    constructor(output, compress) {
        this.outputStr = output;
        this.compress = compress;
        this.zip = new JSZip();
        this.isMemory = (output === "");
    }

    /**
     * @param {string} name file name in zip
     * @param {string|Blob|File} src file path (Node) or Blob/File object (Browser)
     */
    async WriteFile(name, src) {
        if (isNode) {
            if (typeof src === 'string') {
                const data = await fs.readFile(src);
                this.WriteBin(name, data);
            } else {
                this.WriteBin(name, src); // write Blob
            }
        } else {
            if (src instanceof Blob) {
                this.WriteBin(name, src); // write Blob or File
            } else {
                throw new Error("writefile in browser needs Blob object");
            }
        }
    }

    /**
     * @param {string} name file name in zip
     * @param {Uint8Array|string|Blob} data binary data
     */
    WriteBin(name, data) {
        const options = {
            compression: this.compress ? "DEFLATE" : "STORE"
        };
        this.zip.file(name, data, options);
    }

    async Close() {
        // Generate Zip
        const zipData = await this.zip.generateAsync({
            type: isNode ? "nodebuffer" : "uint8array",
            compression: this.compress ? "DEFLATE" : "STORE"
        });
        const result = new Uint8Array(zipData.length);
        result.set(zipData, 0);
        this.zip = null;

        if (this.isMemory) {
            return result;
        } else {
            if (isNode) {
                fs.writeFileSync(this.outputStr, result); // write file (Node)
            } else {
                this._browserDownload(result, this.outputStr || "archive.z64"); // download (Browser)
            }
        }
        return null;
    }

    _browserDownload(data, filename) { // browser download helper
        const blob = new Blob([data], { type: "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.style.display = "none";
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        
        // Cleanup
        setTimeout(() => {
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }, 100);
    }
}

export class ZipReader { // Zip64 Reader
    /**
     * @param {string|Blob|Uint8Array} input path string (Node), Blob or Uint8Array (Browser)
     */
    constructor(input) {
        this.input = input;
        this.zip = null;
        this.Names = [];
        this.Sizes = [];
        this._files = [];
    }

    async Init() {
        // load zip data to memory
        let dataToLoad;
        if (isNode && typeof this.input === 'string') {
            dataToLoad = fs.readFileSync(this.input);
        } else {
            dataToLoad = this.input;
        }
        this.zip = await JSZip.loadAsync(dataToLoad);
        
        this.Names = [];
        this.Sizes = [];
        this._files = [];
        this.zip.forEach((relativePath, file) => {
            this.Names.push(file.name);
            this.Sizes.push(file._data.uncompressedSize);
            this._files.push(file);
        });
    }

    async Read(idx) {
        if (!this.zip) await this.Init();
        if (idx < 0 || idx >= this._files.length) throw new Error("Index out of bounds");
        return await this._files[idx].async("uint8array");
    }

    Close() {
        this.zip = null;
        this.Names = [];
        this.Sizes = [];
        this._files = [];
    }
}
