# test792a : USAG-Lib star
import os
import io
import time

class TarWriter:
    def __init__(self, output: str):
        self.output = io.BytesIO() if output == "" else open(output, "wb") # set output empty to write on memory

    def _tar_header(self, name: str, size: int, mode: int, mtime: int, flag: bytes) -> bytes:
        h = bytearray(512)

        # Name (offset 0)
        name_b = name.encode('utf-8')[:100]
        h[0:len(name_b)] = name_b
        
        # Mode (100), Size (124) - oct format
        h[100:107] = f"{mode:07o}".encode()
        h[124:135] = f"{size:011o}".encode() if size < 0o77777777777 else b"00000000000"
        
        # Mtime (136) - current time
        h[136:147] = f"{mtime:011o}".encode()
        
        # Typeflag (156)
        h[156:157] = flag
        
        # Magic, Version (257)
        h[257:263] = b"ustar\x00"
        h[263:265] = b"00"
        
        # Checksum (148)
        h[148:156] = b"        "
        checksum = sum(h)
        h[148:154] = f"{checksum:06o}".encode()
        h[154:155] = b"\x00"
        return bytes(h)
    
    def _pax_header(self, name: str, size: int) -> bytes:
        pax_elements = []
        for key, value in [("path", name), ("size", str(size))]:
            line = f" {key}={value}\n" # make line
            length = len(line.encode('utf-8')) + 2
            while True: # calculate length
                full_line = f"{length}{line}"
                if len(full_line.encode('utf-8')) == length: break
                length = len(full_line.encode('utf-8'))
            pax_elements.append(full_line.encode('utf-8'))
        
        # make pax header
        pax_data = b"".join(pax_elements)
        return self._tar_header(f"PaxHeader/{name}", len(pax_data), 0o644, int(time.time()), b'x') + pax_data + self._pad(len(pax_data))

    def _pad(self, size: int) -> bytes:
        pad_size = (512 - (size % 512)) % 512
        return b'\0' * pad_size

    def WriteFile(self, name: str, path: str, mode: int = 0o644):
        size = os.path.getsize(path)
        # write pax header if long name or large size
        if len(name.encode('utf-8')) > 99 or size > 0o77777777777:
            self.output.write(self._pax_header(name, size))
        self.output.write(self._tar_header(name, size, mode, int(os.path.getmtime(path)), b'0'))

        # write file content
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk: break
                self.output.write(chunk)
        self.output.write(self._pad(size))

    def WriteDir(self, name: str, mode: int = 0o755):
        name = name.replace("\\", "/")
        if not name.endswith("/"):
            name += "/"
        if len(name.encode('utf-8')) > 99:
            self.output.write(self._pax_header(name, 0))
        self.output.write(self._tar_header(name, 0, mode, int(time.time()), b'5'))

    def WriteBin(self, name: str, data: bytes, mode: int = 0o644):
        size = len(data)
        if len(name.encode('utf-8')) > 99 or size > 0o77777777777:
            self.output.write(self._pax_header(name, size))
        self.output.write(self._tar_header(name, size, mode, int(time.time()), b'0'))
        self.output.write(data)
        self.output.write(self._pad(size))

    def Close(self) -> bytes:
        self.output.write(b"\x00" * 1024) # two 512-byte blocks of zeroes
        if isinstance(self.output, io.BytesIO):
            res = self.output.getvalue()
            self.output.close()
            self.output = None
            return res
        self.output.close()
        self.output = None
        return b""

class TarReader:
    def __init__(self, src: str|bytes):
        if isinstance(src, str):
            self.stream = open(src, "rb")
        elif isinstance(src, bytes):
            self.stream = io.BytesIO(src)
        else:
            self.stream = src

        # metadata of current entry
        self.Name = ""
        self.Size = 0
        self.Mode = 0o644
        self.IsDir = False
        self.IsEOF = False

    def _parse(self, data: bytes):
        lines = data.decode('utf-8', 'replace').split('\n')
        for line in lines: # format: "length key=value\n"
            if line == "": continue
            parts = line.split(' ', 1)
            if len(parts) < 2: continue
            kv = parts[1].split('=', 1)
            if len(kv) < 2: continue
            
            key, value = kv[0], kv[1] # update metadata by pax key-values
            if key == "path": self.Name = value
            elif key == "size": self.Size = int(value)

    def _unpad(self, size: int):
        pad = (512 - (size % 512)) % 512 # jump padding bytes
        if pad > 0: self.stream.read(pad)

    def Next(self) -> bool:
        if self.IsEOF: return False
        header = self.stream.read(512) # read next 512-byte header
        if header == None or len(header) != 512 or header == b'\0' * 512:
            self.IsEOF = True
            self.stream.read(512)
            return False

        # parse standard header
        self.Name = header[0:100].decode('utf-8', 'replace').rstrip('\0')
        self.Mode = int(header[100:108].strip(b'\x00 '), 8)
        self.Size = int(header[124:136].strip(b'\x00 '), 8)
        tp = header[156:157]
        self.IsDir = True if tp == b'5' else False

        # parse PAX header if type is 'x'
        if tp == b'x':
            pax_data = self.stream.read(self.Size)
            self._unpad(self.Size)
            self._parse(pax_data)
            tn, ts = self.Name, self.Size
            e = self.Next() # read next header after pax
            self.Name, self.Size = tn, ts
            return e
        return True

    def Read(self) -> bytes:
        data = self.stream.read(self.Size)
        self._unpad(self.Size)
        return data

    def Mkfile(self, path: str):
        if self.IsDir: # make directory
            os.makedirs(path, exist_ok=True)
            return
        with open(path, "wb") as f: # make file
            rem = self.Size
            while rem > 0:
                chunk = self.stream.read(min(rem, 65536))
                if len(chunk) == 0: break
                f.write(chunk)
                rem -= len(chunk)
        self._unpad(self.Size)

    def Skip(self):
        rem = self.Size
        while rem > 0:
            chunk = self.stream.read(min(rem, 65536))
            if len(chunk) == 0: break
            rem -= len(chunk)
        self._unpad(self.Size)

    def Close(self):
        self.stream.close()

def Pack(srcs: str | list[str], dst: str) -> None:
    if type(srcs) == str: srcs = [srcs]
    tw = TarWriter(dst)
    try:
        for src in srcs:
            if os.path.isfile(src):
                tw.WriteFile(os.path.basename(src), src)
            elif os.path.isdir(src):
                parent = os.path.dirname(os.path.normpath(src))
                for root, dirs, files in os.walk(src):
                    rel_dir = os.path.relpath(root, parent).replace("\\", "/")
                    tw.WriteDir(rel_dir)
                    for f in files:
                        path = os.path.join(root, f)
                        rel = os.path.relpath(path, parent).replace("\\", "/")
                        tw.WriteFile(rel, path)
    finally:
        tw.Close()

def Unpack(src: str, dst: str) -> None:
    tr = TarReader(src)
    try:
        while tr.Next():
            rel_path = tr.Name.replace("\\", "/")
            dest_path = os.path.join(dst, rel_path)
            
            # ZipSlip Protection
            base = os.path.join(os.path.abspath(dst), "")
            if not os.path.abspath(dest_path).startswith(base):
                raise Exception(f"illegal file path: {rel_path}")

            tr.Mkfile(dest_path)
    finally:
        tr.Close()