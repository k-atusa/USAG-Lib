# test790a : USAG-Lib szip

import io
import os
import zipfile

class ZipWriter: # zip64 writer
    def __init__(self, output: str, compress: bool):
        self.output = io.BytesIO() if output == "" else open(output, "wb") # set output empty to write on memory
        self.zip = zipfile.ZipFile(self.output, "a", zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED, allowZip64=True) # create zip writer

    def writefile(self, name:str, path: str):
        self.zip.write(path, name)

    def writebin(self, name: str, data: bytes):
        self.zip.writestr(name, data)

    def close(self) -> bytes:
        self.zip.close()
        if type(self.output) == io.BytesIO:
            temp = self.output.getvalue()
            self.output.close()
            return temp
        else:
            self.output.close()
            return None

class ZipReader: # zip64 reader
    def __init__(self, input):
        self.input = io.BytesIO(input) if type(input) == bytes else open(input, "rb")
        self.zip = zipfile.ZipFile(self.input, "r", allowZip64=True) # create zip reader
        self._files = self.zip.infolist()
        self.names = [i.filename for i in self._files] # get names of files
        self.sizes = [i.file_size for i in self._files] # get sizes of files

    def read(self, idx: int) -> bytes:
        return self.zip.read(self._files[idx])
    
    def open(self, idx: int) -> io.IOBase:
        return self.zip.open(self._files[idx], "r")

    def close(self):
        self.zip.close()
        self.input.close()

def Pack(srcs: str | list[str], dst: str) -> None:
    if type(srcs) == str: srcs = [srcs]
    zw = ZipWriter(dst, True)
    try:
        for src in srcs:
            if os.path.isfile(src):
                zw.writefile(os.path.basename(src), src)
            elif os.path.isdir(src):
                parent = os.path.dirname(os.path.normpath(src))
                for root, dirs, files in os.walk(src):
                    rel_dir = os.path.relpath(root, parent).replace("\\", "/")
                    zw.writebin(rel_dir + "/", b"") # write directory entry
                    for f in files:
                        path = os.path.join(root, f)
                        rel = os.path.relpath(path, parent).replace("\\", "/")
                        zw.writefile(rel, path)
    finally:
        zw.close()

def Unpack(src: str, dst: str) -> None:
    zr = ZipReader(src)
    try:
        for i, name in enumerate(zr.names):
            rel_path = name.replace("\\", "/")
            dest_path = os.path.join(dst, rel_path)
            
            # ZipSlip Protection
            base = os.path.join(os.path.abspath(dst), "")
            if not os.path.abspath(dest_path).startswith(base):
                raise Exception(f"illegal file path: {rel_path}")

            if rel_path.endswith('/'):
                os.makedirs(dest_path, exist_ok=True)
            else:
                parent = os.path.dirname(dest_path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                
                with open(dest_path, "wb") as f_out:
                    with zr.open(i) as f_in:
                        while True:
                            chunk = f_in.read(65536)
                            if not chunk: break
                            f_out.write(chunk)
    finally:
        zr.close()