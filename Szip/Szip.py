# test790a : USAG-Lib szip

import io
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