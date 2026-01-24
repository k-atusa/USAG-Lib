# test795 : YAS2-test

import os

import Icons
import Bencode
import Bencrypt
import Star
import Szip
import Opsec

def dozip_z(files: list[str], output: str):
    writer = Szip.ZipWriter(output, True) # compress=True
    for path in files:
        clean_path = path.rstrip('/\\')
        if not os.path.exists(clean_path): continue

        if os.path.isfile(clean_path): # file
            writer.writefile(os.path.basename(clean_path), clean_path)
        elif os.path.isdir(clean_path): # directory
            parent_dir = os.path.dirname(clean_path)
            for root, dirs, files_in_dir in os.walk(clean_path, topdown=True):
                rel_root = os.path.relpath(root, parent_dir).replace('\\', '/')
                writer.writebin(rel_root + "/", b"") # write itself
                for file in files_in_dir: # write files
                    full_path = os.path.join(root, file)
                    rel_file = os.path.relpath(full_path, parent_dir).replace('\\', '/')
                    writer.writefile(rel_file, full_path)
    writer.close()

def unzip_z(input_path: str, target_dir: str):
    os.makedirs(target_dir, exist_ok=True)
    reader = Szip.ZipReader(input_path)
    for i, name in enumerate(reader.names):
        clean_name = name.replace('\\', '/')
        out_path = os.path.join(target_dir, clean_name)
        
        if clean_name.endswith("/"): # directory
            os.makedirs(out_path, exist_ok=True)
        else: # file
            with reader.open(i) as src:
                with open(out_path, "wb") as dst:
                    while True:
                        chunk = src.read(65536)
                        if not chunk: break
                        dst.write(chunk)
    reader.close()

def dozip_t(files: list[str], output: str):
    writer = Star.TarWriter(output)
    for path in files:
        clean_path = path.rstrip('/\\')
        if not os.path.exists(clean_path): continue

        if os.path.isfile(clean_path): # file
            writer.writeFile(os.path.basename(clean_path), clean_path)
        elif os.path.isdir(clean_path): # directory
            parent_dir = os.path.dirname(clean_path)
            for root, dirs, files_in_dir in os.walk(clean_path, topdown=True):
                rel_root = os.path.relpath(root, parent_dir).replace('\\', '/')
                writer.writeDir(rel_root) # write itself
                for file in files_in_dir: # write files
                    full_path = os.path.join(root, file)
                    rel_file = os.path.relpath(full_path, parent_dir).replace('\\', '/')
                    writer.writeFile(rel_file, full_path)
    writer.close()

def unzip_t(input_path: str, target_dir: str):
    os.makedirs(target_dir, exist_ok=True)
    reader = Star.TarReader(input_path)
    while reader.next():
        clean_name = reader.name.replace('\\', '/')
        out_path = os.path.join(target_dir, clean_name)
        reader.mkfile(out_path)
    reader.close()

class App:
    def __init__(self):
        self.msg: str = ""
        self.smsg: str = ""
        self.files: list[str] = []
        self.isLegacy: bool = False
        self.isZip: bool = False

        self.ico = Icons.Icons()
        self.header: bytes = b""

    def genkey(self, bits: int):
        if bits == 0:
            m = Bencrypt.ECC1()
            pub, pri = m.genkey()
        else:
            m = Bencrypt.RSA1()
            pub, pri = m.genkey(bits)
        m = Bencode.Bencode()
        pub, pri = m.encode(pub, self.isLegacy), m.encode(pri, self.isLegacy)
        with open("public.txt", "w", encoding="utf-8") as f:
            f.write(pub)
        with open("private.txt", "w", encoding="utf-8") as f:
            f.write(pri)

    def encrypt_pw(self, pw: bytes, kf: bytes) -> str:
        m = Opsec.Opsec()
        m.msg = self.msg
        m.smsg = self.smsg
        aes = Bencrypt.AES1()

        mode = 0
        prehead = self.ico.aes_webp()
        prehead = prehead + b"\x00" * (128 - len(prehead) % 128)
        
        # distinguish mode
        if len(self.files) == 0: # msg-only mode
            mode = 0
            prehead = b""
        elif len(self.files) == 1 and os.path.isfile(self.files[0]) and os.path.getsize(self.files[0]) < 10485760: # single file
            mode = 1
            m.size = os.path.getsize(self.files[0]) + 16
            m.name = os.path.basename(self.files[0])
            m.bodyAlgo = "gcm1"
            with open(self.files[0], "rb") as f:
                tgt = f.read()
        else: # multiple files
            mode = 2
            if self.isZip:
                dozip_z(self.files, "temp")
                m.contAlgo = "zip1"
            else:
                dozip_t(self.files, "temp")
                m.contAlgo = "tar1"
            s0 = os.path.getsize("temp")
            s1 = s0 // 1048576 if s0 % 1048576 == 0 and s0 != 0 else s0 // 1048576 + 1
            m.size = s0 + 16 * s1
            m.bodyAlgo = "gcmx1"

        # generate header, return if mode == 0
        header_bytes = m.encpw("pbk1", pw, kf) if self.isLegacy else m.encpw("arg1", pw, kf)
        if mode == 0:
            return Bencode.Bencode().encode(header_bytes, self.isLegacy)

        # write to output.webp
        outs = open("output.webp", "wb")
        outs.write(prehead)
        m.write(outs, header_bytes)

        # body encryption
        if mode == 1:
            enc_body = aes.enAESGCM(m.bodyKey, tgt)
            outs.write(enc_body)
        elif mode == 2:
            with open("temp", "rb") as f_in:
                aes.enAESGCMx(m.bodyKey, f_in, m.size, outs)
            if os.path.exists("temp"): os.remove("temp")
        outs.close()
        return "output.webp"
    
    def encrypt_pub(self, public: str, private: str) -> str:
        m = Opsec.Opsec()
        m.msg = self.msg
        m.smsg = self.smsg
        aes = Bencrypt.AES1()

        ec = Bencode.Bencode()
        with open(public, "r", encoding="utf-8") as f:
            public = ec.decode(f.read())
        if private == "":
            private = None
        else:
            with open(private, "r", encoding="utf-8") as f:
                private = ec.decode(f.read())

        mode = 0
        prehead = self.ico.aes_webp()
        prehead = prehead + b"\x00" * (128 - len(prehead) % 128)
        
        # distinguish mode
        if len(self.files) == 0: # msg-only mode
            mode = 0
            prehead = b""
        elif len(self.files) == 1 and os.path.isfile(self.files[0]) and os.path.getsize(self.files[0]) < 10485760: # single file
            mode = 1
            m.size = os.path.getsize(self.files[0]) + 16
            m.name = os.path.basename(self.files[0])
            m.bodyAlgo = "gcm1"
            with open(self.files[0], "rb") as f:
                tgt = f.read()
        else: # multiple files
            mode = 2
            if self.isZip:
                dozip_z(self.files, "temp")
                m.contAlgo = "zip1"
            else:
                dozip_t(self.files, "temp")
                m.contAlgo = "tar1"
            s0 = os.path.getsize("temp")
            s1 = s0 // 1048576 if s0 % 1048576 == 0 and s0 != 0 else s0 // 1048576 + 1
            m.size = s0 + 16 * s1
            m.bodyAlgo = "gcmx1"

        # generate header, return if mode == 0
        header_bytes = m.encpub("rsa1" if self.isLegacy else "ecc1", public, private)
        if mode == 0:
            return Bencode.Bencode().encode(header_bytes, self.isLegacy)

        # write to output.webp
        outs = open("output.webp", "wb")
        outs.write(prehead)
        m.write(outs, header_bytes)

        # body encryption
        if mode == 1:
            enc_body = aes.enAESGCM(m.bodyKey, tgt)
            outs.write(enc_body)
        elif mode == 2:
            with open("temp", "rb") as f_in:
                aes.enAESGCMx(m.bodyKey, f_in, m.size, outs)
            if os.path.exists("temp"): os.remove("temp")
        outs.close()
        return "output.webp"
    
    def view(self, input_path: str) -> dict:
        m = Opsec.Opsec()
        with open(input_path, "rb") as f:
            header_data = m.read(f) # find header
        if not header_data:
            raise ValueError("YAS2 header not found")
            
        m.view(header_data)
        self.msg = m.msg
        self.header = header_data

    def decrypt_pw(self, input_path: str, pw: bytes, kf: bytes) -> str:
        m = Opsec.Opsec()
        aes = Bencrypt.AES1()

        with open(input_path, "rb") as f:
            # find header, decrypt header
            header_data = m.read(f)
            m.view(header_data)
            m.decpw(pw, kf)
            self.smsg = m.smsg
            
            # decrypt body
            if m.bodyKey != b"":
                if m.bodyAlgo == "gcm1":
                    body_data = f.read()
                    dec_data = aes.deAESGCM(m.bodyKey, body_data)
                    with open("temp", "wb") as tf:
                        tf.write(dec_data)
                elif m.bodyAlgo == "gcmx1":
                    with open("temp", "wb") as tf:
                        aes.deAESGCMx(m.bodyKey, f, m.size, tf)
                
                # unzip
                if m.contAlgo == "zip1":
                    unzip_z("temp", "./")
                    os.remove("temp")
                elif m.contAlgo == "tar1":
                    unzip_t("temp", "./")
                    os.remove("temp")
                else: # rename
                    os.rename("temp", m.name)
        return self.smsg

    def decrypt_pub(self, input_path: str, public_file: str, private_file: str) -> str:
        m = Opsec.Opsec()
        aes = Bencrypt.AES1()
        ec = Bencode.Bencode()
        
        # load keys
        with open(public_file, "r", encoding="utf-8") as f:
            pub_key = ec.decode(f.read())
        with open(private_file, "r", encoding="utf-8") as f:
            pri_key = ec.decode(f.read())
            
        with open(input_path, "rb") as f:
            # find header, decrypt header
            header_data = m.read(f)
            m.view(header_data)
            m.decpub(pri_key, pub_key)
            self.smsg = m.smsg
            
            if m.bodyKey != b"":
                # decrypt body
                if m.bodyAlgo == "gcm1":
                    body_data = f.read()
                    dec_data = aes.deAESGCM(m.bodyKey, body_data)
                    with open("temp", "wb") as tf:
                        tf.write(dec_data)
                elif m.bodyAlgo == "gcmx1":
                    with open("temp", "wb") as tf:
                        aes.deAESGCMx(m.bodyKey, f, m.size, tf)
                
                # unzip
                if m.contAlgo == "zip1":
                    unzip_z("temp", "./")
                    os.remove("temp")
                elif m.contAlgo == "tar1":
                    unzip_t("temp", "./")
                    os.remove("temp")
                else: # rename
                    os.rename("temp", m.name)
        return self.smsg