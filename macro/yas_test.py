# test797 : project USAG YAS-test

import os
import sys
import argparse
import socket
import struct
import threading
import time
import shutil
from pathlib import Path

# USAG-Lib 라이브러리 임포트 (같은 디렉토리에 있다고 가정)
try:
    from Bencode import Bencode
    import Bencrypt
    from Icons import Icons
    from Opsec import Opsec
    import Star
    import Szip
except ImportError as e:
    print(f"Error: USAG-Lib files not found. {e}")
    sys.exit(1)

# --- lib.go 기능 구현 ---

def AfterSize(n: int) -> int:
    c = n // 1048576 + 1
    if n != 0 and n % 1048576 == 0:
        c -= 1
    return n + 16 * c

def DoZip(files: list, output: str, isZip: bool) -> None:
    if isZip:
        zw = Szip.ZipWriter(output, True)
        try:
            for root_path in files:
                if os.path.isfile(root_path):
                    zw.writefile(os.path.basename(root_path), root_path)
                else:
                    for root, dirs, filenames in os.walk(root_path):
                        for filename in filenames:
                            filepath = os.path.join(root, filename)
                            # 상대 경로 계산
                            if os.path.isdir(root_path):
                                parent = os.path.dirname(root_path)
                                if parent:
                                    arcname = os.path.relpath(filepath, parent)
                                else:
                                    arcname = filepath
                            else:
                                arcname = filename
                            
                            arcname = arcname.replace("\\", "/")
                            zw.writefile(arcname, filepath)
                        
                        # 빈 디렉토리 처리 (Szip 구현에 따라 필요 여부 결정, 여기서는 파일 위주)
        finally:
            zw.close()
    else:
        tw = Star.TarWriter(output)
        try:
            for root_path in files:
                if os.path.isfile(root_path):
                    tw.writeFile(os.path.basename(root_path), root_path)
                else:
                    for root, dirs, filenames in os.walk(root_path):
                        for d in dirs:
                            dirpath = os.path.join(root, d)
                            if os.path.isdir(root_path):
                                parent = os.path.dirname(root_path)
                                if parent:
                                    arcname = os.path.relpath(dirpath, parent)
                                else:
                                    arcname = dirpath
                            else:
                                arcname = d
                            tw.writeDir(arcname)
                            
                        for filename in filenames:
                            filepath = os.path.join(root, filename)
                            if os.path.isdir(root_path):
                                parent = os.path.dirname(root_path)
                                if parent:
                                    arcname = os.path.relpath(filepath, parent)
                                else:
                                    arcname = filepath
                            else:
                                arcname = filename
                            tw.writeFile(arcname, filepath)
        finally:
            tw.close()

def UnZip(input_path: str, output_dir: str, isZip: bool) -> None:
    os.makedirs(output_dir, exist_ok=True)
    
    if isZip:
        zr = Szip.ZipReader(input_path)
        try:
            # Szip.py는 extractall 기능이 없으므로 직접 구현하거나 zipfile 사용
            # Szip.ZipReader는 read(idx)와 open(idx)를 제공
            for i, name in enumerate(zr.names):
                rel_path = name.replace("\\", "/")
                dest_path = os.path.join(output_dir, rel_path)
                
                # 경로 검증 (Directory Traversal 방지)
                if not os.path.abspath(dest_path).startswith(os.path.abspath(output_dir)):
                    raise Exception(f"illegal file path: {rel_path}")

                if name.endswith('/'):
                    os.makedirs(dest_path, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    with open(dest_path, "wb") as f:
                        f.write(zr.read(i))
        finally:
            zr.close()
    else:
        tr = Star.TarReader(input_path)
        try:
            while tr.next():
                rel_path = tr.name.replace("\\", "/")
                dest_path = os.path.join(output_dir, rel_path)
                
                # 경로 검증
                if not os.path.abspath(dest_path).startswith(os.path.abspath(output_dir)):
                    raise Exception(f"illegal file path: {tr.name}")

                if tr.isDir:
                    os.makedirs(dest_path, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    tr.mkfile(dest_path)
        finally:
            tr.close()

def GetIPs(v4only: bool = True) -> list:
    ips = []
    try:
        # 간단한 방법: 외부 연결을 시도하여 로컬 IP 확인
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    
    # 모든 인터페이스 IP 가져오기 (cross-platform 호환성 문제로 hostname 방식 사용)
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if v4only and ':' in ip: continue
            if ip not in ips: ips.append(ip)
    except:
        pass
    return ips

# TPprotocol Constants
MODE_MSGONLY = 0x1
MODE_LEGACY  = 0x2
MODE_RSA_4K  = 0x4

STAGE_IDLE         = 0
STAGE_HANDSHAKE    = 1
STAGE_ENCRYPTING   = 2
STAGE_TRANSFERRING = 3
STAGE_COMPLETE     = 4
STAGE_ERROR        = -1

class TPprotocol:
    def __init__(self):
        self.Mode = 0
        self.stage = 0
        self.sent = 0
        self.total = 0
        self.lock = threading.Lock()
        self.conn = None
        self.magic = b'UTP1'
        self.zero8 = b'\x00' * 8
        self.max8 = b'\xff' * 8

    def Init(self, mode: int, conn: socket.socket):
        self.Mode = mode
        self.stage = 0
        self.sent = 0
        self.total = 0
        self.conn = conn

    def GetStatus(self):
        with self.lock:
            return self.stage, self.sent, self.total

    def setStage(self, stage):
        with self.lock:
            self.stage = stage

    def setSent(self, sent):
        with self.lock:
            self.sent = sent

    def setTotal(self, total):
        with self.lock:
            self.total = total

    def syncStatus(self, stop_event: threading.Event):
        try:
            while not stop_event.is_set():
                self.conn.sendall(self.zero8)
                stop_event.wait(1.0)
        except:
            self.setStage(STAGE_ERROR)

    def _recv_all(self, n):
        data = bytearray()
        while len(data) < n:
            packet = self.conn.recv(n - len(data))
            if not packet:
                raise ConnectionError("Connection closed unexpectedly")
            data.extend(packet)
        return bytes(data)

    def handshakeSend(self):
        # 1. Generate Key Pair
        if self.Mode & MODE_LEGACY:
            r = Bencrypt.RSA1()
            bits = 4096 if (self.Mode & MODE_RSA_4K) else 2048
            myPub, myPriv = r.genkey(bits)
        else:
            e = Bencrypt.ECC1()
            myPub, myPriv = e.genkey()
        
        # 2. Prepare Packet
        pubLen = len(myPub)
        if pubLen > 65535:
            raise ValueError("public key is too long")
        
        # Magic(4) + Mode(2) + PubSize(2) + PubKey(N)
        buf = self.magic + \
              Opsec.encodeInt(self.Mode, 2, False) + \
              Opsec.encodeInt(pubLen, 2, False) + \
              myPub
        
        self.conn.sendall(buf)

        # 4. Receive Response: PubSize(2) + PubKey(M)
        head = self._recv_all(2)
        peerPubLen = Opsec.decodeInt(head, False)
        peerPub = self._recv_all(peerPubLen)
        
        return peerPub, myPub, myPriv

    def handshakeReceive(self):
        # 1. Receive Packet: Magic(4) + Mode(2) + PubSize(2)
        header = self._recv_all(8)
        
        if header[:4] != self.magic:
            raise ValueError("invalid magic number")
        
        self.Mode = Opsec.decodeInt(header[4:6], False)
        peerPubLen = Opsec.decodeInt(header[6:8], False)
        
        peerPub = self._recv_all(peerPubLen)
        
        # 5. Generate My Key Pair
        if self.Mode & MODE_LEGACY:
            r = Bencrypt.RSA1()
            bits = 4096 if (self.Mode & MODE_RSA_4K) else 2048
            myPub, myPriv = r.genkey(bits)
        else:
            e = Bencrypt.ECC1()
            myPub, myPriv = e.genkey()
            
        # 6. Send Response
        myPubLen = len(myPub)
        if myPubLen > 65535:
            raise ValueError("generated public key is too long")
            
        resp = Opsec.encodeInt(myPubLen, 2, False) + myPub
        self.conn.sendall(resp)
        
        return peerPub, myPub, myPriv

    def SendFile(self, filePath, tempPath, smsg):
        self.setStage(STAGE_HANDSHAKE)
        try:
            peerPub, _, myPriv = self.handshakeSend()
        except Exception as e:
            self.setStage(STAGE_ERROR)
            raise e

        stop_event = threading.Event()
        t = threading.Thread(target=self.syncStatus, args=(stop_event,))
        t.start()
        self.setStage(STAGE_ENCRYPTING)

        try:
            originalSize = os.path.getsize(filePath)
            encryptedSize = AfterSize(originalSize)

            ops = Opsec() # Note: Opsec.py class is Opsec
            ops.reset()
            ops.size = encryptedSize
            ops.bodyAlgo = "gcmx1"
            ops.contAlgo = "zip1"
            ops.smsg = smsg

            method = "rsa1" if (self.Mode & MODE_LEGACY) else "ecc1"
            opsHead = ops.encpub(method, peerPub, myPriv)

            with open(tempPath, "wb") as tempFile:
                # Write Header
                ops.write(tempFile, opsHead)
                
                # Encrypt Body
                key = ops.bodyKey # 44 bytes
                aes = Bencrypt.AES1()
                with open(filePath, "rb") as srcFile:
                    aes.enAESGCMx(key, srcFile, originalSize, tempFile, 0)

            self.setStage(STAGE_TRANSFERRING)
            stop_event.set()
            t.join()

            totalSize = os.path.getsize(tempPath)
            self.setSent(0)
            self.setTotal(totalSize)
            
            # Send Total Size
            self.conn.sendall(Opsec.encodeInt(totalSize, 8, False))

            # Stream Send
            with open(tempPath, "rb") as f:
                while True:
                    buf = f.read(4096)
                    if not buf: break
                    self.conn.sendall(buf)
                    with self.lock:
                        self.sent += len(buf)

            # Receive Termination
            term = self._recv_all(8)
            if term != self.zero8:
                raise Exception("abnormal termination signal")
            
            self.setStage(STAGE_COMPLETE)

        except Exception as e:
            self.setStage(STAGE_ERROR)
            stop_event.set() # ensure thread stops
            raise e

    def ReceiveFile(self, savePath, tempPath):
        self.setStage(STAGE_HANDSHAKE)
        try:
            peerPub, _, myPriv = self.handshakeReceive()
        except Exception as e:
            self.setStage(STAGE_ERROR)
            raise e

        self.setStage(STAGE_TRANSFERRING)
        
        # Wait for start signal
        while True:
            buf8 = self._recv_all(8)
            if buf8 == self.zero8:
                continue
            elif buf8 == self.max8:
                self.setStage(STAGE_ERROR)
                raise Exception("remote error reported")
            else:
                totalSize = Opsec.decodeInt(buf8, False)
                self.setTotal(totalSize)
                break
        
        # Download
        with open(tempPath, "wb") as tempFile:
            self.setSent(0)
            currentReceived = 0
            while currentReceived < totalSize:
                toRead = min(4096, totalSize - currentReceived)
                buf = self._recv_all(toRead)
                tempFile.write(buf)
                currentReceived += len(buf)
                self.setSent(currentReceived)
        
        # Decrypt
        try:
            with open(tempPath, "rb+") as tempFile:
                tempFile.seek(0)
                ops = Opsec()
                headBytes = ops.read(tempFile, 0)
                ops.view(headBytes)
                ops.decpub(myPriv, peerPub)

                self.setStage(STAGE_ENCRYPTING)
                
                if ops.bodyAlgo != "gcmx1":
                    raise Exception(f"unsupported body algorithm: {ops.bodyAlgo}")

                key = ops.bodyKey
                aes = Bencrypt.AES1()
                
                with open(savePath, "wb") as outFile:
                    aes.deAESGCMx(key, tempFile, ops.size, outFile, 0)
            
            self.conn.sendall(self.zero8)
            self.setStage(STAGE_COMPLETE)
            return ops.smsg

        except Exception as e:
            self.setStage(STAGE_ERROR)
            self.conn.sendall(self.max8)
            raise e

# --- main_cli.go 기능 구현 ---

class Config:
    def __init__(self):
        self.Mode = "help"
        self.TempDir = ""
        self.Output = ""
        self.Files = []
        self.Text = ""
        self.PreHead = ""
        self.IsLegacy = False
        self.IsZip = False
        self.PW = ""
        self.KF = None
        self.Public = None
        self.Private = None
        self.Msg = ""
        self.SMsg = ""
        self.Bits = 2048

Cfg = Config()

def getPrehead():
    if not Cfg.Files: return None, ""
    
    ic = Icons()
    d = b""
    e = ""
    
    if Cfg.PreHead == "none":
        return None, ""
    elif Cfg.PreHead == "zippng":
        d = ic.zip_png()
        e = ".png"
    elif Cfg.PreHead == "zipwebp":
        d = ic.zip_webp()
        e = ".webp"
    elif Cfg.PreHead == "aespng":
        d = ic.aes_png()
        e = ".png"
    elif Cfg.PreHead == "aeswebp":
        d = ic.aes_webp()
        e = ".webp"
    elif Cfg.PreHead == "cloudpng":
        d = ic.cloud_png()
        e = ".png"
    elif Cfg.PreHead == "cloudwebp":
        d = ic.cloud_webp()
        e = ".webp"
    elif not Cfg.PreHead:
        if Cfg.Public is None: # pw-mode
            d = ic.aes_webp()
        else: # pub-mode
            d = ic.cloud_webp()
        e = ".webp"
    else:
        try:
            with open(Cfg.PreHead, "rb") as f:
                d = f.read(65535)
            e = ".bin"
        except:
            d = b""
            e = ""

    if len(d) % 128 != 0:
        d += b'\x00' * (128 - len(d) % 128)
    return d, e

class Progress:
    def __init__(self):
        self.Now = 0
        self.Total = 0
        self.Bar = 40
        self.Msg = ""
    
    def Init(self, total, bar=40):
        self.Now = 0
        self.Total = total
        self.Bar = bar

    def Start(self, msg):
        self.Msg = msg
        print(f"{msg}: [", end="", flush=True)

    def Update(self, now):
        before = int((self.Now / self.Total) * self.Bar) if self.Total > 0 else 0
        after = min(int((now / self.Total) * self.Bar), self.Bar) if self.Total > 0 else 0
        self.Now = now
        
        diff = after - before
        if diff > 0:
            chars = ""
            for i in range(before, after):
                if i != 0 and i % (self.Bar // 4) == 0:
                    chars += "|"
                chars += "="
            print(chars, end="", flush=True)

    def End(self):
        self.Update(self.Total)
        print("]")

def f_zip():
    output = Cfg.Output
    if not output:
        output = "output.zip" if Cfg.IsZip else "output.tar"
    return DoZip(Cfg.Files, output, Cfg.IsZip)

def f_unzip():
    if not Cfg.Files: return Exception("Input file required")
    return UnZip(Cfg.Files[0], Cfg.Output if Cfg.Output else ".", Cfg.IsZip)

def f_send():
    if not Cfg.Text:
        return Exception("receiver address required (-t ip:port)")
    targetAddr = Cfg.Text
    if ":" not in targetAddr:
        targetAddr += ":8888"
    host, port = targetAddr.split(":")
    port = int(port)

    # 2. zip data
    zipPath = os.path.join(Cfg.TempDir, "yas2zip.temp")
    if os.path.exists(zipPath): os.remove(zipPath)
    
    print(f"Packing to {zipPath}...")
    if not Cfg.Files: # msg-only
        open(zipPath, 'a').close()
    else:
        DoZip(Cfg.Files, zipPath, True)

    # 3. Connect
    print(f"Connecting to {targetAddr}...")
    conn = socket.create_connection((host, port), timeout=10)
    
    # 4. Init Protocol
    mode = 0
    if Cfg.IsLegacy: mode |= MODE_LEGACY
    if Cfg.Bits >= 4096: mode |= MODE_RSA_4K
    if not Cfg.Files: mode |= MODE_MSGONLY
    
    p = TPprotocol()
    p.Init(mode, conn)

    # 5. Start Progress
    print(f"Sending data to {targetAddr}...")
    stop = threading.Event()
    
    def progress_loop():
        prog = Progress()
        isStarted = False
        while not stop.is_set():
            stage, sent, total = p.GetStatus()
            if total > 0 and not isStarted:
                prog.Init(total, 40)
                prog.Start("Sending")
                isStarted = True
            
            if isStarted:
                prog.Update(sent)
                if stage == STAGE_ERROR:
                    return
            time.sleep(0.1)
        if isStarted: prog.End()

    t = threading.Thread(target=progress_loop)
    t.start()

    sendPath = os.path.join(Cfg.TempDir, "yas2send.temp")
    try:
        p.SendFile(zipPath, sendPath, Cfg.SMsg)
        print("Session completed successfully")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        stop.set()
        t.join()
        conn.close()
        if os.path.exists(zipPath): os.remove(zipPath)
        if os.path.exists(sendPath): os.remove(sendPath)

def f_recv():
    port = 8888
    if Cfg.Text: port = int(Cfg.Text)

    ips = GetIPs(True)
    for ip in ips:
        print(f"Receiver IP: {ip}:{port}")
    
    print(f"Start listening on port {port}...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(1)

    conn, addr = server.accept()
    print(f"Connected from {addr[0]}")

    p = TPprotocol()
    p.Init(0, conn)
    
    tempPath = os.path.join(Cfg.TempDir, "yas2recv.temp")
    zipPath = os.path.join(Cfg.TempDir, "yas2unzip.temp")
    if os.path.exists(zipPath): os.remove(zipPath)

    stop = threading.Event()
    def progress_loop():
        prog = Progress()
        isStarted = False
        while not stop.is_set():
            stage, sent, total = p.GetStatus()
            if total > 0 and not isStarted:
                prog.Init(total, 40)
                prog.Start("Receiving")
                isStarted = True
            if isStarted:
                prog.Update(sent)
                if stage == STAGE_ERROR: return
            time.sleep(0.1)
        if isStarted: prog.End()

    t = threading.Thread(target=progress_loop)
    t.start()

    smsg = ""
    try:
        smsg = p.ReceiveFile(zipPath, tempPath)
        
        if not (p.Mode & MODE_MSGONLY):
            output = Cfg.Output if Cfg.Output else "./"
            print(f"Unpacking data to {output}...")
            UnZip(zipPath, output, True)
        
        if smsg:
            print(f"\n[SMSG]: {smsg}")
        print("Session completed successfully")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        stop.set()
        t.join()
        conn.close()
        server.close()
        if os.path.exists(zipPath): os.remove(zipPath)
        if os.path.exists(tempPath): os.remove(tempPath)

def f_genkey():
    print("Generating key pair...")
    pubNm = ""
    priNm = ""
    pub = b""
    pri = b""
    
    if Cfg.IsLegacy:
        r = Bencrypt.RSA1()
        if Cfg.Bits == 2048:
            pubNm, priNm = "public_2k.txt", "private_2k.txt"
            pub, pri = r.genkey(2048)
        elif Cfg.Bits == 3072:
            pubNm, priNm = "public_3k.txt", "private_3k.txt"
            pub, pri = r.genkey(3072)
        elif Cfg.Bits == 4096:
            pubNm, priNm = "public_4k.txt", "private_4k.txt"
            pub, pri = r.genkey(4096)
        else:
            return Exception(f"unsupported RSA key size: {Cfg.Bits}")
    else:
        pubNm, priNm = "public.txt", "private.txt"
        e = Bencrypt.ECC1()
        pub, pri = e.genkey()

    output = Cfg.Output if Cfg.Output else "./"
    pubPath = os.path.join(output, pubNm)
    priPath = os.path.join(output, priNm)

    print("Saving key pair...")
    b = Bencode()
    with open(pubPath, "w") as f:
        f.write(b.encode(pub, True))
    print(f"Public key: {pubPath}")
    
    with open(priPath, "w") as f:
        f.write(b.encode(pri, True))
    print(f"Private key: {priPath}")

def f_sign():
    b = Bencode()
    
    if Cfg.Private: # make sign
        if not Cfg.Files: return Exception("no file to sign")
        output = Cfg.Output if Cfg.Output else "./"
        
        print("Loading private key...")
        rsa = Bencrypt.RSA1()
        ecc = Bencrypt.ECC1()
        
        if Cfg.IsLegacy:
            rsa.loadkey(None, Cfg.Private)
        else:
            ecc.loadkey(None, Cfg.Private)
            
        for i, fpath in enumerate(Cfg.Files):
            signPath = os.path.join(output, f"sign_{i}.txt")
            if os.path.isdir(fpath): return Exception(f"file {fpath} is directory")
            if os.path.getsize(fpath) > 512*1048576: return Exception("file too large")
            
            with open(fpath, "rb") as f:
                data = f.read()
            
            sdata = b""
            if Cfg.IsLegacy:
                sdata = rsa.sign(data)
            else:
                sdata = ecc.sign(data)
                
            with open(signPath, "w") as f:
                f.write(b.encode(sdata, True))
            print(f"Signed {fpath} -> {signPath}")
            
    elif Cfg.Public: # verify sign
        print("Loading data...")
        if len(Cfg.Files) < 2: return Exception("need 2 files (file, sign)")
        
        if os.path.isdir(Cfg.Files[0]): return Exception("file is directory")
        
        with open(Cfg.Files[0], "rb") as f:
            data = f.read()
        with open(Cfg.Files[1], "r") as f:
            sdata_str = f.read()
            
        print("Loading public key...")
        sdata = b.decode(sdata_str)
        
        rsa = Bencrypt.RSA1()
        ecc = Bencrypt.ECC1()
        
        if Cfg.IsLegacy:
            rsa.loadkey(Cfg.Public, None)
        else:
            ecc.loadkey(Cfg.Public, None)
            
        c = False
        if Cfg.IsLegacy:
            c = rsa.verify(data, sdata)
        else:
            c = ecc.verify(data, sdata)
            
        if c:
            print(f"Verified successfully {Cfg.Files[0]}")
        else:
            print(f"Invalid sign {Cfg.Files[0]}")
    else:
        return Exception("no key")

def f_enc():
    o = Opsec()
    o.reset()
    phead, suffix = getPrehead()
    output = Cfg.Output if Cfg.Output else f"output{suffix}"

    zipPath = ""
    zipSize = 0
    
    if Cfg.Files:
        print("Packing files...")
        zipPath = os.path.join(Cfg.TempDir, "yas2tar.temp")
        DoZip(Cfg.Files, zipPath, False)
        zipSize = os.path.getsize(zipPath)
    
    print("Generating opsec header...")
    ohead = b""
    o.msg = Cfg.Msg
    o.smsg = Cfg.SMsg
    if Cfg.Files:
        o.bodyAlgo = "gcmx1"
        o.contAlgo = "tar1"
    
    method = ""
    if Cfg.Public is None: # pw-mode
        method = "pbk1" if Cfg.IsLegacy else "arg1"
    else: # pub-mode
        method = "rsa1" if Cfg.IsLegacy else "ecc1"

    if not Cfg.Files:
        if Cfg.Public is None:
            ohead = o.encpw(method, Cfg.PW.encode(), Cfg.KF if Cfg.KF else b"")
        else:
            ohead = o.encpub(method, Cfg.Public, Cfg.Private)
        
        b = Bencode()
        print(f"Encrypted successfully:\n\n{b.encode(ohead, True)}\n\n")
        return
    else:
        o.size = AfterSize(zipSize)
        if Cfg.Public is None:
            ohead = o.encpw(method, Cfg.PW.encode(), Cfg.KF if Cfg.KF else b"")
        else:
            ohead = o.encpub(method, Cfg.Public, Cfg.Private)

    print("Writing headers...")
    with open(output, "wb") as oFile:
        if phead: oFile.write(phead)
        o.write(oFile, ohead)
        
        with open(zipPath, "rb") as zf:
            aes = Bencrypt.AES1()
            
            stop = threading.Event()
            def progress_loop():
                prog = Progress()
                prog.Init(zipSize, 40)
                prog.Start("Encrypting")
                while not stop.is_set():
                    prog.Update(aes.processed())
                    time.sleep(0.1)
                prog.End()
            
            t = threading.Thread(target=progress_loop)
            t.start()
            
            key = o.bodyKey # 44 bytes
            try:
                aes.enAESGCMx(key, zf, zipSize, oFile, 0)
            finally:
                stop.set()
                t.join()
                if os.path.exists(zipPath): os.remove(zipPath)

    print(f"Encrypted successfully: {output}")

def f_dec():
    print("Loading header...")
    headBytes = b""
    inFile = None
    
    if Cfg.Files:
        inFile = open(Cfg.Files[0], "rb")
        o = Opsec()
        headBytes = o.read(inFile, 0)
    elif Cfg.Text:
        b = Bencode()
        headBytes = b.decode(Cfg.Text)
    else:
        return Exception("input source required (file or -t)")
    
    ops = Opsec()
    ops.view(headBytes)
    if ops.msg:
        print(f"\n[MSG]: {ops.msg}\n")
        
    print("Decrypting header...")
    try:
        if ops.headAlgo in ["pbk1", "arg1"]:
            ops.decpw(Cfg.PW.encode(), Cfg.KF if Cfg.KF else b"")
        elif ops.headAlgo in ["rsa1", "ecc1"]:
            if not Cfg.Private: return Exception("private key required (-pri)")
            ops.decpub(Cfg.Private, Cfg.Public)
        else:
            return Exception(f"unknown header algorithm: {ops.headAlgo}")
    except Exception as e:
        if inFile: inFile.close()
        return e

    if ops.smsg:
        print(f"\n[SMSG]: {ops.smsg}\n")
        
    if not inFile or ops.size <= 0:
        print("Decrypted successfully: msg-only mode")
        if inFile: inFile.close()
        return
        
    aes = Bencrypt.AES1()
    key = ops.bodyKey
    output = Cfg.Output if Cfg.Output else "./"
    
    stop = threading.Event()
    def progress_loop():
        prog = Progress()
        prog.Init(ops.size, 40)
        prog.Start("Decrypting")
        while not stop.is_set():
            prog.Update(aes.processed())
            time.sleep(0.1)
        prog.End()

    try:
        if ops.bodyAlgo == "gcm1":
            print("Decrypting body...")
            buf = inFile.read(ops.size)
            dec = aes.deAESGCM(key, buf)
            name = ops.name if ops.name else "noname.bin"
            with open(os.path.join(output, name), "wb") as f:
                f.write(dec)
            print(f"Decrypted successfully: {output}")
            
        elif ops.bodyAlgo == "gcmx1":
            t = threading.Thread(target=progress_loop)
            t.start()
            
            tempPath = os.path.join(Cfg.TempDir, "yas2untar.temp")
            with open(tempPath, "wb") as tFile:
                aes.deAESGCMx(key, inFile, ops.size, tFile, 0)
            
            stop.set()
            t.join()
            
            print(f"Unpacking to {output}...")
            if ops.contAlgo == "zip1":
                UnZip(tempPath, output, True)
            elif ops.contAlgo == "tar1":
                UnZip(tempPath, output, False)
            else:
                raise Exception(f"unknown container algorithm: {ops.contAlgo}")
            
            if os.path.exists(tempPath): os.remove(tempPath)
            print(f"Decrypted successfully: {output}")
        else:
            raise Exception(f"unknown body algorithm: {ops.bodyAlgo}")
            
    finally:
        if inFile: inFile.close()

def main():
    parser = argparse.ArgumentParser(description="USAG YAS-desktop cli (Python)")
    parser.add_argument("-m", dest="mode", default="help", help="work mode: zip, unzip, send, recv, genkey, sign, enc, dec, version, help")
    parser.add_argument("-tmp", dest="temp_dir", default="", help="set temp dir path")
    parser.add_argument("-o", dest="output", default="", help="output file path")
    parser.add_argument("-t", dest="text", default="", help="set text input")
    parser.add_argument("-pre", dest="pre_head", default="", help="PreHeader Type: none, zippng, zipwebp, aespng, aeswebp, cloudpng, cloudwebp")
    parser.add_argument("-legacy", dest="is_legacy", action="store_true", help="Enables PBKDF2/RSA")
    parser.add_argument("-zip", dest="is_zip", action="store_true", help="Enables zip mode")
    parser.add_argument("-pw", dest="password", default="", help="password")
    parser.add_argument("-msg", dest="msg", default="", help="non-secured message")
    parser.add_argument("-smsg", dest="smsg", default="", help="secured message")
    parser.add_argument("-bits", dest="bits", type=int, default=2048, help="RSA key bits")
    parser.add_argument("-kf", dest="kf_path", default="", help="key file path")
    parser.add_argument("-pub", dest="pub", default="", help="public key string or path")
    parser.add_argument("-pri", dest="pri", default="", help="private key string or path")
    parser.add_argument("files", nargs='*', help="target files")

    args = parser.parse_args()

    # Config init
    Cfg.Mode = args.mode
    Cfg.TempDir = args.temp_dir
    Cfg.Output = args.output
    Cfg.Files = args.files
    Cfg.Text = args.text
    Cfg.PreHead = args.pre_head
    Cfg.IsLegacy = args.is_legacy
    Cfg.IsZip = args.is_zip
    Cfg.PW = args.password
    Cfg.Msg = args.msg
    Cfg.SMsg = args.smsg
    Cfg.Bits = args.bits

    # Temp Path
    if not Cfg.TempDir:
        Cfg.TempDir = os.path.dirname(os.path.abspath(__file__))

    # KF
    if args.kf_path:
        try:
            with open(args.kf_path, "rb") as f:
                Cfg.KF = f.read(1024)
        except Exception as e:
            print(e)
            Cfg.KF = None

    # Keys
    b = Bencode()
    
    pub_str = args.pub
    if pub_str and os.path.isfile(pub_str):
        with open(pub_str, "r") as f:
            pub_str = f.read()
            
    pri_str = args.pri
    if pri_str and os.path.isfile(pri_str):
        with open(pri_str, "r") as f:
            pri_str = f.read()
            
    if pub_str:
        try:
            Cfg.Public = b.decode(pub_str)
        except Exception as e:
            print(e)
            Cfg.Public = None
            
    if pri_str:
        try:
            Cfg.Private = b.decode(pri_str)
        except Exception as e:
            print(e)
            Cfg.Private = None

    print("Configuration completed")
    
    err = None
    if Cfg.Mode == "zip":
        err = f_zip()
    elif Cfg.Mode == "unzip":
        err = f_unzip()
    elif Cfg.Mode == "send":
        err = f_send()
    elif Cfg.Mode == "recv":
        err = f_recv()
    elif Cfg.Mode == "genkey":
        err = f_genkey()
    elif Cfg.Mode == "sign":
        err = f_sign()
    elif Cfg.Mode == "enc":
        err = f_enc()
    elif Cfg.Mode == "dec":
        err = f_dec()
    elif Cfg.Mode == "version":
        print("2026 @k-atusa USAG-Yas-cli v0.1 (Python)")
    else:
        parser.print_help()

    if err:
        print(f"\nerror: {err}\n")

if __name__ == "__main__":
    main()