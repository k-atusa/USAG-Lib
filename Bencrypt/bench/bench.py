import time
import io
import os
import tempfile
import Bencrypt

# ========== Settings ==========

# Throughput Test Size
DATA_SIZE = 16 * 1048576      # 16 MiB (Hash, Random)
DATA_SIZE_BIG = 256 * 1048576 # 256 MiB (AES)

# Iterations for Latency Tests
ITER_KDF = 5      # Slow functions (Argon2)
ITER_KEYGEN = 8  # Key Generation (RSA-2048, ECC)
ITER_FAST = 50 # Encrypt/Decrypt ops

def fmt_speed(size_bytes, duration):
    mb = size_bytes / (1024 * 1024)
    speed = mb / duration
    return f"{speed:.2f} MiB/s"

def fmt_time(count, duration):
    avg_ms = (duration / count) * 1000
    return f"{avg_ms:.2f} ms/op"

def main():
    print(f"=== Bencrypt Performance Benchmark (Python) ===")

    # 1. Random Generation
    start = time.perf_counter()
    _ = Bencrypt.random(DATA_SIZE)
    dur = time.perf_counter() - start
    print(f"[Random] Gen: {fmt_speed(DATA_SIZE, dur)}")

    # Prepare Data
    dummy_data = b'\x00' * DATA_SIZE
    
    # 2. SHA3 Functions
    start = time.perf_counter()
    Bencrypt.sha3256(dummy_data)
    dur = time.perf_counter() - start
    print(f"[SHA3-256]    {fmt_speed(DATA_SIZE, dur)}")

    start = time.perf_counter()
    Bencrypt.sha3512(dummy_data)
    dur = time.perf_counter() - start
    print(f"[SHA3-512]    {fmt_speed(DATA_SIZE, dur)}")

    print("-" * 40)

    # 3. KDF Functions
    # PBKDF2
    start = time.perf_counter()
    for _ in range(ITER_KDF):
        Bencrypt.pbkdf2(b"password", b"salt_bytes_16_", 100000, 64)
    dur = time.perf_counter() - start
    print(f"[PBKDF2]      {fmt_time(ITER_KDF, dur)} (iter=100000)")

    # Argon2
    if Bencrypt.HAS_ARGON2:
        start = time.perf_counter()
        for _ in range(ITER_KDF):
            Bencrypt.argon2Hash(b"password", b"salt_bytes_16_")
        dur = time.perf_counter() - start
        print(f"[Argon2id]    {fmt_time(ITER_KDF, dur)} (m=256MB, t=3, p=4)")
    else:
        print("[Argon2id]    Skipped (Module not installed)")

    print("-" * 40)
    dummy_data = b'\x00' * DATA_SIZE_BIG

    # 4. AES-GCM (Memory)
    key = b'\x00' * 44
    aes = Bencrypt.AES1()
    
    # Encrypt
    start = time.perf_counter()
    enc_data = aes.enAESGCM(key, dummy_data)
    dur = time.perf_counter() - start
    print(f"[AES-GCM] Mem Enc: {fmt_speed(DATA_SIZE_BIG, dur)}")

    # Decrypt
    start = time.perf_counter()
    _ = aes.deAESGCM(key, enc_data)
    dur = time.perf_counter() - start
    print(f"[AES-GCM] Mem Dec: {fmt_speed(DATA_SIZE_BIG, dur)}")

    # 5. AES-GCMx (Memory Stream)
    src = io.BytesIO(dummy_data)
    dst = io.BytesIO()
    
    start = time.perf_counter()
    aes.enAESGCMx(key, src, DATA_SIZE_BIG, dst)
    dur = time.perf_counter() - start
    print(f"[AES-GCMx] Mem Enc: {fmt_speed(DATA_SIZE_BIG, dur)}")

    enc_stream_data = dst.getvalue()
    src = io.BytesIO(enc_stream_data)
    dst = io.BytesIO()

    start = time.perf_counter()
    aes.deAESGCMx(key, src, len(enc_stream_data), dst)
    dur = time.perf_counter() - start
    print(f"[AES-GCMx] Mem Dec: {fmt_speed(DATA_SIZE_BIG, dur)}")

    # 6. AES-GCMx (File Stream)
    with tempfile.TemporaryDirectory() as tmpdir:
        f_src_path = os.path.join(tmpdir, "source.bin")
        f_dst_path = os.path.join(tmpdir, "dest.bin")
        f_dec_path = os.path.join(tmpdir, "decrypted.bin")

        # Create dummy file
        with open(f_src_path, 'wb') as f:
            f.write(dummy_data)
        
        # Encrypt File
        with open(f_src_path, 'rb') as f_in, open(f_dst_path, 'wb') as f_out:
            start = time.perf_counter()
            aes.enAESGCMx(key, f_in, DATA_SIZE_BIG, f_out)
            dur = time.perf_counter() - start
            print(f"[AES-GCMx] File Enc: {fmt_speed(DATA_SIZE_BIG, dur)}")

        # Decrypt File
        enc_size = os.path.getsize(f_dst_path)
        with open(f_dst_path, 'rb') as f_in, open(f_dec_path, 'wb') as f_out:
            start = time.perf_counter()
            aes.deAESGCMx(key, f_in, enc_size, f_out)
            dur = time.perf_counter() - start
            print(f"[AES-GCMx] File Dec: {fmt_speed(DATA_SIZE_BIG, dur)}")

    print("-" * 40)

    # 7. RSA
    payload = b"A" * 64 # RSA OAEP limit depends on key size, 64B is safe for 2048+

    for bits in [2048, 4096]:
        if bits == 4096:
            global ITER_KEYGEN
            ITER_KEYGEN = 1
        rsa = Bencrypt.RSA1()
        
        # Key Gen
        start = time.perf_counter()
        for _ in range(ITER_KEYGEN):
            rsa.genkey(bits)
        dur = time.perf_counter() - start
        print(f"[RSA-{bits}] GenKey : {fmt_time(ITER_KEYGEN, dur)}")

        # Prepare for Enc/Dec
        rsa.genkey(bits)
        
        # Encrypt
        start = time.perf_counter()
        for _ in range(ITER_FAST):
            enc = rsa.encrypt(payload)
        dur = time.perf_counter() - start
        print(f"[RSA-{bits}] Encrypt: {fmt_time(ITER_FAST, dur)}")

        # Decrypt
        start = time.perf_counter()
        for _ in range(ITER_FAST):
            rsa.decrypt(enc)
        dur = time.perf_counter() - start
        print(f"[RSA-{bits}] Decrypt: {fmt_time(ITER_FAST, dur)}")
        print(f"[RSA-{bits}] Sign   : (Similar to Decrypt)")

    print("-" * 40)
    ITER_KEYGEN = 20

    # 8. ECC (Curve448)
    ecc = Bencrypt.ECC1()
    
    # Key Gen
    start = time.perf_counter()
    for _ in range(ITER_KEYGEN):
        ecc.genkey()
    dur = time.perf_counter() - start
    print(f"[ECC-448]  GenKey : {fmt_time(ITER_KEYGEN, dur)}")

    # Prepare for Enc/Dec
    pub, _ = ecc.genkey()
    # ECC Encrypt in Bencrypt includes AES-GCM, but payload is small so mostly ECDH time
    
    # Encrypt
    start = time.perf_counter()
    for _ in range(ITER_FAST):
        enc = ecc.encrypt(payload)
    dur = time.perf_counter() - start
    print(f"[ECC-448]  Encrypt: {fmt_time(ITER_FAST, dur)} (Includes AES gen)")

    # Decrypt
    start = time.perf_counter()
    for _ in range(ITER_FAST):
        ecc.decrypt(enc)
    dur = time.perf_counter() - start
    print(f"[ECC-448]  Decrypt: {fmt_time(ITER_FAST, dur)} (Includes AES gen)")

if __name__ == "__main__":
    main()
