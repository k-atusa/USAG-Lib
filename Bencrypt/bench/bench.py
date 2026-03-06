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
ITER_KDF = 5    # Slow functions (Argon2)
ITER_KEYGEN = 8 # Key Generation (RSA-2048, ECC)
ITER_FAST = 50  # Encrypt/Decrypt ops

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
    _ = Bencrypt.Random(DATA_SIZE)
    dur = time.perf_counter() - start
    print(f"[Random] Gen: {fmt_speed(DATA_SIZE, dur)}")

    # Prepare Data
    dummy_data = b'\x00' * DATA_SIZE
    
    # 2. SHA3 Functions
    start = time.perf_counter()
    Bencrypt.SHA3256(dummy_data)
    dur = time.perf_counter() - start
    print(f"[SHA3-256]    {fmt_speed(DATA_SIZE, dur)}")

    start = time.perf_counter()
    Bencrypt.SHA3512(dummy_data)
    dur = time.perf_counter() - start
    print(f"[SHA3-512]    {fmt_speed(DATA_SIZE, dur)}")

    # 3. Symmetric GCM1
    print("-" * 40)
    dummy_data = b'\x00' * DATA_SIZE_BIG
    key = b'\x00' * 44
    m = Bencrypt.SymMaster("gcm1", key)

    # Encrypt
    start = time.perf_counter()
    enc_data = m.EnBin(dummy_data)
    dur = time.perf_counter() - start
    print(f"[GCM1] Mem Enc: {fmt_speed(DATA_SIZE_BIG, dur)}")

    # Decrypt
    start = time.perf_counter()
    _ = m.DeBin(enc_data)
    dur = time.perf_counter() - start
    print(f"[GCM1] Mem Dec: {fmt_speed(DATA_SIZE_BIG, dur)}")

    # File Stream
    with tempfile.TemporaryDirectory() as tmpdir:
        f_src_path = os.path.join(tmpdir, "source.bin")
        f_dst_path = os.path.join(tmpdir, "dest.bin")
        f_dec_path = os.path.join(tmpdir, "decrypted.bin")

        # Create dummy file
        with open(f_src_path, 'wb') as f:
            f.write(dummy_data)
        
        # Encrypt
        with open(f_src_path, 'rb') as f_in, open(f_dst_path, 'wb') as f_out:
            start = time.perf_counter()
            m.EnFile(key, f_in, DATA_SIZE_BIG, f_out)
            dur = time.perf_counter() - start
            print(f"[GCM1] File Enc: {fmt_speed(DATA_SIZE_BIG, dur)}")

        # Decrypt
        enc_size = os.path.getsize(f_dst_path)
        with open(f_dst_path, 'rb') as f_in, open(f_dec_path, 'wb') as f_out:
            start = time.perf_counter()
            m.DeFile(key, f_in, enc_size, f_out)
            dur = time.perf_counter() - start
            print(f"[GCM1] File Dec: {fmt_speed(DATA_SIZE_BIG, dur)}")

    # 4. Symmetric GCMx1
    print("-" * 40)
    dummy_data = b'\x00' * DATA_SIZE_BIG
    key = b'\x00' * 44
    m = Bencrypt.SymMaster("gcmx1", key)

    # Encrypt
    start = time.perf_counter()
    enc_data = m.EnBin(dummy_data)
    dur = time.perf_counter() - start
    print(f"[GCMx1] Mem Enc: {fmt_speed(DATA_SIZE_BIG, dur)}")

    # Decrypt
    start = time.perf_counter()
    _ = m.DeBin(enc_data)
    dur = time.perf_counter() - start
    print(f"[GCMx1] Mem Dec: {fmt_speed(DATA_SIZE_BIG, dur)}")

    # File Stream
    with tempfile.TemporaryDirectory() as tmpdir:
        f_src_path = os.path.join(tmpdir, "source.bin")
        f_dst_path = os.path.join(tmpdir, "dest.bin")
        f_dec_path = os.path.join(tmpdir, "decrypted.bin")

        # Create dummy file
        with open(f_src_path, 'wb') as f:
            f.write(dummy_data)
        
        # Encrypt
        with open(f_src_path, 'rb') as f_in, open(f_dst_path, 'wb') as f_out:
            start = time.perf_counter()
            m.EnFile(key, f_in, DATA_SIZE_BIG, f_out)
            dur = time.perf_counter() - start
            print(f"GCMx1] File Enc: {fmt_speed(DATA_SIZE_BIG, dur)}")

        # Decrypt
        enc_size = os.path.getsize(f_dst_path)
        with open(f_dst_path, 'rb') as f_in, open(f_dec_path, 'wb') as f_out:
            start = time.perf_counter()
            m.DeFile(key, f_in, enc_size, f_out)
            dur = time.perf_counter() - start
            print(f"[GCMx1] File Dec: {fmt_speed(DATA_SIZE_BIG, dur)}")

    # 5. Asymmetric RSA1
    print("-" * 40)
    payload = b"A" * 64
    m = Bencrypt.AsymMaster("rsa1")

    # Key Gen
    start = time.perf_counter()
    for _ in range(ITER_KEYGEN):
        m.Genkey()
    dur = time.perf_counter() - start
    print(f"[RSA1] Genkey : {fmt_time(ITER_KEYGEN, dur)}")

    # Encrypt
    start = time.perf_counter()
    for _ in range(ITER_FAST):
        enc = m.Encrypt(payload)
    dur = time.perf_counter() - start
    print(f"[RSA1] Encrypt: {fmt_time(ITER_FAST, dur)}")

    # Decrypt
    start = time.perf_counter()
    for _ in range(ITER_FAST):
        m.Decrypt(enc)
    dur = time.perf_counter() - start
    print(f"[RSA1] Decrypt: {fmt_time(ITER_FAST, dur)}")
    print(f"[RSA1] Sign   : (Similar to Decrypt)")

    # 6. Asymmetric RSA2
    print("-" * 40)
    payload = b"A" * 64
    ITER_KEYGEN = 1
    m = Bencrypt.AsymMaster("rsa2")

    # Key Gen
    start = time.perf_counter()
    for _ in range(ITER_KEYGEN):
        m.Genkey()
    dur = time.perf_counter() - start
    print(f"[RSA2] Genkey : {fmt_time(ITER_KEYGEN, dur)}")

    # Encrypt
    start = time.perf_counter()
    for _ in range(ITER_FAST):
        enc = m.Encrypt(payload)
    dur = time.perf_counter() - start
    print(f"[RSA2] Encrypt: {fmt_time(ITER_FAST, dur)}")

    # Decrypt
    start = time.perf_counter()
    for _ in range(ITER_FAST):
        m.Decrypt(enc)
    dur = time.perf_counter() - start
    print(f"[RSA2] Decrypt: {fmt_time(ITER_FAST, dur)}")
    print(f"[RSA2] Sign   : (Similar to Decrypt)")

    # 7. Asymmetric ECC1
    print("-" * 40)
    ITER_KEYGEN = 20
    m = Bencrypt.AsymMaster("ecc1")

    # Key Gen
    start = time.perf_counter()
    for _ in range(ITER_KEYGEN):
        m.Genkey()
    dur = time.perf_counter() - start
    print(f"[ECC1] Genkey : {fmt_time(ITER_KEYGEN, dur)}")

    # Encrypt
    start = time.perf_counter()
    for _ in range(ITER_FAST):
        enc = m.Encrypt(payload)
    dur = time.perf_counter() - start
    print(f"[ECC1] Encrypt: {fmt_time(ITER_FAST, dur)}")

    # Decrypt
    start = time.perf_counter()
    for _ in range(ITER_FAST):
        m.Decrypt(enc)
    dur = time.perf_counter() - start
    print(f"[ECC1] Decrypt: {fmt_time(ITER_FAST, dur)}")

if __name__ == "__main__":
    main()
