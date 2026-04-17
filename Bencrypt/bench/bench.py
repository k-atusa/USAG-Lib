import os
import time
import Bencrypt

def fmt_speed(size_bytes, duration):
    mb = size_bytes / (1024 * 1024)
    speed = mb / duration
    return f"{speed:.2f} MiB/s"

def fmt_time(count, duration):
    avg_ms = (duration / count) * 1000
    return f"{avg_ms:.2f} ms/op"

print("Bencrypt Benchmarks (Python)")

time.sleep(1)
print("\n\n===== Basic Functions =====")
p = [100 * 1048576, 100 * 1048576, 100 * 1048576]
start = time.time()
Bencrypt.Random(p[0])
end = time.time()
print(f"RandGen: {fmt_speed(p[0], end - start)}")

data = b"\x00" * p[1]
start = time.time()
Bencrypt.SHA3256(data)
end = time.time()
print(f"SHA3256: {fmt_speed(p[1], end - start)}")

data = b"\x00" * p[2]
start = time.time()
Bencrypt.SHA3512(data)
end = time.time()
print(f"SHA3512: {fmt_speed(p[2], end - start)}")

time.sleep(1)
print("\n\n===== Hash Functions =====")
algos = ["sha3", "pbk2", "arg2"]
iters = [100000, 5, 5]
pw, salt = b"\x00" * 64, b"\x00" * 32 # std: 64B password, 32B salt
for i in range( 0, len(algos) ):
    w = Bencrypt.HashMaster(algos[i])
    start = time.time()
    for j in range(iters[i]):
        w.KDF(pw, salt)
    end = time.time()
    print(f"{algos[i]}: {fmt_time(iters[i], end - start)}")

time.sleep(1)
print("\n\n===== Symmetric Functions =====")
fsize = 512 * 1048576 # 512MiB
data = b"\x00" * fsize
with open("temp.bin", "wb") as f:
    f.write(b"\xff" * fsize)
algos = ["gcm1", "gcmx1"]
for algo in algos:
    w = Bencrypt.SymMaster(algo, b"0" * 44)
    start = time.time()
    w.EnBin(data)
    end = time.time()
    print(f"{algo} (in-memory): {fmt_speed(len(data), end - start)}")
    with open("temp.bin", "rb") as f:
        with open("temp.out", "wb") as t:
            start = time.time()
            w.EnFile(f, fsize, t)
            end = time.time()
            print(f"{algo} (file): {fmt_speed(fsize, end - start)}")
    print("")

time.sleep(1)
print("\n\n===== Asymmetric Functions =====")
algos = ["rsa1", "rsa2", "ecc1", "pqc1"]
iters_g = [3, 1, 20, 20]
iters_c = [25, 25, 50, 50]
data = b"\x00" * 64 # std: 64B data
for i in range( 0, len(algos) ):
    w = Bencrypt.AsymMaster(algos[i])
    start = time.time()
    for j in range(iters_g[i]):
        w.Genkey()
    end = time.time()
    print(f"{algos[i]} (genkey): {fmt_time(iters_g[i], end - start)}")

    start = time.time()
    for j in range(iters_c[i]):
        w.Encrypt(data)
    end = time.time()
    print(f"{algos[i]} (encrypt): {fmt_time(iters_c[i], end - start)}")

    start = time.time()
    for j in range(iters_c[i]):
        w.Sign(data)
    end = time.time()
    print(f"{algos[i]} (sign): {fmt_time(iters_c[i], end - start)}")
    print("")

# clean-up
time.sleep(1)
os.remove("temp.bin")
os.remove("temp.out")
