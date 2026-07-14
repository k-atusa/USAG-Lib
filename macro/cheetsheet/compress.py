# test835 : media file compress

import os
import subprocess
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from PIL import Image

FFPATH = "./ffmpeg.exe"
SLEEP = 15
IMGS = ["png", "jpg", "jpeg", "bmp"]
VIDS = ["mp4", "mkv", "avi", "mov", "wmv", "mts", "m2ts", "mpg", "3gp", "flv"]
IMG_THREADS = os.cpu_count() or 4

# ===== error record =====
_err_lock = threading.Lock()
_errors = []

def logErr(msg):
    print(msg)
    with _err_lock:
        _errors.append(msg)

# ===== convert =====
def getHwaccel():
    try:
        r = subprocess.run(
            [FFPATH, "-hide_banner", "-hwaccels"],
            capture_output=True, text=True, encoding="utf-8", timeout=10
        )
        methods = [l.strip() for l in r.stdout.splitlines() if l.strip() and ":" not in l]
    except Exception:
        return [ ]
    for m in ["cuda", "qsv", "d3d11va", "dxva2", "vulkan", "opencl"]:
        if m in methods:
            return ["-hwaccel", m]
    return ["-hwaccel", methods[0]] if methods else [ ]

def convImg(path):
    before = os.path.getsize(path)
    base, _ = os.path.splitext(path)
    out_path = base + ".webp"
    try:
        with Image.open(path) as img:
            img.save(out_path, "WEBP", quality=85, method=5)
        time.sleep(SLEEP * 0.01)
        if path != out_path and os.path.exists(out_path):
            os.remove(path)
        after = os.path.getsize(out_path)
        calcRate(path, before, after)
    except Exception as e:
        logErr(f"[ERROR] {path}: {e}")

def convVid(path, hwaccel):
    if not os.path.exists(path):
        logErr(f"[ERROR] {path}: File not found")
        return
    before = os.path.getsize(path)
    dir_name = os.path.dirname(path)
    temp_path = os.path.join(dir_name, f"temp_{os.path.basename(path)}")
    base_name, _ = os.path.splitext(os.path.basename(path))
    output = os.path.join(dir_name, base_name + ".mp4")
    
    # change file name and convert
    try:
        os.rename(path, temp_path)
        cmd = [
            FFPATH, "-y", *hwaccel, "-i", temp_path,
            "-c:v", "libsvtav1", "-crf", "32", "-preset", "5",
            "-pix_fmt", "yuv420p10le", "-svtav1-params", "tune=0:film-grain=4:scd=1",
            "-c:a", "libopus", "-b:a", "96k", output
        ]
        
        # print shell result
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        if result.stdout:
            print("-", result.stdout.replace("\n", " ")[-100:])
        if result.stderr:
            print("-", result.stderr.replace("\n", " ")[-100:])
        time.sleep(SLEEP)
        
        # delete or restore temp file
        if os.path.exists(output) and os.path.getsize(output) > 0:
            os.remove(temp_path)
            after = os.path.getsize(output)
            calcRate(output, before, after)
        else:
            os.rename(temp_path, path)
            logErr(f"[ERROR] {path}: Encode failed")
            
    except Exception as e:
        if os.path.exists(temp_path) and not os.path.exists(output):
            os.rename(temp_path, path)
        logErr(f"[ERROR] {path}: {e}")

def calcRate(path, before, after):
    if before == 0:
        print(f"[--.--%] {path}")
        return
    rate = ((before - after) / before) * 100
    print(f"[{rate:.2f}%] {path}")

# ===== main =====
def main(path):
    if not os.path.exists(path):
        logErr(f"[ERROR] {path}: dir not found")
        return
    hwaccel = getHwaccel()
    print(f"HW accel: {hwaccel[1]}" if hwaccel else "HW accel: none")

    # walk lower directory
    for root, dirs, files in os.walk(path):
        img_files, vid_files = [ ], [ ]
        for f in files:
            ext = os.path.splitext(f)[1].lower().lstrip('.')
            if ext in IMGS:
                img_files.append(f)
            elif ext in VIDS:
                vid_files.append(f)
        target_files = img_files + vid_files

        # proceed if target exists
        if target_files:
            print("\n=========================")
            print(f"{root}\n")
            for f in target_files:
                print(f" - {f}")
            print("=========================\n")
            input("press ENTER to continue...")
            
            # convert images (multi-threaded)
            if img_files:
                paths = [os.path.join(root, f) for f in img_files]
                with ThreadPoolExecutor(max_workers=IMG_THREADS) as pool:
                    futs = {pool.submit(convImg, p): p for p in paths}
                    for fut in as_completed(futs):
                        try:
                            fut.result()
                        except Exception as e:
                            logErr(f"[ERROR] {futs[fut]}: {e}")

            # convert videos (sequential)
            for f in vid_files:
                convVid(os.path.join(root, f), hwaccel)

    # error summary
    if _errors:
        print(f"\n========== ERRORS ({len(_errors)}) ==========")
        for e in _errors:
            print(f"  {e}")
        print("=" * 40)

if __name__ == "__main__":
    tgt = input("Tgt dir: ").strip().strip('"')
    main(tgt)
    input("press ENTER to exit...")
