# test835 : media file compress

import os
import string
import subprocess
import time
from PIL import Image

FFPATH = "./ffmpeg.exe"
SLEEP = 4
IMGS = ["png", "jpg", "jpeg", "bmp"]
VIDS = ["mp4", "mkv", "avi", "mov", "wmv", "mts", "m2ts", "mpg", "3gp", "flv"]

def convImg(path):
    before = os.path.getsize(path)
    base, _ = os.path.splitext(path)
    out_path = base + ".webp"
    try:
        with Image.open(path) as img:
            img.save(out_path, "WEBP", quality=85, method=5)
        time.sleep(SLEEP * 0.05)
        if path != out_path and os.path.exists(out_path):
            os.remove(path)
        after = os.path.getsize(out_path)
        calcRate(path, before, after)
    except Exception as e:
        print(f"[ERROR] {path}: {e}")

def convVid(path):
    if not os.path.exists(path):
        print(f"[ERROR] {path}: File not found")
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
            FFPATH, "-y", "-i", temp_path,
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
            print(f"[ERROR] {path}: Encode failed")
            
    except Exception as e:
        if os.path.exists(temp_path) and not os.path.exists(output):
            os.rename(temp_path, path)
        print(f"[ERROR] {path}: {e}")

def calcRate(path, before, after):
    if before == 0:
        print(f"[--.--%] {path}")
        return
    rate = ((before - after) / before) * 100
    print(f"[{rate:.2f}%] {path}")

def main(path):
    if not os.path.exists(path):
        print(f"[ERROR] {path}: dir not found")
        return

    # walk lower directory
    for root, dirs, files in os.walk(path):
        target_files = []
        for f in files:
            ext = os.path.splitext(f)[1].lower().lstrip('.')
            if ext in IMGS or ext in VIDS:
                target_files.append(f)
        
        # proceed if target exists
        if target_files:
            print("\n=========================")
            print(f"{root}\n")
            for f in target_files:
                print(f" - {f}")
            print("=========================\n")
            input("press ENTER to continue...")
            
            # convert each file
            for f in target_files:
                file_path = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower().lstrip('.')
                if ext in IMGS:
                    convImg(file_path)
                elif ext in VIDS:
                    convVid(file_path)

if __name__ == "__main__":
    tgt = input("Tgt dir: ").strip().strip('"')
    main(tgt)
    input("press ENTER to exit...")
