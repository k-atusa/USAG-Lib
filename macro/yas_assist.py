# test801 : yas cli assist
import os
import subprocess

YAS_PATH = "yas-lite"
EXT = "webp"
DELETE = True

def encpw(dirpath, pw, kfpath, msg):
    if not os.path.isdir(dirpath):
        raise Exception("invalid folder path")
    print(f"target: {dirpath}")

    for item in os.listdir(dirpath):
        itempath = os.path.join(dirpath, item)
        if item.lower().endswith(EXT):
            print(f"pass: {item} (already has {EXT})\n")
            continue

        base, ext = os.path.splitext(item)
        output = os.path.join(dirpath, f"{base}.{EXT}")
        print(f"encrypt: {item} -> {base}.{EXT}")

        command = [YAS_PATH, "-m", "enc", "-o", output, f"-{EXT}"]
        if pw != "":
            command = command + ["-pw", pw]
        if kfpath != "":
            command = command + ["-kf", kfpath]
        if msg != "":
            command = command + ["-msg", msg]
        command.append(itempath)

        try:
            res = subprocess.run(command, check=True, text=True, capture_output=True, encoding='utf-8')
            if res.stdout:
                print(res.stdout.strip())
            print("  success\n")
            if DELETE:
                os.remove(itempath)
        except Exception as e:
            print(f"  {e}\n")

def decpw(dirpath, pw, kfpath):
    if not os.path.isdir(dirpath):
        raise Exception("invalid folder path")
    print(f"target: {dirpath}")

    for item in os.listdir(dirpath):
        itempath = os.path.join(dirpath, item)
        if not item.lower().endswith(EXT):
            print(f"pass: {item} (does not have {EXT})\n")
            continue

        output = dirpath
        print(f"decrypt: {item} -> {dirpath}")

        command = [YAS_PATH, "-m", "dec", "-o", output]
        if pw != "":
            command = command + ["-pw", pw]
        if kfpath != "":
            command = command + ["-kf", kfpath]
        command.append(itempath)

        try:
            res = subprocess.run(command, check=True, text=True, capture_output=True, encoding='utf-8')
            if res.stdout:
                print(res.stdout.strip())
            print("  success\n")
            if DELETE:
                os.remove(itempath)
        except Exception as e:
            print(f"  {e}\n")

dirpath = "icons"
pw = "0000"
kf = ""
msg = "0000"
# encpw(dirpath, pw, kf, msg)
# decpw(dirpath, pw, kf)
