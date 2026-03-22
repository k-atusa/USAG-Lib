# test802 : simple filediv
import os

DELETE = True

def pack(filepath, chunksize = 10485760):
    if not os.path.isfile(filepath):
        raise Exception(f"{filepath} not exists")
    num = 0
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunksize)
            if not chunk:
                break
            partname = f"{filepath}.{num}"
            with open(partname, 'wb') as part_file:
                part_file.write(chunk)
            print(f"generated: {partname}")
            num += 1
    if DELETE:
        os.remove(filepath)
    print("completed")

def unpack(startpath):
    if not startpath.endswith('.0'):
        raise Exception("start file should be end with '.0'")
    basepath = startpath[:-2] 
    if os.path.exists(basepath):
        raise Exception(f"{basepath} already exists")
    num = 0
    with open(basepath, 'wb') as f:
        while True:
            partname = f"{basepath}.{num}"
            if not os.path.isfile(partname):
                break
            with open(partname, 'rb') as t:
                f.write(t.read())
            print(f"merged: {partname} to {basepath}")
            num += 1
    if DELETE:
        for i in range(0, num):
            os.remove(f"{basepath}.{i}")
    print("completed")
