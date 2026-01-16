# test791 : piczip

import sys
import os
import shutil
import zipfile

def create_zip(image_path, input_paths, output_path):
    # copy image file
    try:
        with open(image_path, 'rb') as f_src:
            with open(output_path, 'wb') as f_dst:
                shutil.copyfileobj(f_src, f_dst)
        print(f"image file copied: {output_path}")
    except Exception as e:
        print(f"image file copy error: {e}")
        return

    # add zip data
    try:
        with zipfile.ZipFile(output_path, 'a', zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for target in input_paths:
                if os.path.isfile(target): # single file
                    name = os.path.basename(target)
                    zf.write(target, name)
                    print(f"added file {target} as {name}")
                
                elif os.path.isdir(target): # directory
                    abs_target = os.path.abspath(target)
                    parent_dir = os.path.dirname(abs_target)
                    for root, dirs, files in os.walk(target):
                        # add root dir
                        rel_path = os.path.relpath(root, parent_dir).replace("\\", "/")
                        if rel_path[-1] != '/':
                            rel_path += '/'
                        zf.writestr(rel_path, '')
                        print(f"added dir {rel_path}")
                        for file in files: # add files
                            full_path = os.path.join(root, file)
                            rel_path = os.path.relpath(full_path, parent_dir)
                            zf.write(full_path.replace("\\", "/"), rel_path)
                            print(f"added file {full_path} as {rel_path}")

        print(f"completed zip to {output_path}")
    except Exception as e:
        print(f"zip error: {e}")

if __name__ == "__main__":
    img_path = ""
    out_path = ""
    targets = [ ]

    # get arguments
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "-img" and i + 1 < len(sys.argv):
            img_path = sys.argv[i + 1]
            i += 2
        elif arg == "-o" and i + 1 < len(sys.argv):
            out_path = sys.argv[i + 1]
            i += 2
        else:
            targets.append(arg)
            i += 1

    # get manually
    if img_path == "":
        img_path = input("image path: ").strip()
    if out_path == "":
        out_path = input("output path: ").strip()
    if len(targets) == 0:
        i = " "
        while i != "":
            i = input("target (ENTER to end): ").strip()
            if i != "":
                targets.append(i)

    # create zip
    create_zip(img_path, targets, out_path)
