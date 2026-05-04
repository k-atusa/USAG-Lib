# test811 : codemerge
import os

TEXT_EXTS = ("c", "cpp", "cs", "css", "dart", "go", "h", "hpp", "htm", "html", "java", "js", "kt", "lua", "php", "py", "r", "rb", "rs", "sh", "ts", "csv", "json", "md", "txt", "xml")
EXCLUDE_DIRS = (".git", "node_modules", "build", "bin", "pkg", "target", ".idea", ".venv", "__pycache__")

def merge(tgtDir, output="merged.txt"):
    with open(output, 'w', encoding='utf-8') as f:
        f.write(f"Merged Codes of [{os.path.basename(tgtDir)}]\n\n") # write title
        for root, dirs, files in os.walk(tgtDir):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            
            for file in files:
                path = os.path.join(root, file)
                relative = os.path.relpath(path, tgtDir)
                f.write("="*50 + f"\n{relative}\n" + "="*50 + "\n") # write header

                ext = file.split('.')[-1].lower() if '.' in file else ""
                if ext in TEXT_EXTS: # write text
                    try:
                        with open(path, 'r', encoding='utf-8') as t:
                            f.write(t.read() + "\n\n")
                            print(f"added data {relative}")
                    except Exception as e:
                        print(f"Error {e} at {relative}")
                        
                else: # skip data
                    f.write("(non-code, skiped)\n\n")
                    print(f"added header {relative}")

#merge("./")
