# test788 : embed_bin

import sys
import os
import base64
import re

CHUNK_SIZE = 160 # max string len per line

def sanitize_name(filename): # convert filename to funcname
    name = os.path.basename(filename)
    name = os.path.splitext(name)[0]
    return re.sub(r'[^a-zA-Z0-9_]', '_', name)

def get_chunks(data_bytes): # encode data and split
    b64_str = base64.b64encode(data_bytes).decode('utf-8')
    return [b64_str[i:i+CHUNK_SIZE] for i in range(0, len(b64_str), CHUNK_SIZE)]

def generate_python(files): # python code
    lines = ["import base64", "", "class Icons:"]
    for filepath in files:
        func_name = sanitize_name(filepath)
        with open(filepath, 'rb') as f:
            chunks = get_chunks(f.read())
        
        lines.append(f"    @staticmethod")
        lines.append(f"    def {func_name}() -> bytes:")
        lines.append("        data = (")
        for chunk in chunks:
            lines.append(f"            '{chunk}'")
        lines.append("        )")
        lines.append("        return base64.b64decode(data)")
        lines.append("")
    return "\n".join(lines)

def generate_javascript(files): # javascript code
    lines = ["class Icons {"]
    for filepath in files:
        func_name = sanitize_name(filepath)
        with open(filepath, 'rb') as f:
            chunks = get_chunks(f.read())
            
        lines.append(f"    {func_name}() {{")
        lines.append("        const parts = [")
        for chunk in chunks:
            lines.append(f"            '{chunk}',")
        lines.append("        ];")
        
        lines.append("        const base64Str = parts.join('');")
        lines.append("        if (typeof Buffer !== 'undefined') { // Node.js env")
        lines.append("            return Buffer.from(base64Str, 'base64');")
        lines.append("        } else if (typeof atob === 'function') { // Browser env")
        lines.append("            const binaryString = atob(base64Str);")
        lines.append("            const len = binaryString.length;")
        lines.append("            const bytes = new Uint8Array(len);")
        lines.append("            for (let i = 0; i < len; i++) {")
        lines.append("                bytes[i] = binaryString.charCodeAt(i);")
        lines.append("            }")
        lines.append("            return bytes;")
        lines.append("        } else {")
        lines.append("            throw new Error('Unsupported environment');")
        lines.append("        }")
        lines.append("    }")
        lines.append("")
        
    lines.append("}")
    lines.append("")
    lines.append("if (typeof module !== 'undefined' && module.exports) {")
    lines.append("    module.exports = Icons;")
    lines.append("} else if (typeof window !== 'undefined') {")
    lines.append("    window.Icons = Icons;")
    lines.append("}")
    return "\n".join(lines)

def generate_go(files): # golang code
    lines = [
        "package Icons", 
        "", 
        "import (", 
        '\t"encoding/base64"', 
        '\t"strings"', 
        ")", 
        "", 
        "type Icons struct {}", 
        ""
    ]
    for filepath in files:
        func_name = sanitize_name(filepath)
        func_name = func_name[0].upper() + func_name[1:]
        
        with open(filepath, 'rb') as f:
            chunks = get_chunks(f.read())

        lines.append(f"func (i *Icons) {func_name}() ([]byte, error) {{")
        lines.append("\tparts := []string{")
        for chunk in chunks:
            lines.append(f'\t\t"{chunk}",')
        lines.append("\t}")
        lines.append('\treturn base64.StdEncoding.DecodeString(strings.Join(parts, ""))')
        lines.append("}")
        lines.append("")
    return "\n".join(lines)

def generate_java(files): # java code
    lines = [
        "import java.util.Base64;", 
        "", 
        "public class Icons {",
    ]
    for filepath in files:
        func_name = sanitize_name(filepath)
        with open(filepath, 'rb') as f:
            chunks = get_chunks(f.read())
            
        lines.append(f"    public byte[] {func_name}() {{")
        lines.append("        StringBuilder sb = new StringBuilder();")
        for chunk in chunks:
            lines.append(f'        sb.append("{chunk}");')
        lines.append("        return Base64.getDecoder().decode(sb.toString());")
        lines.append("    }")
        lines.append("")
    lines.append("}")
    return "\n".join(lines)

def main():
    files = [ ]
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            files.append(arg)   
    else:
        while True:
            path = input("filepath (ENTER to finish): ")
            if path in ["", "\n", "\r", "\r\n"]:
                break
            else:
                files.append(path)

    for tp in ["py", "js", "go", "java"]:
        if tp == "py":
            output = generate_python(files)
        elif tp == "js":
            output = generate_javascript(files)
        elif tp == "go":
            output = generate_go(files)
        elif tp == "java":
            output = generate_java(files)
        else:
            output = ""
        with open("Icons." + tp, 'w', encoding='utf-8') as f:
            f.write(output)

if __name__ == "__main__":
    main()
