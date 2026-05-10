# test805 : codecount
import os
import requests
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# basic setup values
CODE_EXT = {
    "c", "cpp", "cs", "css", "dart", "go", "h", "hpp", "htm", "html", 
    "ipynb", "java", "js", "jsx", "kt", "lua", "php", "py", "r", "rb", 
    "rs", "sh", "ts", "tsx", "swift", "scala", "sql", "m"
}

DATA_EXT = {"csv", "json", "md", "txt", "yaml", "yml", "xml"}

GITHUB_COLORS = {
    "py": "#3572A5", "c": "#555555", "cpp": "#f34b7d", "cs": "#178600",
    "css": "#563d7c", "dart": "#00B4AB", "go": "#00ADD8", "h": "#555555",
    "hpp": "#f34b7d", "ipynb": "#FF7F00", "java": "#b07219", "js": "#f1e05a", 
    "jsx": "#f1e05a", "kt": "#A97BFF", "lua": "#000080", "php": "#4F5D95", 
    "r": "#198CE7", "rb": "#701516", "rs": "#dea584", "sh": "#89e051", 
    "ts": "#3178c6", "tsx": "#3178c6", "csv": "#237346", "htm": "#e34c26", 
    "html": "#e34c26", "json": "#292929", "txt": "#e3e3e3", "md": "#083fa1",
    "swift": "#ffac45", "scala": "#c22d40", "sql": "#e38c00", "m": "#438eff",
    "yaml": "#cb171e", "yml": "#cb171e", "xml": "#0060ac"
}

GITHUB_LANG_MAP = {
    "Python": "py", "C": "c", "C++": "cpp", "C#": "cs",
    "CSS": "css", "Dart": "dart", "Go": "go", "HTML": "html",
    "Java": "java", "JavaScript": "js", "JSX": "jsx", "Kotlin": "kt",
    "Lua": "lua", "PHP": "php", "R": "r", "Ruby": "rb",
    "Rust": "rs", "Shell": "sh", "TypeScript": "ts", "TSX": "tsx",
    "Jupyter Notebook": "ipynb", "Swift": "swift", "Scala": "scala",
    "SQL": "sql", "Objective-C": "m"
}

DEFAULT_COLOR = "#cccccc"

# helper functions
def get_color(ext):
    return GITHUB_COLORS.get(ext, DEFAULT_COLOR)

def count_lines(filepath):
    encodings = ["utf-8", "utf-16", "cp949"]
    for enc in encodings:
        try:
            with open(filepath, "r", encoding=enc) as f:
                return sum(1 for _ in f)
        except:
            pass
    return 0

def format_bytes(size):
    if size >= 1024 * 1024:
        return f"{size / (1024*1024):.1f} MiB"
    elif size >= 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size} B"

def draw_github_style(data_dict, title, unit_text):
    # delete zero value, sort
    filtered_data = {k: v for k, v in data_dict.items() if v > 0}
    if not filtered_data:
        print(f"[{title}] No data to show.")
        return

    sorted_data = sorted(filtered_data.items(), key=lambda x: x[1], reverse=True)
    total = sum(filtered_data.values())

    # resize figsize height
    fig, ax = plt.subplots(figsize=(10, 2.0))
    left = 0
    legend_elements = []

    # draw github style bar
    for ext, val in sorted_data:
        color = get_color(ext)
        pct = (val / total) * 100
        ax.barh(0, val, left=left, color=color, height=0.1)
        left += val
        
        # format size
        if "Byte" in unit_text:
            display_val = format_bytes(val)
        else:
            display_val = f"{val:,} {unit_text}"
            
        label = f"{ext} {pct:.1f}% ({display_val})"
        legend_elements.append(mpatches.Patch(color=color, label=label))

    # chart design
    ax.set_xlim(0, total)
    ax.set_ylim(-0.5, 0.5)
    ax.axis('off')
    plt.title(title, pad=15, fontsize=12, fontweight='bold')
    ax.legend(handles=legend_elements, loc='upper center', bbox_to_anchor=(0.5, 0.1), ncol=min(4, len(legend_elements)), frameon=False, fontsize=10)

    # chart show
    plt.tight_layout()
    plt.show()

# get data from local
def local():
    target_path = os.path.abspath(path)
    valid_ext = CODE_EXT.union(DATA_EXT)

    # init dict
    lines_by_code = {e: 0 for e in CODE_EXT}
    bytes_by_code = {e: 0 for e in CODE_EXT}
    count_by_ext = {e: 0 for e in valid_ext}
    bytes_by_ext = {e: 0 for e in valid_ext}

    print("Analyzing structure started...")
    for root, dirs, files in os.walk(target_path):
        # folder filter
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
        for file in files:
            ext = file.split('.')[-1].lower() if '.' in file else ""
            
            if ext in valid_ext:
                file_path = os.path.join(root, file)
                try:
                    # get file size and number
                    file_size = os.path.getsize(file_path)
                    bytes_by_ext[ext] += file_size
                    count_by_ext[ext] += 1
                    
                    # get size and line if code
                    if ext in CODE_EXT:
                        bytes_by_code[ext] += file_size
                        lines_by_code[ext] += count_lines(file_path)
                        
                except Exception as e:
                    pass
    print("Analyzing structure completed!")

    # supports 4 modes
    draw_github_style(lines_by_code, "Lines of Code by Language", "Lines")
    draw_github_style(bytes_by_code, "Code Size by Language", "Bytes")
    draw_github_style(count_by_ext, "File Count by Extension", "Files")
    draw_github_style(bytes_by_ext, "Total Size by Extension", "Bytes")

# get data from github
def remote(target_name):
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"

    bytes_by_code = {e: 0 for e in CODE_EXT}
    repos = []
    page = 1
    
    # get all repos from github
    print("Analyzing structure started...")
    while True:
        repos_url = f"https://api.github.com/users/{target_name}/repos?per_page=100&page={page}"
        response = requests.get(repos_url, headers=headers)
        
        if response.status_code != 200:
            print(f"failed to get data: {response.status_code}")
            return
            
        page_data = response.json()
        if not page_data:
            break
            
        repos.extend(page_data)
        page += 1

    # add all repo bytes
    original_repos = repo if include_forks else [repo for repo in repos if not repo.get("fork")] # exclude forked repos
    for repo in original_repos:
        repo_name = repo["name"]
        langs_url = repo["languages_url"]
        
        lang_response = requests.get(langs_url, headers=headers)
        if lang_response.status_code == 200:
            lang_data = lang_response.json()
            for lang_name, bytes_count in lang_data.items():
                ext = GITHUB_LANG_MAP.get(lang_name)
                if ext and ext in bytes_by_code:
                    bytes_by_code[ext] += bytes_count

    print("Analyzing structure completed!")
    draw_github_style(bytes_by_code, "Code Size by Language", "Bytes")

# setup values
path = "./" # count target folder path
exclude_dirs = {".git", "node_modules", "build", "bin", "pkg", "target", ".idea", ".venv"} # folder name that ignored
include_forks = False # count forked repos too

# local()
# remote("taewook427")
