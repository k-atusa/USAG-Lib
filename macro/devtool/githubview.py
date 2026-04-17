# test809 : githubview
import requests
import re
from datetime import datetime

def get_repo_details(owner, repo_name, headers):
    """Fetch and return detailed stats for a single repository."""
    base_url = f"https://api.github.com/repos/{owner}/{repo_name}"
    
    # 1. Base Info
    res = requests.get(base_url, headers=headers)
    if res.status_code != 200:
        return None
    
    repo = res.json()
    
    # 2. Languages
    lang_res = requests.get(repo['languages_url'], headers=headers)
    languages = lang_res.json() if lang_res.status_code == 200 else {}
    
    # 3. Contributors (Top 5)
    contributor_url = f"{base_url}/contributors?per_page=5"
    cont_res = requests.get(contributor_url, headers=headers)
    contributors = [c['login'] for c in cont_res.json()] if cont_res.status_code == 200 else []

    # 4. Format Data
    created_at = datetime.strptime(repo.get('created_at'), "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M")
    pushed_at = datetime.strptime(repo.get('pushed_at'), "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M")
    size_mb = repo.get('size', 0) / 1024

    return {
        "name": repo.get('name'),
        "full_name": repo.get('full_name'),
        "desc": repo.get('description') or "N/A",
        "stars": repo.get('stargazers_count', 0),
        "forks": repo.get('forks_count', 0),
        "subscribers": repo.get('subscribers_count', 0),
        "open_issues": repo.get('open_issues_count', 0),
        "size_mb": size_mb,
        "languages": languages,
        "created_at": created_at,
        "pushed_at": pushed_at,
        "contributors": contributors
    }

def print_repo_stats(stats):
    """Print the repository statistics in a concise format."""
    if not stats:
        print("[!] Failed to fetch repo data.")
        return

    print("-" * 50)
    print(f"Repo  : {stats['full_name']}")
    print(f"Desc  : {stats['desc']}")
    print(f"Stats : {stats['stars']} Stars | {stats['forks']} Forks | {stats['subscribers']} Subs | {stats['open_issues']} Issues")
    print(f"Size  : {stats['size_mb']:.2f} MB")
    
    if stats['languages']:
        lang_str = ", ".join([f"{lang} ({byte}B)" for lang, byte in stats['languages'].items()])
        print(f"Langs : {lang_str}")
    else:
        print("Langs : N/A")
        
    print(f"Dates : Created {stats['created_at']} | Pushed {stats['pushed_at']}")
    print(f"Contr.: {', '.join(stats['contributors']) if stats['contributors'] else 'N/A'}")

def get_user_repos(target_url, token=None):
    """Extract username from URL and fetch all public repos."""
    # Extract username/org from URL
    match = re.search(r'github\.com/([^/]+)', target_url)
    username = match.group(1) if match else target_url
    
    # Setup Headers
    headers = {'Accept': 'application/vnd.github.v3+json'}
    if token:
        headers['Authorization'] = f'token {token}'

    print(f"\n[*] Fetching repos for: {username}...\n")
    
    # Fetch Repo List (Limit to 100 per page for efficiency)
    repos_url = f"https://api.github.com/users/{username}/repos?per_page=100"
    res = requests.get(repos_url, headers=headers)
    
    if res.status_code != 200:
        print(f"[!] Error: HTTP {res.status_code}")
        return

    repos = res.json()
    if not repos:
        print("[-] No public repositories found.")
        return

    # Iterate and fetch details for each repo
    for repo in repos:
        stats = get_repo_details(username, repo['name'], headers)
        print_repo_stats(stats)

# get_user_repos("https://github.com/taewook427", token=None)
# print_repo_stats( get_repo_details("k-atusa", "USAG-Lib", {}) )
