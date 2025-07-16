import subprocess
import webbrowser
import os
import json
import re
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

# ---------- Helpers ----------

def check_dependency(command):
    return subprocess.run(['which', command], capture_output=True).returncode == 0

def write_list_to_file(data, filename):
    with open(filename, 'w') as f:
        f.write("\n".join(data))
    print(f"[+] Saved to {filename}")

def extract_urls_with_parameters(urls):
    return [url for url in urls if "?" in url and "=" in url]

def extract_js_urls(urls):
    return [url for url in urls if url.lower().endswith('.js')]

# ---------- Parameter Rules ----------
param_rules = {
    "file": [
        "lfi",
        "open_redirect",
        "ssrf"
    ],
    "document": [
        "lfi",
        "ssrf"
    ],
    "folder": [
        "lfi",
        "open_redirect",
        "ssrf"
    ],
    "root": [
        "lfi",
        "ssrf"
    ],
    "path": [
        "lfi",
        "open_redirect",
        "ssrf"
    ],
    "pg": [
        "lfi",
        "ssrf"
    ],
    "style": [
        "lfi",
        "ssrf"
    ],
    "pdf": [
        "lfi"
    ],
    "template": [
        "lfi",
        "ssti"
    ],
    "php_path": [
        "lfi",
        "ssrf"
    ],
    "doc": [
        "lfi",
        "ssrf"
    ],
    "page": [
        "lfi",
        "xss",
        "ssrf"
    ],
    "name": [
        "lfi",
        "xss",
        "sqli",
        "ssti"
    ],
    "cat": [
        "lfi"
    ],
    "dir": [
        "lfi",
        "rce",
        "open_redirect",
        "ssrf"
    ],
    "action": [
        "lfi"
    ],
    "board": [
        "lfi"
    ],
    "date": [
        "lfi"
    ],
    "detail": [
        "lfi"
    ],
    "download": [
        "lfi",
        "rce"
    ],
    "prefix": [
        "lfi"
    ],
    "include": [
        "lfi"
    ],
    "inc": [
        "lfi"
    ],
    "locate": [
        "lfi"
    ],
    "show": [
        "lfi",
        "open_redirect",
        "ssrf"
    ],
    "site": [
        "lfi",
        "open_redirect",
        "ssrf"
    ],
    "type": [
        "lfi",
        "xss"
    ],
    "view": [
        "lfi",
        "open_redirect",
        "xss",
        "sqli",
        "ssrf",
        "ssti"
    ],
    "content": [
        "lfi",
        "ssti"
    ],
    "layout": [
        "lfi"
    ],
    "mod": [
        "lfi"
    ],
    "conf": [
        "lfi"
    ],
    "daemon": [
        "rce"
    ],
    "upload": [
        "rce"
    ],
    "log": [
        "rce"
    ],
    "ip": [
        "rce"
    ],
    "cli": [
        "rce"
    ],
    "cmd": [
        "rce"
    ],
    "exec": [
        "rce",
        "ssrf"
    ],
    "command": [
        "rce"
    ],
    "execute": [
        "rce",
        "ssrf"
    ],
    "ping": [
        "rce"
    ],
    "query": [
        "rce",
        "xss",
        "sqli"
    ],
    "jump": [
        "rce"
    ],
    "code": [
        "rce"
    ],
    "reg": [
        "rce"
    ],
    "do": [
        "rce"
    ],
    "func": [
        "rce"
    ],
    "arg": [
        "rce"
    ],
    "option": [
        "rce"
    ],
    "load": [
        "rce",
        "ssrf"
    ],
    "process": [
        "rce",
        "sqli"
    ],
    "step": [
        "rce"
    ],
    "read": [
        "rce"
    ],
    "function": [
        "rce"
    ],
    "req": [
        "rce"
    ],
    "feature": [
        "rce"
    ],
    "exe": [
        "rce"
    ],
    "module": [
        "rce"
    ],
    "payload": [
        "rce"
    ],
    "run": [
        "rce"
    ],
    "print": [
        "rce"
    ],
    "callback": [
        "open_redirect",
        "xss",
        "ssrf"
    ],
    "checkout": [
        "open_redirect"
    ],
    "checkout_url": [
        "open_redirect"
    ],
    "continue": [
        "open_redirect",
        "ssrf"
    ],
    "data": [
        "open_redirect",
        "ssrf"
    ],
    "dest": [
        "open_redirect",
        "ssrf"
    ],
    "destination": [
        "open_redirect"
    ],
    "domain": [
        "open_redirect",
        "ssrf"
    ],
    "feed": [
        "open_redirect",
        "ssrf"
    ],
    "file_name": [
        "open_redirect"
    ],
    "file_url": [
        "open_redirect"
    ],
    "folder_url": [
        "open_redirect"
    ],
    "forward": [
        "open_redirect"
    ],
    "from_url": [
        "open_redirect"
    ],
    "go": [
        "open_redirect"
    ],
    "goto": [
        "open_redirect"
    ],
    "host": [
        "open_redirect",
        "ssrf"
    ],
    "html": [
        "open_redirect",
        "ssrf"
    ],
    "image_url": [
        "open_redirect"
    ],
    "img_url": [
        "open_redirect"
    ],
    "load_file": [
        "open_redirect"
    ],
    "load_url": [
        "open_redirect"
    ],
    "login_url": [
        "open_redirect"
    ],
    "logout": [
        "open_redirect"
    ],
    "navigation": [
        "open_redirect",
        "ssrf"
    ],
    "next": [
        "open_redirect",
        "ssrf"
    ],
    "next_page": [
        "open_redirect"
    ],
    "Open": [
        "open_redirect"
    ],
    "out": [
        "open_redirect",
        "ssrf"
    ],
    "page_url": [
        "open_redirect"
    ],
    "port": [
        "open_redirect",
        "ssrf"
    ],
    "redir": [
        "open_redirect"
    ],
    "redirect": [
        "open_redirect",
        "ssrf",
        "ssti"
    ],
    "redirect_to": [
        "open_redirect"
    ],
    "redirect_uri": [
        "open_redirect"
    ],
    "redirect_url": [
        "open_redirect"
    ],
    "reference": [
        "open_redirect",
        "ssrf"
    ],
    "return": [
        "open_redirect",
        "ssrf"
    ],
    "return_path": [
        "open_redirect"
    ],
    "return_to": [
        "open_redirect"
    ],
    "returnTo": [
        "open_redirect"
    ],
    "return_url": [
        "open_redirect"
    ],
    "rt": [
        "open_redirect"
    ],
    "rurl": [
        "open_redirect"
    ],
    "target": [
        "open_redirect"
    ],
    "to": [
        "open_redirect",
        "ssrf"
    ],
    "uri": [
        "open_redirect",
        "ssrf"
    ],
    "url": [
        "open_redirect",
        "xss",
        "ssrf"
    ],
    "val": [
        "open_redirect",
        "ssrf"
    ],
    "validate": [
        "open_redirect",
        "ssrf"
    ],
    "window": [
        "open_redirect",
        "ssrf"
    ],
    "q": [
        "xss"
    ],
    "s": [
        "xss"
    ],
    "search": [
        "xss",
        "sqli"
    ],
    "lang": [
        "xss"
    ],
    "keyword": [
        "xss",
        "sqli"
    ],
    "keywords": [
        "xss"
    ],
    "year": [
        "xss"
    ],
    "email": [
        "xss",
        "xss"
    ],
    "p": [
        "xss"
    ],
    "jsonp": [
        "xss"
    ],
    "api_key": [
        "xss"
    ],
    "api": [
        "xss"
    ],
    "password": [
        "xss"
    ],
    "emailto": [
        "xss"
    ],
    "token": [
        "xss"
    ],
    "username": [
        "xss"
    ],
    "csrf_token": [
        "xss"
    ],
    "unsubscribe_token": [
        "xss"
    ],
    "id": [
        "xss",
        "sqli",
        "ssti"
    ],
    "item": [
        "xss"
    ],
    "page_id": [
        "xss"
    ],
    "month": [
        "xss"
    ],
    "immagine": [
        "xss"
    ],
    "list_type": [
        "xss"
    ],
    "terms": [
        "xss"
    ],
    "categoryid": [
        "xss"
    ],
    "key": [
        "xss"
    ],
    "l": [
        "xss"
    ],
    "begindate": [
        "xss"
    ],
    "enddate": [
        "xss"
    ],
    "select": [
        "sqli"
    ],
    "report": [
        "sqli"
    ],
    "role": [
        "sqli"
    ],
    "update": [
        "sqli"
    ],
    "user": [
        "sqli"
    ],
    "sort": [
        "sqli"
    ],
    "where": [
        "sqli"
    ],
    "params": [
        "sqli"
    ],
    "row": [
        "sqli"
    ],
    "table": [
        "sqli"
    ],
    "from": [
        "sqli"
    ],
    "sel": [
        "sqli"
    ],
    "results": [
        "sqli"
    ],
    "sleep": [
        "sqli"
    ],
    "fetch": [
        "sqli"
    ],
    "order": [
        "sqli"
    ],
    "column": [
        "sqli"
    ],
    "field": [
        "sqli"
    ],
    "delete": [
        "sqli",
        "ssrf"
    ],
    "string": [
        "sqli"
    ],
    "number": [
        "sqli"
    ],
    "filter": [
        "sqli"
    ],
    "access": [
        "ssrf"
    ],
    "admin": [
        "ssrf"
    ],
    "dbg": [
        "ssrf"
    ],
    "debug": [
        "ssrf"
    ],
    "edit": [
        "ssrf"
    ],
    "grant": [
        "ssrf"
    ],
    "test": [
        "ssrf"
    ],
    "alter": [
        "ssrf"
    ],
    "clone": [
        "ssrf"
    ],
    "create": [
        "ssrf"
    ],
    "disable": [
        "ssrf"
    ],
    "enable": [
        "ssrf"
    ],
    "make": [
        "ssrf"
    ],
    "modify": [
        "ssrf"
    ],
    "rename": [
        "ssrf"
    ],
    "reset": [
        "ssrf"
    ],
    "shell": [
        "ssrf"
    ],
    "toggle": [
        "ssrf"
    ],
    "adm": [
        "ssrf"
    ],
    "cfg": [
        "ssrf"
    ],
    "open": [
        "ssrf"
    ],
    "img": [
        "ssrf"
    ],
    "filename": [
        "ssrf"
    ],
    "preview": [
        "ssti"
    ],
    "activity": [
        "ssti"
    ]
}

def categorize_param_urls(param_urls):
    categorized = defaultdict(list)
    for url in param_urls:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        for param in query:
            key = param.lower()
            if key in param_rules:
                for vuln in param_rules[key]:
                    categorized[vuln].append(url)
    for vuln, urls in categorized.items():
        write_list_to_file(urls, f"potential_{vuln}.txt")
    return categorized

def fetch_wayback_urls(domain):
    print(f"[+] Fetching Wayback URLs for {domain}...")
    all_urls = f"wayback_all_urls.txt"
    filtered_urls = f"wayback_filtered_urls.txt"
    subprocess.run([
        "curl", "-G", "https://web.archive.org/cdx/search/cdx",
        "--data-urlencode", f"url=*.{domain}/*",
        "--data-urlencode", "collapse=urlkey",
        "--data-urlencode", "output=text",
        "--data-urlencode", "fl=original",
        "-o", all_urls
    ])
    subprocess.run([
        "curl",
        f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.(js|pdf|sql|docx|xlsx|env|zip|tar|gz|log|db|bak)$",
        "-o", filtered_urls
    ])
    print("[+] Wayback fetch complete.")
    return all_urls

def run_sqlmap_on_urls(urls):
    for url in urls:
        print(f"[SQLMAP] Testing: {url}")
        subprocess.run(["sqlmap", "-u", url, "--batch", "-o", "--output-dir=sqlmap_results"])

def run_secretfinder(js_urls):
    for url in js_urls:
        print(f"[SecretFinder] Scanning: {url}")
        subprocess.run(["SecretFinder.py", "-i", url, "-o", "cli"])

def main():
    domain = input("Enter the domain (e.g., example.com): ").strip()
    fetch_wayback_urls(domain)

    # Read all fetched URLs
    all_urls = []
    if os.path.exists("wayback_all_urls.txt"):
        with open("wayback_all_urls.txt", "r") as f:
            all_urls = [line.strip() for line in f if line.strip()]

    js_urls = extract_js_urls(all_urls)
    param_urls = extract_urls_with_parameters(all_urls)

    write_list_to_file(js_urls, "javascript_urls.txt")
    write_list_to_file(param_urls, "parameterized_urls.txt")

    if js_urls:
        print("\n[+] Running SecretFinder on JS files...")
        run_secretfinder(js_urls)

    if param_urls:
        print("\n[+] Categorizing param URLs by potential vuln...")
        categorized = categorize_param_urls(param_urls)

        if "sqli" in categorized:
            if input("Run sqlmap on SQLi-suspected URLs? (y/n): ").lower() == "y":
                run_sqlmap_on_urls(categorized["sqli"])

    # Open recon tools in browser
    print("\n[+] Opening recon tools...")
    webbrowser.open(f"https://search.censys.io/search?query={domain}")
    webbrowser.open(f"https://www.virustotal.com/gui/domain/{domain}")
    webbrowser.open(f"https://shrewdeye.app/?d={domain}")

    if input("Run nmap scan? (y/n): ").lower() == "y":
        subprocess.run(["nmap", "-T4", "-sV", domain, "-oN", "nmap_scan.txt"])

    if input("Run wafw00f to detect WAF/tech stack? (y/n): ").lower() == "y":
        subprocess.run(["wafw00f", domain])

    if input("Run feroxbuster for directory busting? (y/n): ").lower() == "y":
        subprocess.run(["feroxbuster", "-u", f"http://{domain}", "-o", "feroxbuster.txt"])

if __name__ == "__main__":
    main()

