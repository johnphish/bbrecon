import subprocess
import webbrowser
import os
import json
import re

# -------------------------- Helpers --------------------------

def check_dependency(command):
    result = subprocess.run(['which', command], capture_output=True, text=True)
    return result.returncode == 0

def write_list_to_file(data, filename):
    with open(filename, 'w') as f:
        f.write("\n".join(data))
    print(f"  -> Saved to {filename}")

def extract_urls_with_parameters(urls):
    return [url for url in urls if "?" in url and "=" in url]

def extract_js_urls(urls):
    return [url for url in urls if url.lower().endswith('.js')]

# -------------------- Core Functionalities --------------------

def fetch_otx_urls(domain):
    print(f"[+] Fetching URLs from AlienVault OTX for {domain}")
    all_urls = []
    page = 1
    limit = 500

    while True:
        print(f"  > Page {page}...")
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list?limit={limit}&page={page}"
        result = subprocess.run(['curl', '-s', url], capture_output=True, text=True)
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            break

        urls = [entry['url'] for entry in data.get('url_list', []) if 'url' in entry]
        if not urls:
            break
        all_urls.extend(urls)

        if len(urls) < limit:
            break
        page += 1

    write_list_to_file(all_urls, 'otx_urls.txt')
    return all_urls

def fetch_wayback_urls(domain):
    print("[+] Fetching Wayback Machine URLs...")
    subprocess.run([
        'curl', '-G', "https://web.archive.org/cdx/search/cdx",
        '--data-urlencode', f"url=*.{domain}/*",
        '--data-urlencode', "collapse=urlkey",
        '--data-urlencode', "output=text",
        '--data-urlencode', "fl=original",
        '-o', 'all_urls.txt'
    ])

    subprocess.run([
        'curl',
        f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.(js|xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$",
        '-o', 'filtered_urls.txt'
    ])

    print("  -> Wayback files saved: all_urls.txt, filtered_urls.txt")

    with open("filtered_urls.txt") as f:
        return f.read().splitlines()

def run_secretfinder(js_urls):
    if not check_dependency('SecretFinder.py'):
        print("[-] SecretFinder not found. Skipping JS analysis.")
        return
    os.makedirs("secretfinder_reports", exist_ok=True)
    print(f"[+] Running SecretFinder on JS files...")
    for js_url in js_urls:
        output = f"secretfinder_reports/{re.sub(r'[:/]+', '_', js_url)}.html"
        subprocess.run(['python3', 'SecretFinder.py', '-i', js_url, '-o', 'html', '-r', output])
        print(f"  > {js_url} → {output}")

def run_sqlmap_on_urls(param_urls):
    if not check_dependency('sqlmap'):
        print("[-] sqlmap not found. Skipping SQLi tests.")
        return
    os.makedirs("sqlmap_reports", exist_ok=True)
    print(f"[+] Running sqlmap on parameterized URLs...")
    for url in param_urls:
        output = f"sqlmap_reports/{re.sub(r'[:/]+', '_', url)}.txt"
        subprocess.run(['sqlmap', '-u', url, '--batch', '--level', '2', '--risk', '1', '-o', '--output-dir', 'sqlmap_reports'])
        print(f"  > {url} → sqlmap report generated")

def open_browser_tabs(domain):
    print("[+] Opening OSINT tabs...")
    urls = [
        f"https://search.censys.io/search?resource=hosts&q={domain}",
        f"https://www.virustotal.com/gui/domain/{domain}/detection",
        f"https://shrewdeye.app/?domain={domain}"
    ]
    for url in urls:
        webbrowser.open_new_tab(url)

def run_nmap_scan(domain):
    if not check_dependency('nmap'):
        print("[-] Nmap not found.")
        return
    output_file = f"nmap_scan_{domain.replace('.', '_')}.txt"
    subprocess.run(['nmap', '-T4', '-sV', domain, '-oN', output_file])
    print(f"[+] Nmap output saved to {output_file}")

def run_wafw00f(domain):
    if not check_dependency('wafw00f'):
        print("[-] wafw00f not found.")
        return
    subprocess.run(['wafw00f', domain])

def run_feroxbuster(domain):
    if not check_dependency('feroxbuster'):
        print("[-] feroxbuster not found.")
        return
    print("[+] Running feroxbuster for directory busting...")
    subprocess.run(['feroxbuster', '-u', f"http://{domain}", '-w', '/usr/share/seclists/Discovery/Web-Content/common.txt'])

# -------------------- Main Flow --------------------

def main():
    domain = input("Enter domain (e.g., example.com): ").strip()

    all_otx_urls = fetch_otx_urls(domain)
    wayback_urls = fetch_wayback_urls(domain)
    combined_urls = all_otx_urls + wayback_urls

    js_urls = extract_js_urls(combined_urls)
    write_list_to_file(js_urls, 'javascript_urls.txt')
    if js_urls:
        run_secretfinder(js_urls)

    param_urls = extract_urls_with_parameters(combined_urls)
    write_list_to_file(param_urls, 'param_urls.txt')
    if param_urls:
        run_sqlmap_on_urls(param_urls)

    open_browser_tabs(domain)

    if input("Run quick Nmap scan? (y/n): ").lower() == 'y':
        run_nmap_scan(domain)

    if input("Run WAFW00F? (y/n): ").lower() == 'y':
        run_wafw00f(domain)

    if input("Bust directories with feroxbuster? (y/n): ").lower() == 'y':
        run_feroxbuster(domain)

    print("[+] Recon complete.")

if __name__ == "__main__":
    main()
