import subprocess
import webbrowser
import os
import json

def check_dependency(command):
    result = subprocess.run(['which', command], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[-] Required tool '{command}' is not installed.")
        return False
    return True

def fetch_otx_urls(domain):
    print(f"[+] Fetching URLs from AlienVault OTX for domain: {domain}")
    page = 1
    limit = 500

    while True:
        print(f"  > Fetching page {page}...")
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list?limit={limit}&page={page}"
        result = subprocess.run(['curl', '-s', url], capture_output=True, text=True)
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            print("  ! Invalid JSON returned.")
            break

        urls = [entry['url'] for entry in data.get('url_list', []) if 'url' in entry]

        if not urls:
            print(f"  > No more URLs found on page {page}.")
            break

        for u in urls:
            print(f"    - {u}")

        if len(urls) < limit:
            print("  > Last page reached.")
            break

        page += 1

def fetch_wayback_urls(domain):
    print("[+] Fetching all URLs from the Wayback Machine...")
    all_url_cmd = [
        'curl', '-G', "https://web.archive.org/cdx/search/cdx",
        '--data-urlencode', f"url=*.{domain}/*",
        '--data-urlencode', "collapse=urlkey",
        '--data-urlencode', "output=text",
        '--data-urlencode', "fl=original",
        '-o', 'all_urls.txt'
    ]
    subprocess.run(all_url_cmd)

    print("[+] Fetching filtered URLs (file extensions)...")
    filtered_cmd = [
        'curl',
        f"https://web.archive.org/cdx/search/cdx?url=*." + domain +
        "/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$",
        '-o', 'filtered_urls.txt'
    ]
    subprocess.run(filtered_cmd)

    print("  -> Saved all_urls.txt and filtered_urls.txt.")

def open_browser_tabs(domain):
    print("[+] Opening browser tabs...")
    urls = [
        f"https://search.censys.io/search?resource=hosts&q={domain}",
        f"https://www.virustotal.com/gui/domain/{domain}/detection",
        f"https://shrewdeye.app/?domain={domain}"
    ]
    for url in urls:
        webbrowser.open_new_tab(url)

def run_nmap_scan(domain):
    output_file = f"nmap_scan_{domain.replace('.', '_')}.txt"
    print(f"[+] Running quick Nmap scan on {domain}...")
    try:
        subprocess.run(['nmap', '-T4', '-sV', domain, '-oN', output_file])
        print(f"  -> Nmap output saved to {output_file}")
    except FileNotFoundError:
        print("[-] Nmap not found. Please install it.")

def run_wafw00f(domain):
    print(f"[+] Running wafw00f on {domain}...")
    try:
        subprocess.run(['wafw00f', domain])
    except FileNotFoundError:
        print("[-] wafw00f not found. Please install it with `pip install wafw00f`.")

def main():
    if not all(map(check_dependency, ['curl'])):
        return

    domain = input("Enter the domain (e.g., example.com): ").strip()
    if not domain:
        print("[-] Domain is required.")
        return

    fetch_otx_urls(domain)
    fetch_wayback_urls(domain)
    open_browser_tabs(domain)

    do_nmap = input("Do you want to run a quick Nmap scan? (y/n): ").lower()
    if do_nmap == 'y':
        run_nmap_scan(domain)

    do_waf = input("Do you want to run WAFW00F to detect tech stack? (y/n): ").lower()
    if do_waf == 'y':
        run_wafw00f(domain)

    print("[+] Done.")

if __name__ == "__main__":
    main()
