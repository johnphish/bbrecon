import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import os

# === ASCII Art ===
ASCII_ART = r"""
############################
#                          #
#   __    __  _____  ___   #
#  / / /\ \ \/__   \/ __\  #
#  \ \/  \/ /  / /\/ _\    #
#   \  /\  /  / / / /      #
#    \/  \/   \/  \/       #
#                          #
############################
                                             
Fast Vuln Scanner - by INFIN1TEXPL0IT
"""

print(ASCII_ART)

# === Configurations ===
MAX_THREADS = 20
TIMEOUT = 10

# === User agents list ===
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.198 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.65 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; GT-I9505 Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
        "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/114.0",
        "Mozilla/5.0 (iPad; CPU OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15",
        "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
        "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.137 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
        "Mozilla/5.0 (Linux; Android 9; Redmi Note 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.126 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0",
        "Mozilla/5.0 (Linux; U; Android 4.2.2; en-us; GT-P5113 Build/JDQ39) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19577",
        "Mozilla/5.0 (X11) AppleWebKit/62.41 (KHTML, like Gecko) Edge/17.10859 Safari/452.6",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14931",
        "Chrome (AppleWebKit/537.1; Chrome50.0; Windows NT 6.3) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.9200",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.16) Gecko/20120421 Firefox/11.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:11.0) Gecko Firefox/11.0",
        "Mozilla/5.0 (Windows NT 6.1; U;WOW64; de;rv:11.0) Gecko Firefox/11.0",
        "Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0",
        "Mozilla/6.0 (Macintosh; I; Intel Mac OS X 11_7_9; de-LI; rv:1.9b4) Gecko/2012010317 Firefox/10.0a4",
        "Mozilla/5.0 (Macintosh; I; Intel Mac OS X 11_7_9; de-LI; rv:1.9b4) Gecko/2012010317 Firefox/10.0a4",
        "Mozilla/5.0 (X11; Mageia; Linux x86_64; rv:10.0.9) Gecko/20100101 Firefox/10.0.9",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:9.0a2) Gecko/20111101 Firefox/9.0a2",
        "Mozilla/5.0 (Windows NT 6.2; rv:9.0.1) Gecko/20100101 Firefox/9.0.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:9.0) Gecko/20100101 Firefox/9.0",
        "Mozilla/5.0 (Windows NT 5.1; rv:8.0; en_us) Gecko/20100101 Firefox/8.0",
        "Mozilla/5.0 (Windows NT 6.1; rv:6.0) Gecko/20100101 Firefox/7.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110613 Firefox/6.0a2",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110612 Firefox/6.0a2",
        "Mozilla/5.0 (X11; Linux i686; rv:6.0) Gecko/20100101 Firefox/6.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.90 Safari/537.36",
        "Mozilla/5.0 (X11; NetBSD) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
        "Mozilla/5.0 (X11; CrOS i686 3912.101.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.60 Safari/537.17",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1309.0 Safari/537.17",
        "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.15 (KHTML, like Gecko) Chrome/24.0.1295.0 Safari/537.15",
        "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.14 (KHTML, like Gecko) Chrome/24.0.1292.0 Safari/537.14",
        "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1290.1 Safari/537.13",
      "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1290.1 Safari/537.13"
    
]

# Lock for thread-safe writes
lock = threading.Lock()

# Global results storage
results = []

# === Payload loaders (you implement payload files yourself) ===
def load_payloads(payload_type):
    filename = f"payloads/{payload_type}.txt"
    if not os.path.isfile(filename):
        print(f"[!] Payload file not found: {filename}")
        return []
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

# Example loading payloads for different vuln types (extend as needed)
payloads = {
    "sqli": load_payloads("sqli"),
    "xss": load_payloads("xss"),
    "rce": load_payloads("rce"),
    "xxe": load_payloads("xxe"),
    "open_redirect": load_payloads("open_redirect"),
    "idor": load_payloads("idor"),
}

# === Vulnerability test stub ===
def test_vulnerability(url, param, payload):
    """
    Stub function to test a single vuln payload against a param in URL.
    You implement your own detection logic here.
    """
    try:
        # Build URL with injected payload
        if "?" in url:
            target_url = f"{url}&{param}={payload}"
        else:
            target_url = f"{url}?{param}={payload}"

        headers = {"User-Agent": USER_AGENTS[0]}  # Can randomize if desired
        resp = requests.get(target_url, headers=headers, timeout=TIMEOUT, verify=False)

        # Simple heuristic: check if payload is reflected or error codes, customize this
        if payload in resp.text:
            return True, target_url
        if resp.status_code >= 500:
            return True, target_url

        return False, None
    except Exception as e:
        # print(f"[!] Request failed: {e}")
        return False, None

# === Worker function for threads ===
def worker(url, param):
    found_vulns = []
    for vuln_type, payload_list in payloads.items():
        for payload in payload_list:
            vulnerable, test_url = test_vulnerability(url, param, payload)
            if vulnerable:
                with lock:
                    found_vulns.append((vuln_type, test_url))
                break  # Stop testing further payloads for this vuln type
    if found_vulns:
        with lock:
            for vuln, vul_url in found_vulns:
                results.append({
                    "url": url,
                    "param": param,
                    "vuln": vuln,
                    "test_url": vul_url,
                })
        print(f"[+] Vulns found for {url} param={param}: {[v[0] for v in found_vulns]}")

# === Load targets ===
def load_targets():
    choice = input("Choose input method:\n1. Enter single domain\n2. Load from targets.txt file\nChoice (1/2): ").strip()
    targets = []

    if choice == "1":
        domain = input("Enter domain (include http/https, e.g. http://stupiddomain.com): ").strip()
        # For demo, let's create some example params (you can expand)
        params = input("Enter parameters to test, separated by commas (e.g. id,q,search): ").strip()
        param_list = [p.strip() for p in params.split(",") if p.strip()]
        for param in param_list:
            targets.append((domain, param))

    elif choice == "2":
        if not os.path.isfile("targets.txt"):
            print("[!] targets.txt file not found.")
            return []
        with open("targets.txt", "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    url, param = parts[0], parts[1]
                    targets.append((url, param))
                else:
                    print(f"[!] Invalid line in targets.txt: {line}")
    else:
        print("[!] Invalid choice")
        return []

    return targets

# === HTML report generation ===
def generate_html_report(results, filename="scan_report.html"):
    html_header = """
    <html><head><title>Stupid Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even){background-color: #f2f2f2;}
    </style>
    </head><body>
    <h2>Vulnerability Scan Report</h2>
    <table>
        <tr><th>URL</th><th>Parameter</th><th>Vulnerability</th><th>Test URL</th></tr>
    """
    html_footer = "</table></body></html>"

    rows = ""
    for r in results:
        rows += f"<tr><td>{r['url']}</td><td>{r['param']}</td><td>{r['vuln']}</td><td><a href='{r['test_url']}' target='_blank'>Test Link</a></td></tr>"

    with open(filename, "w") as f:
        f.write(html_header + rows + html_footer)
    print(f"[+] Report saved to {filename}")

# === Main ===
def main():
    targets = load_targets()
    if not targets:
        print("[!] No targets to scan.")
        return

    print(f"[+] Loaded {len(targets)} targets. Starting scan with {MAX_THREADS} threads...")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(worker, url, param) for url, param in targets]

        for _ in as_completed(futures):
            pass  # Can add progress here if you want

    print(f"[+] Scan finished. {len(results)} vulnerabilities found.")
    generate_html_report(results)

if __name__ == "__main__":
    main()
