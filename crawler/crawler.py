import json
import os
import tldextract
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

OUTPUT_DIR = "crawl_results"
TARGETS_FILE = "targets.txt"
MAX_PAGES = 10  # Number of pages to visit per domain

os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_domain_root(url):
    parts = tldextract.extract(url)
    return f"{parts.domain}.{parts.suffix}"

def get_browser():
    caps = DesiredCapabilities.CHROME
    caps["goog:loggingPrefs"] = {"performance": "ALL"}

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--log-level=3")

    return webdriver.Chrome(desired_capabilities=caps, options=chrome_options)

def extract_requests(driver):
    logs = driver.get_log("performance")
    urls = set()

    for entry in logs:
        try:
            message = json.loads(entry["message"])["message"]
            if message["method"] == "Network.requestWillBeSent":
                url = message["params"]["request"]["url"]
                urls.add(url)
        except Exception:
            continue
    return urls

def crawl_full_asset_map(start_url, max_pages=MAX_PAGES):
    visited_urls = set()
    all_assets = set()
    queue = [start_url]
    browser = get_browser()

    while queue and len(visited_urls) < max_pages:
        url = queue.pop(0)
        if url in visited_urls:
            continue
        print(f"[+] Visiting: {url}")
        try:
            browser.get(url)
            visited_urls.add(url)
            assets = extract_requests(browser)
            all_assets.update(assets)

            # Add discovered links to queue (simple version)
            new_links = [link for link in assets if link.startswith("http") and get_domain_root(link) == get_domain_root(start_url)]
            queue.extend([l for l in new_links if l not in visited_urls])
        except Exception as e:
            print(f"[!] Failed: {url} ({e})")
            continue

    browser.quit()
    return visited_urls, all_assets

def save_output(domain, visited, assets):
    base = domain.replace('.', '_')
    html_file = os.path.join(OUTPUT_DIR, f"{base}_sitemap.html")
    json_file = os.path.join(OUTPUT_DIR, f"{base}_assets.json")

    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(f"<html><body><h1>Assets for {domain}</h1><ul>\n")
        for url in sorted(assets):
            f.write(f"<li><a href='{url}'>{url}</a></li>\n")
        f.write("</ul></body></html>")

    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(sorted(assets), f, indent=2)

    print(f"[✓] Saved {len(assets)} assets to {html_file} and {json_file}")

def run():
    user_input = input("Enter a domain (or press Enter to use targets.txt): ").strip()
    targets = [user_input] if user_input else []

    if not targets:
        if os.path.exists(TARGETS_FILE):
            with open(TARGETS_FILE, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        else:
            print("No domain input or targets.txt found.")
            return

    for target in targets:
        if not target.startswith("http"):
            target = "http://" + target
        print(f"\n=== Crawling {target} ===")
        visited, assets = crawl_full_asset_map(target)
        save_output(get_domain_root(target), visited, assets)

if __name__ == "__main__":
    run()
