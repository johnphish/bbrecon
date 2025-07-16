import os
import json
import time
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup

# === CONFIG ===
OUTPUT_DIR = "crawl_results"
TARGETS_FILE = "targets.txt"
MAX_PAGES = 50
WAIT_TIME = 2
MAX_WORKERS = 5

os.makedirs(OUTPUT_DIR, exist_ok=True)

# === BROWSER SETUP ===
def get_browser():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--log-level=3")
    options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    return webdriver.Chrome(options=options)

# === URL EXTRACTION ===
def extract_network_urls(driver, base_domain):
    urls = set()
    try:
        logs = driver.get_log("performance")
        for entry in logs:
            msg = json.loads(entry["message"])["message"]
            if msg.get("method") == "Network.requestWillBeSent":
                url = msg["params"]["request"]["url"]
                if urlparse(url).netloc == base_domain:
                    urls.add(url)
    except Exception as e:
        print(f"[!] Error parsing logs: {e}")
    return urls

def extract_dom_urls(html, base_url, base_domain):
    soup = BeautifulSoup(html, 'html.parser')
    urls = set()
    for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'source']):
        for attr in ['href', 'src', 'data-src']:
            url = tag.get(attr)
            if url:
                full_url = urljoin(base_url, url)
                if urlparse(full_url).netloc == base_domain:
                    urls.add(full_url)
    return urls

# === CRAWLER ===
def crawl_single_url(url, base_domain, visited):
    driver = get_browser()
    assets = set()

    try:
        print(f"[+] Visiting: {url}")
        driver.get(url)
        time.sleep(WAIT_TIME)
        html = driver.page_source

        dom_urls = extract_dom_urls(html, url, base_domain)
        net_urls = extract_network_urls(driver, base_domain)
        all_urls = dom_urls.union(net_urls)

        assets.update(all_urls)

    except Exception as e:
        print(f"[!] Error on {url}: {e}")
    finally:
        driver.quit()

    return {url}, assets, all_urls

def crawl(start_url):
    base_domain = urlparse(start_url).netloc
    visited = set()
    assets_found = set()
    queue = [start_url]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while queue and len(visited) < MAX_PAGES:
            tasks = []
            for url in queue[:MAX_WORKERS]:
                if url not in visited:
                    tasks.append(executor.submit(crawl_single_url, url, base_domain, visited))

            queue = queue[MAX_WORKERS:]

            for task in as_completed(tasks):
                v, assets, new_urls = task.result()
                visited.update(v)
                assets_found.update(assets)
                for link in new_urls:
                    if link not in visited and link not in queue:
                        queue.append(link)

    return visited, assets_found

# === SAVE RESULTS ===
def save_results(domain, visited, assets):
    safe_domain = domain.replace('.', '_')
    html_file = os.path.join(OUTPUT_DIR, f"{safe_domain}_sitemap.html")
    json_file = os.path.join(OUTPUT_DIR, f"{safe_domain}_assets.json")

    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(f"<html><body><h1>Sitemap for {domain}</h1><ul>")
        for url in sorted(visited):
            f.write(f"<li><a href='{url}' target='_blank'>{url}</a></li>")
        f.write("</ul></body></html>")

    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(sorted(assets), f, indent=2)

    print(f"[✓] Saved {len(visited)} pages and {len(assets)} unique assets.")

# === MAIN ENTRYPOINT ===
def main():
    user_input = input("Enter domain (or leave blank to use targets.txt): ").strip()
    targets = [user_input] if user_input else []

    if not targets and os.path.exists(TARGETS_FILE):
        with open(TARGETS_FILE, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    elif not targets:
        print("No domain or targets.txt provided.")
        return

    for target in targets:
        if not target.startswith("http"):
            target = "http://" + target
        print(f"\n=== Crawling: {target} ===")
        visited, assets = crawl(target)
        save_results(urlparse(target).netloc, visited, assets)

if __name__ == "__main__":
    main()
