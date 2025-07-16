import json
import os
import time
from urllib.parse import urljoin, urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from bs4 import BeautifulSoup

OUTPUT_DIR = "crawl_results"
TARGETS_FILE = "targets.txt"
MAX_PAGES = 50  # Increase pages to crawl for better coverage
WAIT_TIME = 2  # seconds to wait for page JS to load

os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_browser():
    caps = DesiredCapabilities.CHROME
    caps["goog:loggingPrefs"] = {"performance": "ALL"}

    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--log-level=3")
    driver = webdriver.Chrome(desired_capabilities=caps, options=options)
    return driver

def extract_network_urls(driver):
    logs = driver.get_log("performance")
    urls = set()
    for entry in logs:
        try:
            message = json.loads(entry["message"])["message"]
            if message["method"] == "Network.requestWillBeSent":
                url = message["params"]["request"]["url"]
                urls.add(url)
        except:
            continue
    return urls

def extract_dom_urls(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    urls = set()
    attrs = ['href', 'src', 'data-src']
    tags = ['a', 'link', 'script', 'img', 'iframe', 'source']

    for tag in soup.find_all(tags):
        for attr in attrs:
            url = tag.get(attr)
            if url:
                full_url = urljoin(base_url, url)
                urls.add(full_url)
    return urls

def crawl(start_url):
    visited = set()
    assets_found = set()
    to_visit = [start_url]

    driver = get_browser()

    while to_visit and len(visited) < MAX_PAGES:
        url = to_visit.pop(0)
        if url in visited:
            continue
        try:
            print(f"[+] Visiting: {url}")
            driver.get(url)
            time.sleep(WAIT_TIME)  # Wait for JS/AJAX content to load
            visited.add(url)

            html = driver.page_source
            dom_urls = extract_dom_urls(html, url)
            net_urls = extract_network_urls(driver)

            # Combine and add to asset list
            all_urls = dom_urls.union(net_urls)
            assets_found.update(all_urls)

            # Add new URLs to visit queue if not visited
            for link in all_urls:
                if link not in visited and link not in to_visit:
                    to_visit.append(link)

        except Exception as e:
            print(f"[!] Error visiting {url}: {e}")

    driver.quit()
    return visited, assets_found

def save_results(domain, visited, assets):
    base = domain.replace('.', '_')
    html_file = os.path.join(OUTPUT_DIR, f"{base}_sitemap.html")
    json_file = os.path.join(OUTPUT_DIR, f"{base}_assets.json")

    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(f"<html><body><h1>Assets & URLs for {domain}</h1><ul>\n")
        for url in sorted(visited):
            f.write(f"<li><a href='{url}'>{url}</a></li>\n")
        f.write("</ul></body></html>")

    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(sorted(assets), f, indent=2)

    print(f"[✓] Saved {len(visited)} visited pages and {len(assets)} assets.")

def main():
    user_input = input("Enter a domain (or leave blank to use targets.txt): ").strip()
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
        print(f"\n=== Starting crawl for {target} ===")
        visited, assets = crawl(target)
        domain = urlparse(target).netloc
        save_results(domain, visited, assets)

if __name__ == "__main__":
    main()
