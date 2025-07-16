import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
import tldextract
import os
import threading
import logging
from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Config
USE_SELENIUM = False  # Set to True for JS rendering
FILTER_EXTENSIONS = [".php", ".asp", ".aspx"]  # Leave empty to disable filtering
MAX_DEPTH = 2
MAX_THREADS = 10
TARGETS_FILE = "targets.txt"

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
lock = threading.Lock()

def is_valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ('http', 'https') and bool(parsed.netloc)

def get_domain(url):
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"

def get_html(url):
    try:
        if USE_SELENIUM:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            driver = webdriver.Chrome(options=chrome_options)
            driver.get(url)
            html = driver.page_source
            driver.quit()
            return html
        else:
            response = requests.get(url, timeout=5)
            if "text/html" in response.headers.get("Content-Type", ""):
                return response.text
    except Exception as e:
        logging.debug(f"Error fetching {url}: {e}")
    return ""

def crawl_url(base_url, current_url, domain, visited, queue, found_urls, depth):
    if depth > MAX_DEPTH or current_url in visited:
        return
    html = get_html(current_url)
    if not html:
        return

    with lock:
        visited.add(current_url)
        found_urls.add(current_url)

    soup = BeautifulSoup(html, 'html.parser')
    tags = soup.find_all(['a', 'link', 'script', 'img'])

    for tag in tags:
        attr = 'href' if tag.name in ['a', 'link'] else 'src'
        link = tag.get(attr)
        if not link:
            continue
        absolute_url = urljoin(current_url, link)
        if not is_valid_url(absolute_url):
            continue
        if get_domain(absolute_url) != domain:
            continue
        if FILTER_EXTENSIONS and not any(absolute_url.lower().endswith(ext) for ext in FILTER_EXTENSIONS):
            continue

        with lock:
            if absolute_url not in visited:
                queue.append((absolute_url, depth + 1))

def crawl_domain(start_url):
    domain = get_domain(start_url)
    visited = set()
    found_urls = set()
    queue = deque([(start_url, 0)])

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        while queue:
            tasks = []
            for _ in range(min(len(queue), MAX_THREADS)):
                url, depth = queue.popleft()
                tasks.append(executor.submit(crawl_url, start_url, url, domain, visited, queue, found_urls, depth))
            for task in tasks:
                task.result()  # wait for completion

    return sorted(found_urls)

def save_to_html(domain, urls):
    filename = f"{domain.replace('.', '_')}_sitemap.html"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("<html><body><h1>Sitemap for {}</h1><ul>\n".format(domain))
        for url in urls:
            f.write(f"<li><a href='{url}'>{url}</a></li>\n")
        f.write("</ul></body></html>")
    logging.info(f"[+] Saved {len(urls)} URLs to {filename}")

def load_targets():
    if os.path.exists(TARGETS_FILE):
        with open(TARGETS_FILE, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return []

def main():
    print("[?] Enter a domain (or leave blank to use targets.txt):")
    user_input = input("Domain: ").strip()

    targets = [user_input] if user_input else load_targets()
    if not targets:
        logging.error("No targets provided.")
        return

    for target in targets:
        if not target.startswith("http"):
            target = "http://" + target
        logging.info(f"[*] Crawling: {target}")
        urls = crawl_domain(target)
        save_to_html(get_domain(target), urls)

if __name__ == "__main__":
    main()
