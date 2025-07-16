import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
import tldextract
import os

def is_valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ('http', 'https') and bool(parsed.netloc)

def get_domain(url):
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"

def crawl_domain(start_url, max_depth=3):
    visited = set()
    queue = deque([(start_url, 0)])
    domain = get_domain(start_url)

    found_urls = []

    while queue:
        current_url, depth = queue.popleft()
        if current_url in visited or depth > max_depth:
            continue

        try:
            response = requests.get(current_url, timeout=5)
            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                continue
        except Exception as e:
            continue

        visited.add(current_url)
        found_urls.append(current_url)

        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup.find_all(['a', 'link', 'script', 'img']):
            attr = 'href' if tag.name == 'a' or tag.name == 'link' else 'src'
            link = tag.get(attr)
            if not link:
                continue

            absolute_url = urljoin(current_url, link)
            if is_valid_url(absolute_url) and get_domain(absolute_url) == domain:
                queue.append((absolute_url, depth + 1))

    return sorted(set(found_urls))

def save_to_html(domain, urls):
    filename = f"{domain.replace('.', '_')}_sitemap.html"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("<html><body><h1>Sitemap for {}</h1><ul>\n".format(domain))
        for url in urls:
            f.write(f"<li><a href='{url}'>{url}</a></li>\n")
        f.write("</ul></body></html>")
    print(f"[+] Saved {len(urls)} URLs to {filename}")

def main():
    target_file = "targets.txt"
    if not os.path.exists(target_file):
        print(f"[!] Target list '{target_file}' not found.")
        return

    with open(target_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    for target in targets:
        print(f"[*] Crawling {target}...")
        urls = crawl_domain(target)
        save_to_html(get_domain(target), urls)

if __name__ == "__main__":
    main()
