import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import json
import os

requests.packages.urllib3.disable_warnings()

visited = set()
sitemap = {}

def normalize_url(base, link):
    return urljoin(base, link.split('#')[0])

def extract_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all(["a", "link", "script", "img", "form"]):
        for attr in ["href", "src", "action"]:
            link = tag.get(attr)
            if link:
                full_url = normalize_url(base_url, link)
                if full_url.startswith("http"):
                    links.add(full_url)
    return links

def add_to_sitemap(domain, path):
    if domain not in sitemap:
        sitemap[domain] = set()
    sitemap[domain].add(path)

def crawl(url, depth=2):
    if url in visited or depth <= 0:
        return
    visited.add(url)

    try:
        resp = requests.get(url, timeout=5, verify=False)
        parsed = urlparse(url)
        if "text/html" in resp.headers.get("Content-Type", ""):
            add_to_sitemap(parsed.netloc, parsed.path or "/")
            links = extract_links(resp.text, url)
            for link in links:
                crawl(link, depth - 1)
    except Exception:
        pass

def build_tree():
    nodes = []
    links = []
    domain_nodes = {}

    for domain, paths in sitemap.items():
        domain_id = f"domain_{domain}"
        nodes.append({"id": domain_id, "name": domain, "group": 1})
        domain_nodes[domain] = domain_id
        for path in paths:
            path_id = f"{domain}_{path}"
            nodes.append({"id": path_id, "name": path, "group": 2})
            links.append({"source": domain_id, "target": path_id})
    return {"nodes": nodes, "links": links}

def main():
    input_domains = input("Enter domains (comma-separated): ").split(",")
    input_domains = [d.strip() for d in input_domains if d.strip()]

    for domain in input_domains:
        if not domain.startswith("http"):
            domain = "https://" + domain
        print(f"[+] Crawling: {domain}")
        crawl(domain, depth=2)

    tree_data = build_tree()
    with open("site_structure.json", "w") as f:
        json.dump(tree_data, f, indent=2)

    print("[+] Site structure saved to site_structure.json")
