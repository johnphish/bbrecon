#!/usr/bin/env python3
"""
infin1te_gitleaks_recon.py
Fetch public GitHub repos by domain, clone them, run Gitleaks, and report findings.
"""
import os, sys, subprocess, argparse
from github import Github
import requests
from tqdm import tqdm
import csv

# -------- Configuration --------

GIT_EXTRA_ARGS = ["--depth", "1"]
WORKDIR = "infiniterepo_scans"

# -------- Helpers --------

def run(cmd, cwd=None):
    subprocess.run(cmd, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

# -------- GitHub Search --------

def fetch_repos_by_domain(domain, gh):
    query = f"{domain} in:readme,description"
    return gh.search_repositories(query=query, sort="stars", order="desc")

# -------- Cloning & Gitleaks --------

def clone_and_scan(repo, token):
    dest = os.path.join(WORKDIR, repo.full_name.replace("/", "__"))
    if not os.path.exists(dest):
        run(["git", "clone", *GIT_EXTRA_ARGS,
             f"https://{token}:x-oauth-basic@github.com/{repo.full_name}.git", dest])
    print(f"[+] Scanning {repo.full_name}")
    subprocess.run(["gitleaks", "detect", "--source", dest,
                    "--redact", "--report-format", "json",
                    "--report-path", f"{dest}/gitleaks-report.json"])

# -------- Optional Google Dorking --------

def fetch_from_dorks(csvfile):
    urls = []
    with open(csvfile) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if "dork" in row and "domain" in row:
                query = row["dork"].replace("{domain}", row["domain"])
                # Use search engine or Google API here...
                print(f"[i] Would run dork: {query}")
    return urls

# -------- Main --------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", action="append", help="Domain to scan")
    parser.add_argument("-f", "--file", help="File with domain list")
    parser.add_argument("--dorks", help="CSV file list of Google dorks")
    args = parser.parse_args()

    if not (args.domain or args.file):
        parser.error("Specify -d/--domain or -f/--file")

    # Build domain list
    domains = []
    if args.domain:
        domains += args.domain
    if args.file:
        domains += [l.strip() for l in open(args.file) if l.strip()]

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("Set GITHUB_TOKEN environment variable")
        sys.exit(1)

    gh = Github(token)
    ensure_dir(WORKDIR)

    for domain in domains:
        print(f"\n=== Scanning domain: {domain} ===")
        repos = fetch_repos_by_domain(domain, gh)
        for repo in tqdm(repos[:30], desc="Repos"):
            clone_and_scan(repo, token)

    if args.dorks:
        urls = fetch_from_dorks(args.dorks)
        print(f"[i] (Placeholder) Would scan {len(urls)} URLs from dorks")

if __name__ == "__main__":
    main()
