#!/usr/bin/env python3
ascii_art = r"""
██╗███╗   ██╗███████╗██╗███╗   ██╗██╗████████╗███████╗██╗  ██╗███████╗██╗     ██╗████████╗
██║████╗  ██║██╔════╝██║████╗  ██║██║╚══██╔══╝██╔════╝██║ ██╔╝██╔════╝██║     ██║╚══██╔══╝
██║██╔██╗ ██║█████╗  ██║██╔██╗ ██║██║   ██║   █████╗  █████╔╝ █████╗  ██║     ██║   ██║   
██║██║╚██╗██║██╔══╝  ██║██║╚██╗██║██║   ██║   ██╔══╝  ██╔═██╗ ██╔══╝  ██║     ██║   ██║   
██║██║ ╚████║██║     ██║██║ ╚████║██║   ██║   ███████╗██║  ██╗███████╗███████╗██║   ██║   
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝   ╚═╝   
                      Open Redirect + DOM XSS Scanner
"""
print(ascii_art)

import asyncio
import aiohttp
import requests
import argparse
import re
import warnings
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

warnings.filterwarnings("ignore")

REDIRECT_PAYLOADS = [
   "//example.com@google.com/%2f..",
"///google.com/%2f..",
"///example.com@google.com/%2f..",
"////google.com/%2f..",
"https://google.com/%2f..",
"https://example.com@google.com/%2f..",
"/https://google.com/%2f..",
"/https://example.com@google.com/%2f..",
"//google.com/%2f%2e%2e",
"//example.com@google.com/%2f%2e%2e",
"///google.com/%2f%2e%2e",
"///example.com@google.com/%2f%2e%2e",
"////google.com/%2f%2e%2e",
"/http://example.com",
"/http:/example.com",
"/https:/%5cexample.com/",
"/https://%09/example.com",
"/https://%5cexample.com",
"/https:///example.com/%2e%2e",
"/https:///example.com/%2f%2e%2e",
"/https://example.com",
"/https://example.com/",
"/https://example.com/%2e%2e",
"/https://example.com/%2e%2e%2f",
"/https://example.com/%2f%2e%2e",
"/https://example.com/%2f..",
"/https://example.com//",
"/https:example.com",
"/%09/example.com",
"/%2f%2fexample.com",
"/%2f%5c%2f%67%6f%6f%67%6c%65%2e%63%6f%6d/",
"/%5cexample.com",
"/%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d",
"/.example.com",
"//%09/example.com",
"//%5cexample.com",
"///%09/example.com",
"///%5cexample.com",
"////%09/example.com",
"////%5cexample.com",
"/////example.com",
"/////example.com/",
"////\;@example.com",
"////example.com/"
]

DOM_XSS_SINKS = [
      "location.href",
                "location.hash",
                "location.search",
                "location.pathname",
                "document.URL",
                "window.name",
                "document.referrer",
                "document.documentURI",
                "document.baseURI",
                "document.cookie",
                "location.hostname",
                "jQuery.globalEval",
                "eval",
                "Function",
                "execScript",
                "setTimeout",
                "setInterval",
                "setImmediate",
                "msSetImmediate",
                "script.src",
                "script.textContent",
                "script.text",
                "script.innerText",
                "script.innerHTML",
                "script.appendChild",
                "script.append",
                "document.write",
                "document.writeln",
                "jQuery",
                "jQuery.$",
                "jQuery.constructor",
                "jQuery.parseHTML",
                "jQuery.has",
                "jQuery.init",
                "jQuery.index",
                "jQuery.add",
                "jQuery.append",
                "jQuery.appendTo",
                "jQuery.after",
                "jQuery.insertAfter",
                "jQuery.before",
                "jQuery.insertBefore",
                "jQuery.html",
                "jQuery.prepend",
                "jQuery.prependTo",
                "jQuery.replaceWith",
                "jQuery.replaceAll",
                "jQuery.wrap",
                "jQuery.wrapAll",
                "jQuery.wrapInner",
                "jQuery.prop.innerHTML",
                "jQuery.prop.outerHTML",
                "element.innerHTML",
                "element.outerHTML",
                "element.insertAdjacentHTML",
                "iframe.srcdoc",
                "location.replace",
                "location.assign",
                "window.open",
                "iframe.src",
                "javascriptURL",
                "jQuery.attr.onclick",
                "jQuery.attr.onmouseover",
                "jQuery.attr.onmousedown",
                "jQuery.attr.onmouseup",
                "jQuery.attr.onkeydown",
                "jQuery.attr.onkeypress",
                "jQuery.attr.onkeyup",
                "element.setAttribute.onclick",
                "element.setAttribute.onmouseover",
                "element.setAttribute.onmousedown",
                "element.setAttribute.onmouseup",
                "element.setAttribute.onkeydown",
                "element.setAttribute.onkeypress",
                "element.setAttribute.onkeyup",
                "createContextualFragment",
                "document.implementation.createHTMLDocument",
                "xhr.open",
                "xhr.send",
                "fetch",
                "fetch.body",
                "xhr.setRequestHeader.name",
                "xhr.setRequestHeader.value",
                "jQuery.attr.href",
                "jQuery.attr.src",
                "jQuery.attr.data",
                "jQuery.attr.action",
                "jQuery.attr.formaction",
                "jQuery.prop.href",
                "jQuery.prop.src",
                "jQuery.prop.data",
                "jQuery.prop.action",
                "jQuery.prop.formaction",
                "form.action",
                "input.formaction",
                "button.formaction",
                "button.value",
                "element.setAttribute.href",
                "element.setAttribute.src",
                "element.setAttribute.data",
                "element.setAttribute.action",
                "element.setAttribute.formaction",
                "webdatabase.executeSql",
                "document.domain",
                "history.pushState",
                "history.replaceState",
                "xhr.setRequestHeader",
                "websocket",
                "anchor.href",
                "anchor.target",
                "JSON.parse",
                "localStorage.setItem.name",
                "localStorage.setItem.value",
                "sessionStorage.setItem.name",
                "sessionStorage.setItem.value",
                "element.outerText",
                "element.innerText",
                "element.textContent",
                "element.style.cssText",
                "RegExp",
                "location.protocol",
                "location.host",
                "input.value",
                "input.type",
                "document.evaluate"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"
}

def scan_redirect(url, use_proxy=False):
    print(f"\n[🔍] Checking Open Redirect: {url}")
    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"} if use_proxy else None
    for payload in REDIRECT_PAYLOADS:
        test_url = f"{url.rstrip('/')}/{payload.lstrip('/')}"
        try:
            resp = requests.get(test_url, headers=HEADERS, allow_redirects=False, proxies=proxies, timeout=8)
            if resp.status_code in [301, 302, 303, 307, 308]:
                loc = resp.headers.get("Location", "")
                if "google.com" in loc or "example.com" in loc:
                    print(f"  [🚨] Possible Open Redirect: {test_url} → {loc}")
        except requests.RequestException:
            continue

def scan_dom_xss(url, use_proxy=False):
    print(f"\n[🔍] Checking DOM XSS: {url}")
    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"} if use_proxy else None
    try:
        resp = requests.get(url, headers=HEADERS, proxies=proxies, timeout=8)
        soup = BeautifulSoup(resp.text, 'html.parser')
        scripts = soup.find_all("script")
        for script in scripts:
            if not script.string:
                continue
            for sink in DOM_XSS_SINKS:
                if sink.lower() in script.string.lower():
                    print(f"  [🚨] Potential DOM XSS Sink Found: '{sink}' in {url}")
                    break
    except requests.RequestException:
        print("  [!] Connection error or timeout.")

def load_targets(file):
    try:
        with open(file, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[!] Target file not found.")
        return []

def main():
    parser = argparse.ArgumentParser(description="Open Redirect & DOM XSS Scanner")
    parser.add_argument("-u", "--url", help="Scan a single URL")
    parser.add_argument("-l", "--list", help="Scan URLs from file")
    parser.add_argument("--proxy", help="Use proxy (127.0.0.1:8080)", action="store_true")

    args = parser.parse_args()
    targets = []

    if args.url:
        targets = [args.url]
    elif args.list:
        targets = load_targets(args.list)
    else:
        print("[-] Provide a URL or list of URLs with -u or -l")
        return

    for url in targets:
        if not url.startswith("http"):
            url = "http://" + url
        scan_redirect(url, args.proxy)
        scan_dom_xss(url, args.proxy)

if __name__ == "__main__":
    main()
