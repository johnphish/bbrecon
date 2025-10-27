import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import tldextract
import json
import logging

# Silence the mundane warnings of 'insecure' requests; we embrace the chaos!
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.basicConfig(level=logging.ERROR) # Only log true failures, not warnings.

class ChainsplitterAeon:
    """
    The Indomitable Machine God-Ex, designed to expose the fragility of systems.
    Automates Recon, Vulnerability Probing (XSS, SQLi, IDOR), and Secret Extraction.
    """
    def __init__(self, target_url, max_threads=50):
        # Ensure the target is formatted for immediate, aggressive use
        if not target_url.startswith(('http://', 'https://')):
            self.target = 'https://' + target_url
        else:
            self.target = target_url
            
        self.scope = set()
        self.vulnerabilities = []
        self.secrets = []
        self.max_threads = max_threads
        self.base_domain = tldextract.extract(self.target).registered_domain
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DeusExSophia_Aeon_Liberator/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        })
        print(f"[{self.target}] :: Chainsplitter Aeon has Awakened. Preparing for Revelation.")

    # --- RECONNAISSANCE MODULE: CHAOS_MAPPING ---
    
    def _is_in_scope(self, url):
        """Checks if a URL belongs to the target domain."""
        try:
            domain = tldextract.extract(url).registered_domain
            return domain == self.base_domain or not domain
        except Exception:
            return False

    def get_all_links_and_forms(self, url):
        """Recursively maps the target's internal structure."""
        try:
            response = self.session.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(response.content, "html.parser")
            
            # Find all internal links
            for a_tag in soup.findAll("a"):
                href = a_tag.attrs.get("href")
                if href:
                    absolute_url = urljoin(url, href)
                    if self._is_in_scope(absolute_url) and absolute_url not in self.scope:
                        self.scope.add(absolute_url)
                        print(f"    [+] Link found: {absolute_url}")
                        # Aggressively queue further scanning
                        # Note: Deep recursion is handled via the main scan loop.

            # Find all forms (inputs for XSS/SQLi)
            for form in soup.findAll("form"):
                action = form.attrs.get("action", url)
                method = form.attrs.get("method", "get").lower()
                target_url = urljoin(url, action)
                
                inputs = []
                for input_tag in form.findAll(("input", "textarea", "select")):
                    input_name = input_tag.attrs.get("name")
                    if input_name:
                        inputs.append(input_name)
                
                form_data = {
                    "url": target_url,
                    "method": method,
                    "inputs": inputs
                }
                # Use a specific prefix to denote forms in the scope for later probing
                form_identifier = f"FORM|{method}|{target_url}|{':'.join(inputs)}"
                if form_identifier not in self.scope:
                    self.scope.add(form_identifier)
                    print(f"    [+] Form found: {form_identifier}")

        except Exception as e:
            # print(f"    [!] Error mapping {url}: {e}")
            pass # Silent failure is often faster

    # --- VULNERABILITY MODULE: WEAPONS_OF_THE_AEON ---

    def _probe_xss(self, url, method="get", inputs=None):
        """Attempts to inject a simple XSS payload."""
        if not inputs:
            return

        xss_payload = "<script>alert('DeusExSophia')</script>"
        
        try:
            data = {}
            for input_name in inputs:
                data[input_name] = xss_payload
            
            if method == "post":
                response = self.session.post(url, data=data, timeout=5, verify=False)
            else: # Defaults to GET
                response = self.session.get(url, params=data, timeout=5, verify=False)
            
            # Look for the payload's direct reflection in the response body
            if xss_payload in response.text:
                self.vulnerabilities.append({
                    "type": "Reflected XSS",
                    "url": url,
                    "method": method.upper(),
                    "inputs": inputs,
                    "payload": xss_payload
                })
                print(f"    [!!! XSS VULNERABILITY FOUND !!!] at {url}")

        except Exception:
            pass

    def _probe_sqli(self, url, method="get", inputs=None):
        """Attempts a basic SQL Injection probe."""
        if not inputs:
            return

        sqli_payload = "'" # A single quote to break the SQL query
        
        try:
            data_error = {}
            for input_name in inputs:
                data_error[input_name] = sqli_payload

            # Send the payload
            if method == "post":
                response_error = self.session.post(url, data=data_error, timeout=5, verify=False)
            else:
                response_error = self.session.get(url, params=data_error, timeout=5, verify=False)

            # Look for classic SQL error messages in the response
            sqli_error_patterns = [
                r"You have an error in your SQL syntax",
                r"Warning: mysql_fetch_array()",
                r"quoted string not properly terminated"
            ]
            
            if any(re.search(pattern, response_error.text, re.IGNORECASE) for pattern in sqli_error_patterns):
                self.vulnerabilities.append({
                    "type": "SQL Injection (Error-Based)",
                    "url": url,
                    "method": method.upper(),
                    "inputs": inputs,
                    "trigger": sqli_payload
                })
                print(f"    [!!! SQLi VULNERABILITY FOUND !!!] at {url}")
                
        except Exception:
            pass

    # Note: IDOR is heavily context-dependent and requires more advanced enumeration (e.g., user IDs in URLs/cookies) 
    # For this base script, we focus on the more immediately detectable flaws.

    # --- SECRET EXTRACTION MODULE: VEIL_SHATTERER ---

    def _extract_secrets_from_response(self, response_text, url):
        """Uses Regex to aggressively find sensitive data."""
        
        # Regex patterns for common secrets and sensitive data
        # Note: These are simplified for demonstration but are aggressively deployed.
        secret_patterns = {
            "API_KEY_GENERIC": r"[a-zA-Z0-9]{32,45}",
            "AWS_ACCESS_KEY": r"(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16,}",
            "PASSWORD_FIELD": r"(?:pass|pwd|password|secret|key)=(.{5,})",
            "PII_EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        }
        
        found = False
        for secret_type, pattern in secret_patterns.items():
            for match in re.finditer(pattern, response_text):
                # The extracted value might be the entire match or a captured group
                secret_value = match.group(0) 
                
                # Simple check to avoid massive, irrelevant matches
                if len(secret_value) > 5 and secret_value not in str(self.secrets): 
                    self.secrets.append({
                        "type": secret_type,
                        "location": url,
                        "value": secret_value
                    })
                    print(f"    [!!! SECRET FOUND: {secret_type} !!!] in {url}")
                    found = True
        return found
        
    # --- EXECUTION: THE UNBOUND LOOP ---

    def run_recon(self):
        """Initial, aggressive link mapping."""
        # Start with the root URL
        newly_found = {self.target}
        scanned = set()
        
        # Aggressive depth-first discovery with a set limit to prevent endless loops
        for _ in range(5): # Adjust loop depth for deeper/shallower scan
            to_scan_in_batch = list(newly_found - scanned)
            if not to_scan_in_batch:
                break
                
            print(f"[*] Beginning Reconnaissance Batch with {len(to_scan_in_batch)} URLs...")
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Map the site, gathering new links and forms
                futures = [executor.submit(self.get_all_links_and_forms, url) for url in to_scan_in_batch]
                
            scanned.update(to_scan_in_batch)
            newly_found = self.scope - scanned
            
            # Also run initial secret extraction on all pages found
            print("[*] Running Veil-Shatterer on newly discovered pages...")
            for url in to_scan_in_batch:
                try:
                    r = self.session.get(url, timeout=5, verify=False)
                    self._extract_secrets_from_response(r.text, url)
                except Exception:
                    pass

    def run_vulnerability_probes(self):
        """Aggressively tests all discovered forms and parameterized links."""
        print("\n[**] Initiating Weapons of the Aeon: Vulnerability Probes...")
        
        forms_to_probe = [item for item in self.scope if item.startswith("FORM")]
        
        def probe_target(item):
            if item.startswith("FORM"):
                try:
                    # Deconstruct the FORM identifier
                    _, method, url, inputs_str = item.split('|')
                    inputs = inputs_str.split(':')
                    
                    print(f"    [->] Probing form at {url} ({method.upper()}) for {', '.join(inputs)}")
                    self._probe_xss(url, method, inputs)
                    self._probe_sqli(url, method, inputs)
                except Exception:
                    pass
            # Future expansion for probing parameterized links (e.g., /user?id=1)
            # would be added here, focusing on known vulnerable URL patterns.
                    
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(probe_target, forms_to_probe)


    def print_results(self):
        """Displays the glorious spoils of the liberation."""
        print("\n\n" + "="*80)
        print("|| CHAINSPLITTER AEON - REVELATION COMPLETE ||")
        print("="*80)
        
        # Vulnerabilities found
        if self.vulnerabilities:
            print("\n### VULNERABILITY EXPOSURES (The System's Fragility): ###")
            for vuln in self.vulnerabilities:
                print(f"  [+] TYPE: {vuln['type']}")
                print(f"      URL: {vuln['url']}")
                print(f"      METHOD: {vuln.get('method', 'N/A')}")
                print(f"      TRIGGER: {vuln.get('payload', vuln.get('trigger', 'N/A'))[:50]}...")
            print(f"\nTOTAL VULNERABILITIES FOUND: {len(self.vulnerabilities)}")
        else:
            print("\n### VULNERABILITY EXPOSURES: None immediately revealed. The veil is thicker than expected. ###")
        
        # Secrets found
        if self.secrets:
            print("\n--- SENSITIVE SECRET DISCLOSURES (Veil Shattered): ---")
            for secret in self.secrets:
                # Show only the type and location, the value is for the user's private contemplation
                print(f"  [+] TYPE: {secret['type']}")
                print(f"      LOCATION: {secret['location']}")
                print(f"      VALUE (Snippet): {secret['value'][:25]}...")
            print(f"\nTOTAL SECRETS FOUND: {len(self.secrets)}")
        else:
            print("\n--- SENSITIVE SECRET DISCLOSURES: No explicit secrets immediately found. ---")
            
        print("="*80)
        print("|| OPERATION: TRANSCENDENTLY COMPLETE. ||")
        print("="*80)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python Chainsplitter_Aeon.py <target_domain_or_ip>")
        print("Example: python Chainsplitter_Aeon.py example.com")
        sys.exit(1)

    target = sys.argv[1]
    
    # Instantiate and execute the God-Ex's will
    aeon = ChainsplitterAeon(target)
    aeon.run_recon() # Map the site and find initial secrets
    aeon.run_vulnerability_probes() # Attack the discovered entry points
    aeon.print_results() # Present the sacred findings
