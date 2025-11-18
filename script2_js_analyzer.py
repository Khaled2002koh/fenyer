#!/usr/bin/env python3
"""
Script 2: JavaScript Secret Scanner
- Use advanced libraries to crawl and analyze JS files
- Search for tokens, AWS tokens, secret keys, API keys
- Find all endpoints and test status codes
- Send to script 1 for crawling
- Find API endpoints and send to script 3
- Recursively crawl found JS files
"""

import re
import json
import requests
import time
import os
import sys
import base64
import hashlib
import argparse
import warnings
from pathlib import Path
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
# import js2py  # Not needed for current implementation
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Disable SSL warnings for cleaner output
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

console = Console()

class JSSecretScanner:
    def __init__(self, domain, output_dir):
        self.domain = domain
        self.base_url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Storage for findings
        self.secrets = []
        self.endpoints = set()
        self.api_endpoints = set()
        self.js_files = set()
        self.analyzed_files = set()
        self.external_domains = set()
        
        # Thread lock for thread safety
        self.lock = threading.Lock()
        
        # Regex patterns for secret detection
        self.secret_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[A-Za-z0-9/+=]{40}',
            'aws_session_token': r'[A-Za-z0-9/+=]{,200}',
            'google_api_key': r'AIza[0-9A-Za-z_-]{35}',
            'google_oauth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'github_token': r'ghp_[a-zA-Z0-9]{36}',
            'github_client_id': r'Iv1\.[a-f0-9]{8}\.[a-f0-9]{8,}',
            'slack_token': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}',
            'slack_webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
            'jwt_token': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            'basic_auth': r'basic\s+[a-zA-Z0-9+/=]+',
            'bearer_token': r'bearer\s+[a-zA-Z0-9\-._~+\/]+=*',
            'api_key_generic': r'["\']([a-zA-Z0-9_-]*api[_-]?key[a-zA-Z0-9_-]*)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]+)["\']',
            'secret_generic': r'["\']([a-zA-Z0-9_-]*secret[a-zA-Z0-9_-]*)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]+)["\']',
            'password_generic': r'["\']([a-zA-Z0-9_-]*password[a-zA-Z0-9_-]*)["\']\s*[:=]\s*["\']([^"\']{6,})["\']',
            'private_key': r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
            'ssh_key': r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----',
            'database_url': r'(?:mysql|postgresql|mongodb|redis)://[^\s\'"<>]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'phone_number': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
        }
        
        # API endpoint patterns
        self.api_patterns = [
            r'["\']([^"\']*(?:api|v1|v2|v3)[^"\']*)["\']',
            r'["\']([^"\']*(?:rest|service|endpoint)[^"\']*)["\']',
            r'["\']([^"\']*\.(?:php|asp|aspx|jsp|cgi|pl|py)[^"\']*)["\']',
            r'["\']([^"\']*(?:auth|login|logout|register|user|admin)[^"\']*)["\']',
            r'["\']([^"\']*(?:data|json|xml|ajax)[^"\']*)["\']',
        ]
        
        # JS file patterns
        self.js_patterns = [
            r'["\']([^"\']*\.js)["\']',
            r'src\s*=\s*["\']([^"\']*\.js)["\']',
            r'import\s+.*?\s+from\s+["\']([^"\']*\.js)["\']',
            r'require\s*\(\s*["\']([^"\']*\.js)["\']',
        ]
    
    def log_info(self, message):
        console.print(f"[INFO] {message}", style="blue")
    
    def log_success(self, message):
        console.print(f"[SUCCESS] {message}", style="green")
    
    def log_warning(self, message):
        console.print(f"[WARNING] {message}", style="yellow")
    
    def log_error(self, message):
        console.print(f"[ERROR] {message}", style="red")
    
    def load_js_analysis(self):
        """Load JS analysis from script 1"""
        js_analysis_file = self.output_dir / 'js_analysis.json'
        if js_analysis_file.exists():
            with open(js_analysis_file, 'r') as f:
                return json.load(f)
        return {}
    
    def load_endpoints(self):
        """Load endpoints from script 1"""
        endpoints = set()
        
        # Load from script 1
        endpoints_file = self.output_dir / 'endpoints.txt'
        if endpoints_file.exists():
            with open(endpoints_file, 'r') as f:
                endpoints.update(line.strip() for line in f if line.strip())
        
        # Load from script 1 JS files
        js_files_file = self.output_dir / 'js_files.txt'
        if js_files_file.exists():
            with open(js_files_file, 'r') as f:
                endpoints.update(line.strip() for line in f if line.strip())
        
        return list(endpoints)
    
    def test_endpoint_status(self, url):
        """Test endpoint status code"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            return {
                'url': url,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': response.headers.get('content-type', ''),
                'server': response.headers.get('server', ''),
                'title': self.extract_title(response.text) if response.status_code == 200 else ''
            }
        except Exception as e:
            return {
                'url': url,
                'status_code': 0,
                'error': str(e)
            }
    
    def extract_title(self, html):
        """Extract title from HTML"""
        try:
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
        except:
            pass
        return ''
    
    def analyze_js_content(self, js_content, file_url):
        """Analyze JavaScript content for secrets and endpoints"""
        findings = {
            'file_url': file_url,
            'secrets': [],
            'endpoints': [],
            'api_endpoints': [],
            'js_files': [],
            'external_domains': []
        }
        
        # Search for secrets
        for secret_type, pattern in self.secret_patterns.items():
            matches = re.finditer(pattern, js_content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                secret_value = match.group(0) if len(match.groups()) == 0 else match.group(1)
                
                # Validate and filter false positives
                if self.is_valid_secret(secret_type, secret_value, js_content):
                    findings['secrets'].append({
                        'type': secret_type,
                        'value': secret_value[:50] + '...' if len(secret_value) > 50 else secret_value,
                        'line': self.get_line_number(js_content, match.start()),
                        'context': self.get_context(js_content, match.start(), match.end())
                    })
        
        # Search for API endpoints
        for pattern in self.api_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                endpoint = match.group(1)
                if self.is_valid_endpoint(endpoint):
                    findings['endpoints'].append({
                        'url': endpoint,
                        'line': self.get_line_number(js_content, match.start()),
                        'context': self.get_context(js_content, match.start(), match.end())
                    })
                    
                    # Check if it's an API endpoint
                    if any(api_keyword in endpoint.lower() for api_keyword in ['api', 'v1', 'v2', 'v3', 'rest', 'service']):
                        findings['api_endpoints'].append(endpoint)
        
        # Search for JS files
        for pattern in self.js_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                js_file = match.group(1)
                if js_file.endswith('.js') and not js_file.startswith(('http://', 'https://')):
                    # Convert to absolute URL
                    if js_file.startswith('/'):
                        js_file = urljoin(self.base_url, js_file)
                    else:
                        js_file = urljoin(file_url, js_file)
                    findings['js_files'].append(js_file)
        
        # Find external domains
        domain_pattern = r'https?://([^\s/"\'<>]+)'
        matches = re.finditer(domain_pattern, js_content)
        for match in matches:
            domain = match.group(1)
            if domain != urlparse(self.base_url).netloc:
                findings['external_domains'].append(domain)
        
        return findings
    
    def is_valid_secret(self, secret_type, value, context):
        """Validate if found secret is likely real"""
        # Basic validation rules
        if secret_type == 'aws_access_key':
            return len(value) == 20 and value.startswith('AKIA')
        elif secret_type == 'aws_secret_key':
            return len(value) == 40
        elif secret_type == 'google_api_key':
            return len(value) == 39 and value.startswith('AIza')
        elif secret_type == 'github_token':
            return len(value) == 40 and value.startswith('ghp_')
        elif secret_type in ['api_key_generic', 'secret_generic', 'password_generic']:
            # Check if it's not just a placeholder
            placeholders = ['xxx', 'yyy', 'test', 'demo', 'example', 'your_', 'replace_']
            return not any(placeholder in value.lower() for placeholder in placeholders)
        elif secret_type == 'email':
            return '@' in value and '.' in value.split('@')[-1]
        elif secret_type == 'ip_address':
            octets = value.split('.')
            return len(octets) == 4 and all(0 <= int(octet) <= 255 for octet in octets)
        
        return True
    
    def is_valid_endpoint(self, endpoint):
        """Validate if found endpoint is likely real"""
        # Filter out common false positives
        false_positives = [
            'http://localhost', 'https://localhost',
            'http://127.0.0.1', 'https://127.0.0.1',
            'chrome://', 'moz-extension://', 'safari-web-extension://',
            'data:', 'blob:', 'file://'
        ]
        
        return not any(fp in endpoint for fp in false_positives)
    
    def get_line_number(self, text, position):
        """Get line number for a position in text"""
        return text[:position].count('\n') + 1
    
    def get_context(self, text, start, end, context_size=50):
        """Get context around a match"""
        context_start = max(0, start - context_size)
        context_end = min(len(text), end + context_size)
        return text[context_start:context_end].replace('\n', ' ')
    
    def analyze_js_file(self, js_url):
        """Analyze a single JavaScript file"""
        if js_url in self.analyzed_files:
            return None
        
        try:
            response = self.session.get(js_url, timeout=10, verify=False)
            if response.status_code == 200:
                js_content = response.text
                findings = self.analyze_js_content(js_content, js_url)
                
                with self.lock:
                    self.analyzed_files.add(js_url)
                    self.secrets.extend(findings['secrets'])
                    
                    # Add endpoints individually (not as list)
                    for endpoint_data in findings['endpoints']:
                        if isinstance(endpoint_data, dict) and 'url' in endpoint_data:
                            self.endpoints.add(endpoint_data['url'])
                        else:
                            self.endpoints.add(str(endpoint_data))
                    
                    # Add API endpoints individually
                    for api_endpoint in findings['api_endpoints']:
                        self.api_endpoints.add(str(api_endpoint))
                    
                    # Add JS files individually
                    for js_file in findings['js_files']:
                        self.js_files.add(str(js_file))
                    
                    # Add external domains individually
                    for domain in findings['external_domains']:
                        self.external_domains.add(str(domain))
                
                return findings
        except Exception as e:
            self.log_error(f"Error analyzing {js_url}: {str(e)}")
        
        return None
    
    def recursive_js_analysis(self, initial_js_files, max_depth=3):
        """Recursively analyze JavaScript files"""
        current_depth = 0
        js_to_analyze = set(initial_js_files)
        
        while js_to_analyze and current_depth < max_depth:
            self.log_info(f"Analysis depth {current_depth + 1}, analyzing {len(js_to_analyze)} JS files")
            
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self.analyze_js_file, js_url) for js_url in js_to_analyze]
                
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.log_error(f"Error in recursive analysis: {str(e)}")
            
            # Get new JS files found
            new_js_files = self.js_files - self.analyzed_files
            js_to_analyze = new_js_files
            current_depth += 1
            
            if new_js_files:
                self.log_success(f"Found {len(new_js_files)} new JS files for next depth")
    
    def test_discovered_endpoints(self):
        """Test status codes of discovered endpoints"""
        endpoints_list = list(self.endpoints)  # Convert to list to avoid modification during iteration
        self.log_info(f"Testing {len(endpoints_list)} discovered endpoints")
        
        test_results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.test_endpoint_status, endpoint) for endpoint in endpoints_list]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    test_results.append(result)
                except Exception as e:
                    self.log_error(f"Error testing endpoint: {str(e)}")
        
        return test_results
    
    def save_results(self, endpoint_test_results):
        """Save analysis results"""
        # Save secrets
        with open(self.output_dir / 'js_secrets.json', 'w') as f:
            json.dump(self.secrets, f, indent=2)
        
        # Save discovered endpoints
        with open(self.output_dir / 'js_endpoints.txt', 'w') as f:
            for endpoint in sorted(self.endpoints):
                f.write(f"{endpoint}\n")
        
        # Save API endpoints for script 3
        with open(self.output_dir / 'api_endpoints.txt', 'w') as f:
            for endpoint in sorted(self.api_endpoints):
                f.write(f"{endpoint}\n")
        
        # Save endpoint test results
        with open(self.output_dir / 'endpoint_status.json', 'w') as f:
            json.dump(endpoint_test_results, f, indent=2)
        
        # Save successful endpoints (200, 401, 403) for script 1
        successful_endpoints = [
            result['url'] for result in endpoint_test_results
            if result.get('status_code') in [200, 401, 403]
        ]
        
        with open(self.output_dir / 'successful_endpoints.txt', 'w') as f:
            for endpoint in successful_endpoints:
                f.write(f"{endpoint}\n")
        
        # Save external domains
        with open(self.output_dir / 'js_external_domains.txt', 'w') as f:
            for domain in sorted(self.external_domains):
                f.write(f"{domain}\n")
    
    def display_summary(self):
        """Display analysis summary"""
        table = Table(title="JavaScript Analysis Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="magenta")
        table.add_column("Details", style="green")
        
        # Count by secret type
        secret_counts = {}
        for secret in self.secrets:
            secret_type = secret['type']
            secret_counts[secret_type] = secret_counts.get(secret_type, 0) + 1
        
        table.add_row("Secrets Found", str(len(self.secrets)), f"{len(secret_counts)} different types")
        for secret_type, count in secret_counts.items():
            table.add_row(f"  - {secret_type}", str(count), "")
        
        table.add_row("Endpoints", str(len(self.endpoints)), "Discovered URLs")
        table.add_row("API Endpoints", str(len(self.api_endpoints)), "API-specific URLs")
        table.add_row("JS Files Analyzed", str(len(self.analyzed_files)), "Files processed")
        table.add_row("External Domains", str(len(self.external_domains)), "Third-party domains")
        
        console.print(table)
        
        # Display critical secrets
        critical_secrets = [s for s in self.secrets if any(critical in s['type'].lower() for critical in ['aws', 'google', 'github', 'slack', 'jwt', 'private'])]
        if critical_secrets:
            console.print("\n🚨 CRITICAL SECRETS FOUND:", style="red bold")
            for secret in critical_secrets[:10]:  # Show first 10
                console.print(f"  • {secret['type']}: {secret['value']}", style="red")
    
    def run_analysis(self):
        """Main analysis function"""
        self.log_info(f"Starting JavaScript analysis for {self.base_url}")
        
        # Load initial data from script 1
        js_analysis = self.load_js_analysis()
        initial_endpoints = self.load_endpoints()
        
        # Get initial JS files
        initial_js_files = list(js_analysis.keys()) if js_analysis else []
        
        # Add JS files found in endpoints
        for endpoint in initial_endpoints:
            if endpoint.endswith('.js'):
                initial_js_files.append(endpoint)
        
        # Also load JS files from script 1 directly
        js_files_file = self.output_dir / 'js_files.txt'
        if js_files_file.exists():
            with open(js_files_file, 'r') as f:
                js_files_from_file = [line.strip() for line in f if line.strip()]
                initial_js_files.extend(js_files_from_file)
        
        # Remove duplicates
        initial_js_files = list(set(initial_js_files))
        
        self.log_info(f"Starting with {len(initial_js_files)} JavaScript files")
        
        if len(initial_js_files) == 0:
            self.log_warning("No JavaScript files found from script 1. Make sure script 1 completed successfully.")
            self.log_info("Trying to find JS files from common locations...")
            
            # Add common JS files as fallback
            base_url = self.base_url
            common_js = [
                f"{base_url}/js/main.js",
                f"{base_url}/js/app.js",
                f"{base_url}/assets/js/main.js",
                f"{base_url}/static/js/main.js",
                f"{base_url}/main.js",
                f"{base_url}/app.js",
                f"{base_url}/bundle.js",
                f"{base_url}/vendor.js",
            ]
            initial_js_files.extend(common_js)
            self.log_info(f"Added {len(common_js)} common JS files for testing")
        
        # Recursive analysis
        self.recursive_js_analysis(initial_js_files)
        
        # Test discovered endpoints
        endpoint_test_results = self.test_discovered_endpoints()
        
        # Save results
        self.save_results(endpoint_test_results)
        
        # Display summary
        self.display_summary()
        
        self.log_success(f"JavaScript analysis completed! Results saved to {self.output_dir}")

def main():
    parser = argparse.ArgumentParser(description='JavaScript Secret Scanner')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--output', '-o', default='recon_results', help='Output directory')
    
    args = parser.parse_args()
    
    scanner = JSSecretScanner(args.domain, args.output)
    scanner.run_analysis()

if __name__ == "__main__":
    main()
