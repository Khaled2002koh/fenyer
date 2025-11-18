#!/usr/bin/env python3
"""
Script 1: Domain Analyzer & Endpoint Finder
- Request domain and interact with it
- Find parameters + hidden parameters from HTML response
- Follow 302/301 redirects
- Find all endpoints and request them
- Request JS files and send to script 2
- Analyze requests and methods (POST/GET/OPTIONS/PATCH/PUT)
- Find parameters that call other domains
"""

import requests
import re
import json
import time
import os
import sys
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from bs4 import BeautifulSoup
from collections import defaultdict
import argparse
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
import colorama
from colorama import Fore, Style

# Initialize colorama
colorama.init()
console = Console()

class DomainAnalyzer:
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
        self.endpoints = set()
        self.js_files = set()
        self.forms = []
        self.parameters = defaultdict(set)
        self.external_domains = set()
        self.request_methods = defaultdict(list)
        self.cookies = {}
        self.headers = {}
        
    def log_info(self, message):
        console.print(f"[INFO] {message}", style="blue")
    
    def log_success(self, message):
        console.print(f"[SUCCESS] {message}", style="green")
    
    def log_warning(self, message):
        console.print(f"[WARNING] {message}", style="yellow")
    
    def log_error(self, message):
        console.print(f"[ERROR] {message}", style="red")
    
    def make_request(self, url, method='GET', data=None, params=None, follow_redirects=True):
        """Make HTTP request with proper error handling"""
        try:
            response = self.session.request(
                method=method,
                url=url,
                data=data,
                params=params,
                allow_redirects=follow_redirects,
                timeout=10,
                verify=False
            )
            return response
        except requests.exceptions.RequestException as e:
            self.log_error(f"Request failed for {url}: {str(e)}")
            return None
    
    def follow_redirects(self, url):
        """Follow redirects and return final URL"""
        try:
            response = self.session.get(url, allow_redirects=False, timeout=10, verify=False)
            
            if response.status_code in [301, 302, 303, 307, 308]:
                redirect_url = response.headers.get('Location')
                if redirect_url:
                    self.log_info(f"Redirect found: {url} -> {redirect_url}")
                    # Handle relative redirects
                    if not redirect_url.startswith(('http://', 'https://')):
                        redirect_url = urljoin(url, redirect_url)
                    return self.follow_redirects(redirect_url)
            
            return url
            
        except Exception as e:
            self.log_error(f"Error following redirects: {str(e)}")
            return url
    
    def extract_endpoints_from_html(self, html_content, base_url):
        """Extract endpoints from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        endpoints = set()
        
        # Extract from links
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('/') or not href.startswith(('http://', 'https://', '#', 'mailto:', 'tel:')):
                full_url = urljoin(base_url, href)
                endpoints.add(full_url)
        
        # Extract from forms
        for form in soup.find_all('form', action=True):
            action = form['action']
            if action.startswith('/') or not action.startswith(('http://', 'https://')):
                full_url = urljoin(base_url, action)
                endpoints.add(full_url)
                
                # Extract form parameters
                form_data = {
                    'action': full_url,
                    'method': form.get('method', 'GET').upper(),
                    'parameters': []
                }
                
                for input_tag in form.find_all(['input', 'select', 'textarea']):
                    if input_tag.get('name'):
                        param_info = {
                            'name': input_tag['name'],
                            'type': input_tag.get('type', 'text'),
                            'value': input_tag.get('value', '')
                        }
                        form_data['parameters'].append(param_info)
                        self.parameters[full_url].add(input_tag['name'])
                
                self.forms.append(form_data)
        
        # Extract from scripts, images, etc.
        for tag in soup.find_all(['script', 'img', 'link', 'iframe'], src=True):
            src = tag['src']
            if src.startswith('/') or not src.startswith(('http://', 'https://', 'data:')):
                full_url = urljoin(base_url, src)
                endpoints.add(full_url)
        
        # Extract from onclick and other event handlers
        for tag in soup.find_all(attrs={'onclick': True}):
            onclick_content = tag['onclick']
            # Extract URLs from onclick content
            url_pattern = r'["\']([^"\']+\.(php|asp|aspx|jsp|js|html?|cgi|pl|py))["\']'
            matches = re.findall(url_pattern, onclick_content, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match[0])
                endpoints.add(full_url)
        
        return endpoints
    
    def extract_js_files(self, html_content, base_url):
        """Extract JavaScript files from HTML"""
        soup = BeautifulSoup(html_content, 'html.parser')
        js_files = set()
        
        # Extract from script tags
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src.endswith('.js'):
                if src.startswith('/') or not src.startswith(('http://', 'https://')):
                    full_url = urljoin(base_url, src)
                else:
                    full_url = src
                js_files.add(full_url)
        
        # Extract from inline scripts
        for script in soup.find_all('script'):
            if not script.get('src'):
                script_content = script.string or ''
                # Look for .js file references in inline scripts
                js_pattern = r'["\']([^"\']+\.js)["\']'
                matches = re.findall(js_pattern, script_content)
                for match in matches:
                    if match.startswith('/') or not match.startswith(('http://', 'https://')):
                        full_url = urljoin(base_url, match)
                    else:
                        full_url = match
                    js_files.add(full_url)
        
        return js_files
    
    def extract_hidden_parameters(self, html_content, url):
        """Extract hidden parameters from HTML"""
        soup = BeautifulSoup(html_content, 'html.parser')
        hidden_params = set()
        
        # Hidden input fields
        for hidden_input in soup.find_all('input', {'type': 'hidden'}):
            if hidden_input.get('name'):
                hidden_params.add(hidden_input['name'])
                self.parameters[url].add(hidden_input['name'])
        
        # Meta tags
        for meta in soup.find_all('meta'):
            if meta.get('name') or meta.get('property'):
                param_name = meta.get('name') or meta.get('property')
                hidden_params.add(param_name)
        
        # Data attributes
        for tag in soup.find_all(attrs=True):
            for attr_name, attr_value in tag.attrs.items():
                if attr_name.startswith('data-'):
                    hidden_params.add(attr_name)
        
        return hidden_params
    
    def find_external_domains(self, html_content, base_url):
        """Find external domains referenced in the content"""
        external_domains = set()
        base_domain = urlparse(base_url).netloc
        
        # Extract all URLs
        url_pattern = r'https?://([^\s/"\'<>]+)'
        urls = re.findall(url_pattern, html_content)
        
        for domain in urls:
            if domain != base_domain:
                external_domains.add(domain)
        
        # Extract from script tags
        soup = BeautifulSoup(html_content, 'html.parser')
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src.startswith(('http://', 'https://')):
                domain = urlparse(src).netloc
                if domain != base_domain:
                    external_domains.add(domain)
        
        return external_domains
    
    def analyze_request_methods(self, url):
        """Analyze different HTTP methods for a URL"""
        methods_to_test = ['GET', 'POST', 'PUT', 'PATCH', 'OPTIONS', 'HEAD']
        method_results = {}
        
        for method in methods_to_test:
            try:
                if method == 'POST':
                    response = self.session.post(url, data={'test': 'value'}, timeout=5, verify=False)
                elif method in ['PUT', 'PATCH']:
                    response = self.session.request(method, url, json={'test': 'value'}, timeout=5, verify=False)
                else:
                    response = self.session.request(method, url, timeout=5, verify=False)
                
                method_results[method] = {
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'headers': dict(response.headers)
                }
                
                self.request_methods[url].append(method)
                
            except Exception as e:
                method_results[method] = {'error': str(e)}
        
        return method_results
    
    def crawl_endpoints(self, endpoints):
        """Crawl discovered endpoints"""
        crawled_data = {}
        
        # Convert to list to avoid modification during iteration
        endpoints_list = list(endpoints)
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task(f"Crawling {len(endpoints_list)} endpoints...", total=len(endpoints_list))
            
            for endpoint in endpoints_list:
                try:
                    response = self.make_request(endpoint)
                    if response:
                        crawled_data[endpoint] = {
                            'status_code': response.status_code,
                            'content_length': len(response.content),
                            'content_type': response.headers.get('content-type', ''),
                            'headers': dict(response.headers)
                        }
                        
                        # Extract new endpoints from this page
                        if 'text/html' in response.headers.get('content-type', ''):
                            new_endpoints = self.extract_endpoints_from_html(response.text, endpoint)
                            self.endpoints.update(new_endpoints)
                    
                except Exception as e:
                    self.log_error(f"Error crawling {endpoint}: {str(e)}")
                
                progress.advance(task)
                time.sleep(0.1)  # Be respectful
        
        return crawled_data
    
    def analyze_js_files(self, js_files):
        """Analyze JavaScript files"""
        js_analysis = {}
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task(f"Analyzing {len(js_files)} JS files...", total=len(js_files))
            
            for js_file in js_files:
                try:
                    response = self.make_request(js_file)
                    if response and response.status_code == 200:
                        js_content = response.text
                        
                        # Look for API endpoints in JS
                        api_pattern = r'["\']([^"\']*(?:api|endpoint|service)[^"\']*)["\']'
                        api_endpoints = re.findall(api_pattern, js_content, re.IGNORECASE)
                        
                        # Look for external domains
                        external_pattern = r'https?://([^\s/"\'<>]+)'
                        external_domains = re.findall(external_pattern, js_content)
                        
                        js_analysis[js_file] = {
                            'size': len(js_content),
                            'api_endpoints': list(set(api_endpoints)),
                            'external_domains': list(set(external_domains)),
                            'content': js_content[:1000] + '...' if len(js_content) > 1000 else js_content
                        }
                        
                        self.external_domains.update(external_domains)
                        
                except Exception as e:
                    self.log_error(f"Error analyzing JS file {js_file}: {str(e)}")
                
                progress.advance(task)
                time.sleep(0.1)
        
        return js_analysis
    
    def save_results(self):
        """Save analysis results to files"""
        # Save endpoints
        with open(self.output_dir / 'endpoints.txt', 'w') as f:
            for endpoint in sorted(self.endpoints):
                f.write(f"{endpoint}\n")
        
        # Save JS files
        with open(self.output_dir / 'js_files.txt', 'w') as f:
            for js_file in sorted(self.js_files):
                f.write(f"{js_file}\n")
        
        # Save forms
        with open(self.output_dir / 'forms.json', 'w') as f:
            json.dump(self.forms, f, indent=2)
        
        # Save parameters
        with open(self.output_dir / 'parameters.json', 'w') as f:
            param_dict = {k: list(v) for k, v in self.parameters.items()}
            json.dump(param_dict, f, indent=2)
        
        # Save external domains
        with open(self.output_dir / 'external_domains.txt', 'w') as f:
            for domain in sorted(self.external_domains):
                f.write(f"{domain}\n")
        
        # Save request methods
        with open(self.output_dir / 'request_methods.json', 'w') as f:
            json.dump(dict(self.request_methods), f, indent=2)
    
    def run_analysis(self):
        """Main analysis function"""
        self.log_info(f"Starting analysis for {self.base_url}")
        
        # Follow redirects to get final URL
        final_url = self.follow_redirects(self.base_url)
        self.log_success(f"Final URL after redirects: {final_url}")
        
        # Make initial request
        response = self.make_request(final_url)
        if not response:
            self.log_error("Failed to get initial response")
            return
        
        self.log_success(f"Initial response: {response.status_code}")
        
        # Store cookies and headers
        self.cookies = response.cookies.get_dict()
        self.headers = dict(response.headers)
        
        # Extract endpoints
        self.endpoints = self.extract_endpoints_from_html(response.text, final_url)
        self.log_success(f"Found {len(self.endpoints)} initial endpoints")
        
        # Extract JS files
        self.js_files = self.extract_js_files(response.text, final_url)
        self.log_success(f"Found {len(self.js_files)} JavaScript files")
        
        # Extract hidden parameters
        hidden_params = self.extract_hidden_parameters(response.text, final_url)
        self.log_success(f"Found {len(hidden_params)} hidden parameters")
        
        # Find external domains
        external_domains = self.find_external_domains(response.text, final_url)
        self.external_domains.update(external_domains)
        self.log_success(f"Found {len(external_domains)} external domains")
        
        # Crawl endpoints
        crawled_data = self.crawl_endpoints(self.endpoints)
        
        # Analyze request methods for main endpoints
        for endpoint in list(self.endpoints)[:20]:  # Limit to first 20 for demo
            self.analyze_request_methods(endpoint)
        
        # Analyze JS files
        js_analysis = self.analyze_js_files(self.js_files)
        
        # Save JS analysis for script 2
        with open(self.output_dir / 'js_analysis.json', 'w') as f:
            json.dump(js_analysis, f, indent=2)
        
        # Save all results
        self.save_results()
        
        # Display summary
        self.display_summary()
    
    def display_summary(self):
        """Display analysis summary"""
        table = Table(title="Domain Analysis Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="magenta")
        table.add_column("Details", style="green")
        
        table.add_row("Endpoints", str(len(self.endpoints)), "Discovered URLs")
        table.add_row("JS Files", str(len(self.js_files)), "JavaScript files")
        table.add_row("Forms", str(len(self.forms)), "HTML forms")
        table.add_row("Parameters", str(sum(len(params) for params in self.parameters.values())), "Form parameters")
        table.add_row("External Domains", str(len(self.external_domains)), "Third-party domains")
        
        console.print(table)
        
        self.log_success(f"Analysis completed! Results saved to {self.output_dir}")

def main():
    parser = argparse.ArgumentParser(description='Domain Analyzer & Endpoint Finder')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--output', '-o', default='recon_results', help='Output directory')
    
    args = parser.parse_args()
    
    analyzer = DomainAnalyzer(args.domain, args.output)
    analyzer.run_analysis()

if __name__ == "__main__":
    main()