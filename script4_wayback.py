#!/usr/bin/env python3
"""
Script 4: Wayback Machine Endpoint Discovery
- Use Wayback Machine to find historical endpoints
- Test discovered endpoints and save 200, 401, 403 URLs
- Advanced URL extraction and filtering
- Comprehensive endpoint analysis
"""

import re
import json
import requests
import time
import os
import sys
import argparse
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from datetime import datetime, timedelta
import random

console = Console()

class WaybackMachineAnalyzer:
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
        self.wayback_urls = []
        self.successful_endpoints = []
        self.endpoints_by_status = {}
        self.url_patterns = {}
        self.parameters = set()
        self.subdomains = set()
        self.technologies = set()
        
        # Thread lock
        self.lock = threading.Lock()
        
        # Wayback Machine API
        self.wayback_api = "http://web.archive.org/cdx/search/cdx"
        
        # URL patterns to extract
        self.url_patterns_regex = [
            r'/api/[^/\s]+',
            r'/v\d+/[^/\s]+',
            r'/admin/[^/\s]+',
            r'/wp-[^/\s]+',
            r'/\.well-known/[^/\s]+',
            r'/robots\.txt',
            r'/sitemap\.xml',
            r'/crossdomain\.xml',
            r'/\.env',
            r'/\.git/',
            r'/\.svn/',
            r'/backup/[^/\s]+',
            r'/test/[^/\s]+',
            r'/dev/[^/\s]+',
            r'/staging/[^/\s]+',
            r'/prod/[^/\s]+',
            r'/config/[^/\s]+',
            r'/uploads/[^/\s]+',
            r'/files/[^/\s]+',
            r'/images/[^/\s]+',
            r'/css/[^/\s]+',
            r'/js/[^/\s]+',
            r'/assets/[^/\s]+',
            r'/static/[^/\s]+',
            r'/media/[^/\s]+',
            r'/download/[^/\s]+',
            r'/export/[^/\s]+',
            r'/import/[^/\s]+',
            r'/login',
            r'/logout',
            r'/register',
            r'/signup',
            r'/signin',
            r'/profile',
            r'/dashboard',
            r'/settings',
            r'/account',
            r'/user/[^/\s]+',
            r'/users/[^/\s]+',
            r'/order/[^/\s]+',
            r'/orders/[^/\s]+',
            r'/product/[^/\s]+',
            r'/products/[^/\s]+',
            r'/category/[^/\s]+',
            r'/categories/[^/\s]+',
            r'/search',
            r'/query',
            r'/filter',
            r'/sort',
            r'/page/[^/\s]+',
            r'/index\.php',
            r'/index\.asp',
            r'/index\.aspx',
            r'/index\.jsp',
            r'/default\.php',
            r'/default\.asp',
            r'/default\.aspx',
            r'/default\.jsp',
            r'/home\.php',
            r'/home\.asp',
            r'/home\.aspx',
            r'/home\.jsp',
        ]
        
        # File extensions to look for
        self.file_extensions = [
            '.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py', '.rb',
            '.html', '.htm', '.shtml', '.phtml', '.php3', '.php4', '.php5',
            '.js', '.css', '.xml', '.json', '.txt', '.log', '.ini', '.conf',
            '.bak', '.backup', '.old', '.orig', '.tmp', '.temp', '.swp',
            '.sql', '.db', '.sqlite', '.mdb', '.accdb',
            '.zip', '.tar', '.gz', '.rar', '.7z',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
            '.exe', '.msi', '.dmg', '.pkg', '.deb', '.rpm',
        ]
        
        # Parameter patterns
        self.parameter_patterns = [
            r'id=\d+',
            r'user_id=\d+',
            r'page=\d+',
            'limit=\d+',
            r'offset=\d+',
            r'sort=[^&\s]+',
            r'order=[^&\s]+',
            r'filter=[^&\s]+',
            r'search=[^&\s]+',
            r'query=[^&\s]+',
            r'action=[^&\s]+',
            r'method=[^&\s]+',
            r'type=[^&\s]+',
            r'format=[^&\s]+',
            r'version=[^&\s]+',
            r'lang=[^&\s]+',
            r'callback=[^&\s]+',
            r'jsonp=[^&\s]+',
            r'redirect=[^&\s]+',
            r'return=[^&\s]+',
            r'url=[^&\s]+',
            r'path=[^&\s]+',
            r'file=[^&\s]+',
            r'download=[^&\s]+',
            r'view=[^&\s]+',
            r'mode=[^&\s]+',
            r'state=[^&\s]+',
            r'status=[^&\s]+',
            r'level=[^&\s]+',
            r'role=[^&\s]+',
            r'access=[^&\s]+',
            r'auth=[^&\s]+',
            r'token=[^&\s]+',
            r'key=[^&\s]+',
            r'secret=[^&\s]+',
            r'hash=[^&\s]+',
            r'signature=[^&\s]+',
            r'timestamp=\d+',
            r'expires=\d+',
            r'cache=[^&\s]+',
            r'debug=[^&\s]+',
            r'test=[^&\s]+',
            r'dev=[^&\s]+',
            r'admin=[^&\s]+',
            r'password=[^&\s]+',
            r'email=[^&\s]+',
            r'username=[^&\s]+',
            r'login=[^&\s]+',
            r'logout=[^&\s]+',
        ]
    
    def log_info(self, message):
        console.print(f"[INFO] {message}", style="blue")
    
    def log_success(self, message):
        console.print(f"[SUCCESS] {message}", style="green")
    
    def log_warning(self, message):
        console.print(f"[WARNING] {message}", style="yellow")
    
    def log_error(self, message):
        console.print(f"[ERROR] {message}", style="red")
    
    def get_wayback_urls(self, domain, limit=10000):
        """Get URLs from Wayback Machine"""
        self.log_info(f"Fetching URLs from Wayback Machine for {domain}")
        
        urls = []
        from_date = (datetime.now() - timedelta(days=365*5)).strftime('%Y%m%d')
        to_date = datetime.now().strftime('%Y%m%d')
        
        params = {
            'url': f'*.{domain}/*',
            'from': from_date,
            'to': to_date,
            'output': 'json',
            'collapse': 'timestamp:8',
            'limit': limit,
            'filter': 'statuscode:200',
            'filter': 'mimetype:text/html',
            'filter': 'mimetype:application/javascript',
            'filter': 'mimetype:application/json',
            'filter': 'mimetype:text/css',
        }
        
        try:
            response = self.session.get(self.wayback_api, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:
                    for row in data[1:]:  # Skip header row
                        if len(row) >= 3:
                            url = row[2]
                            timestamp = row[1]
                            status_code = row[3]
                            
                            urls.append({
                                'url': url,
                                'timestamp': timestamp,
                                'status_code': status_code,
                                'date': datetime.strptime(timestamp, '%Y%m%d%H%M%S').strftime('%Y-%m-%d %H:%M:%S')
                            })
                
                self.log_success(f"Found {len(urls)} URLs from Wayback Machine")
            else:
                self.log_error(f"Failed to fetch Wayback URLs: {response.status_code}")
                
        except Exception as e:
            self.log_error(f"Error fetching Wayback URLs: {str(e)}")
        
        return urls
    
    def extract_unique_urls(self, wayback_data):
        """Extract unique URLs from Wayback data"""
        unique_urls = set()
        url_info = {}
        
        for item in wayback_data:
            url = item['url']
            
            # Clean URL
            clean_url = self.clean_url(url)
            if clean_url:
                unique_urls.add(clean_url)
                url_info[clean_url] = {
                    'first_seen': item['date'],
                    'last_seen': item['date'],
                    'status_code': item['status_code'],
                    'count': 1
                }
            else:
                # Update existing URL info
                if clean_url in url_info:
                    url_info[clean_url]['count'] += 1
                    url_info[clean_url]['last_seen'] = item['date']
        
        return list(unique_urls), url_info
    
    def clean_url(self, url):
        """Clean and normalize URL"""
        try:
            parsed = urlparse(url)
            
            # Remove query parameters for unique URL identification
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Only keep URLs from target domain
            if self.domain not in parsed.netloc:
                return None
            
            # Filter out common false positives
            if any(pattern in clean_url.lower() for pattern in [
                'web.archive.org', 'webcache.googleusercontent.com',
                'cc.bingj.com', 'r.jina.ai/http://'
            ]):
                return None
            
            return clean_url
            
        except Exception:
            return None
    
    def extract_url_patterns(self, urls):
        """Extract common URL patterns"""
        patterns = {}
        
        for url in urls:
            parsed = urlparse(url)
            path = parsed.path
            
            # Extract patterns
            for pattern_regex in self.url_patterns_regex:
                matches = re.finditer(pattern_regex, path, re.IGNORECASE)
                for match in matches:
                    pattern = match.group(0)
                    if pattern not in patterns:
                        patterns[pattern] = []
                    patterns[pattern].append(url)
        
        return patterns
    
    def extract_parameters(self, urls):
        """Extract parameters from URLs"""
        parameters = set()
        
        for url in urls:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            for param in query_params.keys():
                parameters.add(param)
        
        return parameters
    
    def extract_subdomains(self, urls):
        """Extract subdomains from URLs"""
        subdomains = set()
        
        for url in urls:
            parsed = urlparse(url)
            domain_parts = parsed.netloc.split('.')
            
            if len(domain_parts) > 2:
                subdomain = '.'.join(domain_parts[:-2])
                subdomains.add(subdomain)
        
        return subdomains
    
    def test_endpoint(self, url):
        """Test endpoint status"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            
            result = {
                'url': url,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': response.headers.get('content-type', ''),
                'server': response.headers.get('server', ''),
                'title': self.extract_title(response.text) if response.status_code == 200 else '',
                'redirect_url': response.url if response.url != url else '',
                'response_time': response.elapsed.total_seconds(),
            }
            
            # Check for interesting headers
            interesting_headers = {}
            for header in response.headers:
                if any(keyword in header.lower() for keyword in [
                    'server', 'x-powered-by', 'x-generator', 'x-aspnet-version',
                    'x-php-version', 'x-drupal-cache', 'x-varnish', 'x-cache',
                    'cf-ray', 'x-served-by', 'x-timer'
                ]):
                    interesting_headers[header] = response.headers[header]
            
            result['interesting_headers'] = interesting_headers
            
            return result
            
        except Exception as e:
            return {
                'url': url,
                'status_code': 0,
                'error': str(e)
            }
    
    def extract_title(self, html):
        """Extract title from HTML"""
        try:
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
        except:
            pass
        return ''
    
    def analyze_endpoints(self, urls):
        """Analyze discovered endpoints"""
        urls_list = list(urls)  # Convert to list to avoid modification during iteration
        self.log_info(f"Testing {len(urls_list)} endpoints")
        
        results = []
        status_groups = {}
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%")
        ) as progress:
            
            task = progress.add_task("Testing endpoints...", total=len(urls_list))
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(self.test_endpoint, url) for url in urls_list]
                
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        results.append(result)
                        
                        status_code = result.get('status_code', 0)
                        if status_code not in status_groups:
                            status_groups[status_code] = []
                        status_groups[status_code].append(result)
                        
                        # Update successful endpoints (200, 401, 403)
                        if status_code in [200, 401, 403]:
                            with self.lock:
                                self.successful_endpoints.append(result)
                        
                        progress.advance(task)
                        
                    except Exception as e:
                        self.log_error(f"Error testing endpoint: {str(e)}")
                        progress.advance(task)
        
        return results, status_groups
    
    def filter_interesting_endpoints(self, results):
        """Filter and categorize interesting endpoints"""
        interesting = {
            'high_value': [],
            'api_endpoints': [],
            'admin_panels': [],
            'file_uploads': [],
            'config_files': [],
            'backup_files': [],
            'test_files': [],
            'error_pages': []
        }
        
        for result in results:
            url = result['url']
            status_code = result.get('status_code', 0)
            
            # High value endpoints (200, 401, 403)
            if status_code in [200, 401, 403]:
                interesting['high_value'].append(result)
            
            # API endpoints
            if any(pattern in url.lower() for pattern in ['/api/', '/v1/', '/v2/', '/rest/', '/graphql']):
                interesting['api_endpoints'].append(result)
            
            # Admin panels
            if any(pattern in url.lower() for pattern in ['/admin', '/administrator', '/wp-admin', '/manager', '/console']):
                interesting['admin_panels'].append(result)
            
            # File upload endpoints
            if any(pattern in url.lower() for pattern in ['/upload', '/file', '/attachment', '/import']):
                interesting['file_uploads'].append(result)
            
            # Config files
            if any(pattern in url.lower() for pattern in ['.env', '.config', '.ini', '.conf', 'config.php', 'web.config']):
                interesting['config_files'].append(result)
            
            # Backup files
            if any(pattern in url.lower() for pattern in ['.bak', '.backup', '.old', '.orig', '.zip', '.tar', '.gz']):
                interesting['backup_files'].append(result)
            
            # Test files
            if any(pattern in url.lower() for pattern in ['/test', '/dev', '/staging', '/debug', '/demo']):
                interesting['test_files'].append(result)
            
            # Error pages
            if status_code >= 400:
                interesting['error_pages'].append(result)
        
        return interesting
    
    def save_results(self, status_groups, interesting_endpoints):
        """Save analysis results"""
        # Save successful endpoints (200, 401, 403)
        with open(self.output_dir / 'way.txt', 'w') as f:
            for endpoint in self.successful_endpoints:
                f.write(f"{endpoint['url']} - Status: {endpoint['status_code']}")
                if endpoint.get('title'):
                    f.write(f" - Title: {endpoint['title']}")
                f.write("\n")
        
        # Save all Wayback URLs
        with open(self.output_dir / 'wayback_all_urls.txt', 'w') as f:
            for url_data in self.wayback_urls:
                f.write(f"{url_data['url']} - {url_data['date']} - Status: {url_data['status_code']}\n")
        
        # Save endpoints by status code
        with open(self.output_dir / 'wayback_by_status.json', 'w') as f:
            # Convert sets to lists for JSON serialization
            serializable_groups = {}
            for status, endpoints in status_groups.items():
                serializable_groups[str(status)] = endpoints
            json.dump(serializable_groups, f, indent=2)
        
        # Save URL patterns
        with open(self.output_dir / 'wayback_url_patterns.json', 'w') as f:
            # Convert sets to lists
            serializable_patterns = {}
            for pattern, urls in self.url_patterns.items():
                serializable_patterns[pattern] = urls
            json.dump(serializable_patterns, f, indent=2)
        
        # Save parameters
        with open(self.output_dir / 'wayback_parameters.txt', 'w') as f:
            for param in sorted(self.parameters):
                f.write(f"{param}\n")
        
        # Save subdomains
        with open(self.output_dir / 'wayback_subdomains.txt', 'w') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        
        # Save interesting endpoints
        with open(self.output_dir / 'wayback_interesting.json', 'w') as f:
            json.dump(interesting_endpoints, f, indent=2)
        
        # Save summary statistics
        summary = {
            'total_wayback_urls': len(self.wayback_urls),
            'unique_urls_tested': len(status_groups.get(200, []) + status_groups.get(401, []) + status_groups.get(403, [])),
            'successful_endpoints': len(self.successful_endpoints),
            'url_patterns_found': len(self.url_patterns),
            'parameters_found': len(self.parameters),
            'subdomains_found': len(self.subdomains),
            'status_distribution': {str(k): len(v) for k, v in status_groups.items()},
            'interesting_counts': {k: len(v) for k, v in interesting_endpoints.items()}
        }
        
        with open(self.output_dir / 'wayback_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
    
    def display_summary(self, status_groups, interesting_endpoints):
        """Display analysis summary"""
        table = Table(title="Wayback Machine Analysis Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="magenta")
        table.add_column("Details", style="green")
        
        table.add_row("Wayback URLs", str(len(self.wayback_urls)), "Total historical URLs")
        table.add_row("Successful Endpoints", str(len(self.successful_endpoints)), "200/401/403 responses")
        table.add_row("URL Patterns", str(len(self.url_patterns)), "Common patterns found")
        table.add_row("Parameters", str(len(self.parameters)), "Unique parameters")
        table.add_row("Subdomains", str(len(self.subdomains)), "Discovered subdomains")
        
        # Status code distribution
        table.add_row("Status Distribution", "", "")
        for status, endpoints in sorted(status_groups.items()):
            table.add_row(f"  - {status}", str(len(endpoints)), "HTTP status codes")
        
        # Interesting endpoints
        table.add_row("Interesting Endpoints", "", "")
        for category, endpoints in interesting_endpoints.items():
            table.add_row(f"  - {category.replace('_', ' ').title()}", str(len(endpoints)), "")
        
        console.print(table)
        
        # Display top findings
        if interesting_endpoints['admin_panels']:
            console.print(f"\n🔐 Admin Panels Found: {len(interesting_endpoints['admin_panels'])}", style="yellow bold")
            for panel in interesting_endpoints['admin_panels'][:3]:
                console.print(f"  • {panel['url']} - Status: {panel['status_code']}", style="yellow")
        
        if interesting_endpoints['config_files']:
            console.print(f"\n⚙️  Config Files Found: {len(interesting_endpoints['config_files'])}", style="red bold")
            for config in interesting_endpoints['config_files'][:3]:
                console.print(f"  • {config['url']} - Status: {config['status_code']}", style="red")
        
        if interesting_endpoints['backup_files']:
            console.print(f"\n💾 Backup Files Found: {len(interesting_endpoints['backup_files'])}", style="red bold")
            for backup in interesting_endpoints['backup_files'][:3]:
                console.print(f"  • {backup['url']} - Status: {backup['status_code']}", style="red")
    
    def run_analysis(self):
        """Main analysis function"""
        self.log_info(f"Starting Wayback Machine analysis for {self.base_url}")
        
        # Get URLs from Wayback Machine
        self.wayback_urls = self.get_wayback_urls(self.domain)
        
        if not self.wayback_urls:
            self.log_error("No URLs found from Wayback Machine")
            return
        
        # Extract unique URLs
        unique_urls, url_info = self.extract_unique_urls(self.wayback_urls)
        self.log_info(f"Extracted {len(unique_urls)} unique URLs")
        
        # Extract patterns and metadata
        self.url_patterns = self.extract_url_patterns(unique_urls)
        self.parameters = self.extract_parameters(self.wayback_urls)
        self.subdomains = self.extract_subdomains(self.wayback_urls)
        
        # Test endpoints
        all_results, status_groups = self.analyze_endpoints(unique_urls)
        
        # Filter interesting endpoints
        interesting_endpoints = self.filter_interesting_endpoints(all_results)
        
        # Save results
        self.save_results(status_groups, interesting_endpoints)
        
        # Display summary
        self.display_summary(status_groups, interesting_endpoints)
        
        self.log_success(f"Wayback Machine analysis completed! Results saved to {self.output_dir}")

def main():
    parser = argparse.ArgumentParser(description='Wayback Machine Endpoint Discovery')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--output', '-o', default='recon_results', help='Output directory')
    parser.add_argument('--limit', '-l', type=int, default=10000, help='Maximum URLs to fetch from Wayback Machine')
    
    args = parser.parse_args()
    
    analyzer = WaybackMachineAnalyzer(args.domain, args.output)
    analyzer.run_analysis()

if __name__ == "__main__":
    main()