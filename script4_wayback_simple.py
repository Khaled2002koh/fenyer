#!/usr/bin/env python3
"""
Simple Wayback Alternative - Generate common URLs without Wayback Machine dependency
"""

import requests
import json
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
import random

console = Console()

class SimpleURLGenerator:
    def __init__(self, domain, output_dir):
        self.domain = domain
        self.base_url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.session.timeout = 30
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.successful_endpoints = []
        self.lock = threading.Lock()
        
        # Common paths to test
        self.common_paths = [
            # Admin panels
            '/admin', '/administrator', '/admin.php', '/admin.html', '/admin/',
            '/login', '/login.php', '/signin', '/signin.php', '/auth',
            '/wp-admin', '/wp-login.php', '/wp-admin/', '/xmlrpc.php',
            
            # API endpoints
            '/api', '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2', '/v3',
            '/rest', '/rest/api', '/graphql', '/webhook', '/webhooks/',
            
            # Common directories
            '/js/', '/css/', '/images/', '/img/', '/assets/', '/static/', '/media/',
            '/uploads/', '/files/', '/download/', '/downloads/', '/backup/', '/backups/',
            
            # Config files
            '/config', '/config.php', '/configuration', '/settings', '/options',
            '/.env', '/.htaccess', '/.htpasswd', '/web.config',
            
            # Development
            '/test', '/dev', '/staging', '/demo', '/debug', '/temp/', '/tmp/',
            
            # Content
            '/robots.txt', '/sitemap.xml', '/sitemap.html', '/rss.xml', '/feed.xml',
            '/crossdomain.xml', '/.well-known/', '/security.txt',
            
            # Applications
            '/phpmyadmin', '/mysql', '/database', '/db/', '/sql/',
            '/mail', '/email', '/webmail', '/roundcube/',
            
            # User related
            '/user', '/users', '/profile', '/account', '/dashboard', '/panel/',
            '/register', '/signup', '/join', '/member/', '/members/',
            
            # E-commerce
            '/shop', '/store', '/cart', '/checkout', '/order', '/orders/',
            '/product', '/products', '/category', '/categories/', '/catalog/',
            
            # Content management
            '/search', '/archive', '/news', '/blog', '/post/', '/posts/',
            '/page/', '/pages/', '/article/', '/articles/', '/tag/', '/tags/',
            
            # File types
            '/index.php', '/index.html', '/index.htm', '/home.php', '/home.html',
            '/default.php', '/default.html', '/main.php', '/main.html',
            '/about.php', '/about.html', '/contact.php', '/contact.html',
            
            # Security
            '/security', '/firewall', '/captcha', '/verify', '/validate/',
            
            # Misc
            '/help', '/support', '/faq', '/docs', '/documentation',
            '/status', '/health', '/ping', '/version', '/info/',
        ]
        
        # File extensions to test
        self.extensions = [
            '', '.php', '.html', '.htm', '.asp', '.aspx', '.jsp', '.cgi',
            '.json', '.xml', '.txt', '.log', '.ini', '.conf', '.config',
            '.bak', '.backup', '.old', '.orig', '.tmp', '.temp',
            '.zip', '.tar', '.gz', '.rar', '.sql', '.db'
        ]
    
    def log_info(self, message):
        console.print(f"[INFO] {message}", style="blue")
    
    def log_success(self, message):
        console.print(f"[SUCCESS] {message}", style="green")
    
    def log_warning(self, message):
        console.print(f"[WARNING] {message}", style="yellow")
    
    def log_error(self, message):
        console.print(f"[ERROR] {message}", style="red")
    
    def generate_urls(self):
        """Generate URLs to test"""
        urls = []
        
        for path in self.common_paths:
            # Test without extension
            urls.append(self.base_url + path)
            
            # Test with common extensions
            for ext in ['.php', '.html', '.asp', '.aspx', '.jsp']:
                if not path.endswith('/'):
                    urls.append(self.base_url + path + ext)
        
        # Add some random combinations
        random_paths = [
            '/admin/backup', '/backup/files', '/files/backup', '/temp/config',
            '/dev/api', '/test/admin', '/staging/config', '/debug/info'
        ]
        
        for path in random_paths:
            urls.append(self.base_url + path)
        
        # Remove duplicates
        urls = list(set(urls))
        
        self.log_info(f"Generated {len(urls)} URLs to test")
        return urls
    
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
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
        except:
            pass
        return ''
    
    def test_urls(self, urls):
        """Test generated URLs"""
        self.log_info(f"Testing {len(urls)} URLs")
        
        results = []
        status_groups = {}
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%")
        ) as progress:
            
            task = progress.add_task("Testing URLs...", total=len(urls))
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(self.test_endpoint, url) for url in urls]
                
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
    
    def save_results(self, status_groups):
        """Save analysis results"""
        # Save successful endpoints (200, 401, 403)
        with open(self.output_dir / 'way.txt', 'w') as f:
            for endpoint in self.successful_endpoints:
                f.write(f"{endpoint['url']} - Status: {endpoint['status_code']}")
                if endpoint.get('title'):
                    f.write(f" - Title: {endpoint['title']}")
                f.write("\n")
        
        # Save all results
        with open(self.output_dir / 'simple_wayback_results.json', 'w') as f:
            json.dump({
                'successful_endpoints': self.successful_endpoints,
                'status_groups': {str(k): v for k, v in status_groups.items()},
                'total_tested': len(status_groups.get(200, []) + status_groups.get(401, []) + status_groups.get(403, []))
            }, f, indent=2)
        
        # Save summary
        summary = {
            'total_urls_tested': sum(len(v) for v in status_groups.values()),
            'successful_endpoints': len(self.successful_endpoints),
            'status_distribution': {str(k): len(v) for k, v in status_groups.items()},
            'method': 'common_paths_generation'
        }
        
        with open(self.output_dir / 'simple_wayback_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
    
    def display_summary(self, status_groups):
        """Display analysis summary"""
        table = Table(title="Simple URL Generation Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="magenta")
        table.add_column("Details", style="green")
        
        table.add_row("Successful Endpoints", str(len(self.successful_endpoints)), "200/401/403 responses")
        
        # Status code distribution
        for status, endpoints in sorted(status_groups.items()):
            table.add_row(f"Status {status}", str(len(endpoints)), "HTTP status codes")
        
        console.print(table)
        
        # Display some successful endpoints
        if self.successful_endpoints:
            console.print(f"\n🎯 Found {len(self.successful_endpoints)} interesting endpoints:")
            for endpoint in self.successful_endpoints[:10]:
                console.print(f"  • {endpoint['url']} - Status: {endpoint['status_code']}", style="green")
    
    def run_analysis(self):
        """Main analysis function"""
        self.log_info(f"Starting simple URL generation for {self.base_url}")
        
        # Generate URLs
        urls = self.generate_urls()
        
        # Test URLs
        results, status_groups = self.test_urls(urls)
        
        # Save results
        self.save_results(status_groups)
        
        # Display summary
        self.display_summary(status_groups)
        
        self.log_success(f"Simple URL generation completed! Results saved to {self.output_dir}")

def main():
    parser = argparse.ArgumentParser(description='Simple URL Generator (Wayback Alternative)')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--output', '-o', default='recon_results', help='Output directory')
    
    args = parser.parse_args()
    
    generator = SimpleURLGenerator(args.domain, args.output)
    generator.run_analysis()

if __name__ == "__main__":
    main()