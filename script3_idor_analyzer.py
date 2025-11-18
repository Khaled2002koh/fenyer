#!/usr/bin/env python3
"""
Script 3: IDOR & Cache Analyzer
- Analyze request URLs to find possible IDOR endpoints
- Analyze responses for cache headers (miss/hit/other)
- Additional reconnaissance and crawling functions
- Advanced security analysis
"""

import re
import json
import requests
import time
import os
import sys
import hashlib
import argparse
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import random
import string

console = Console()

class IDORCacheAnalyzer:
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
        self.idor_endpoints = []
        self.cache_analysis = []
        self.vulnerabilities = []
        self.security_headers = {}
        self.technologies = []
        self.info_disclosure = []
        
        # Thread lock
        self.lock = threading.Lock()
        
        # IDOR patterns
        self.idor_patterns = [
            r'/(\d+)/?$',
            r'/user/(\d+)/?',
            r'/profile/(\d+)/?',
            r'/account/(\d+)/?',
            r'/order/(\d+)/?',
            r'/product/(\d+)/?',
            r'/item/(\d+)/?',
            r'/post/(\d+)/?',
            r'/comment/(\d+)/?',
            r'/message/(\d+)/?',
            r'/file/(\d+)/?',
            r'/document/(\d+)/?',
            r'/record/(\d+)/?',
            r'/entry/(\d+)/?',
            r'/article/(\d+)/?',
            r'/(\w+)\.php\?id=(\d+)',
            r'/(\w+)\.asp\?id=(\d+)',
            r'/(\w+)\.aspx\?id=(\d+)',
            r'/(\w+)\.jsp\?id=(\d+)',
            r'/(\w+)\?id=(\d+)',
            r'/(\w+)\?user_id=(\d+)',
            r'/(\w+)\?account_id=(\d+)',
            r'/(\w+)\?profile_id=(\d+)',
            r'/(\w+)\?order_id=(\d+)',
            r'/(\w+)\?product_id=(\d+)',
            r'/(\w+)\?post_id=(\d+)',
            r'/(\w+)\?comment_id=(\d+)',
            r'/(\w+)\?message_id=(\d+)',
            r'/(\w+)\?file_id=(\d+)',
            r'/(\w+)\?document_id=(\d+)',
            r'/(\w+)\?record_id=(\d+)',
            r'/(\w+)\?entry_id=(\d+)',
            r'/(\w+)\?article_id=(\d+)',
            r'/api/(\w+)/(\d+)/?',
            r'/api/v\d+/(\w+)/(\d+)/?',
            r'/rest/(\w+)/(\d+)/?',
            r'/v\d+/(\w+)/(\d+)/?',
        ]
        
        # Cache-related headers
        self.cache_headers = [
            'cache-control',
            'expires',
            'etag',
            'last-modified',
            'age',
            'x-cache',
            'x-cache-status',
            'cf-cache-status',
            'x-accel-expires',
            'x-fastcgi-cache',
            'x-drupal-cache',
            'x-varnish',
            'x-served-by',
            'x-timer',
        ]
        
        # Security headers to check
        self.security_headers_list = [
            'strict-transport-security',
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'content-security-policy',
            'referrer-policy',
            'feature-policy',
            'permissions-policy',
            'x-download-options',
            'x-permitted-cross-domain-policies',
        ]
        
        # Technology signatures
        self.tech_signatures = {
            'Server': {
                'apache': r'Apache[/\s][\d.]+',
                'nginx': r'nginx[/\s][\d.]+',
                'iis': r'IIS[/\s][\d.]+',
                'cloudflare': r'cloudflare',
                'litespeed': r'LiteSpeed',
                'caddy': r'Caddy',
            },
            'X-Powered-By': {
                'php': r'PHP[/\s][\d.]+',
                'asp.net': r'ASP.NET',
                'express': r'Express',
                'django': r'Django',
                'rails': r'Rails',
                'spring': r'Spring',
            },
            'X-Generator': {
                'wordpress': r'WordPress',
                'drupal': r'Drupal',
                'joomla': r'Joomla',
                'magento': r'Magento',
                'shopify': r'Shopify',
            }
        }
    
    def log_info(self, message):
        console.print(f"[INFO] {message}", style="blue")
    
    def log_success(self, message):
        console.print(f"[SUCCESS] {message}", style="green")
    
    def log_warning(self, message):
        console.print(f"[WARNING] {message}", style="yellow")
    
    def log_error(self, message):
        console.print(f"[ERROR] {message}", style="red")
    
    def load_endpoints(self):
        """Load endpoints from previous scripts"""
        endpoints = set()
        
        # Load from script 1
        endpoints_file = self.output_dir / 'endpoints.txt'
        if endpoints_file.exists():
            with open(endpoints_file, 'r') as f:
                endpoints.update(line.strip() for line in f if line.strip())
        
        # Load from script 2
        js_endpoints_file = self.output_dir / 'js_endpoints.txt'
        if js_endpoints_file.exists():
            with open(js_endpoints_file, 'r') as f:
                endpoints.update(line.strip() for line in f if line.strip())
        
        # Load API endpoints
        api_endpoints_file = self.output_dir / 'api_endpoints.txt'
        if api_endpoints_file.exists():
            with open(api_endpoints_file, 'r') as f:
                endpoints.update(line.strip() for line in f if line.strip())
        
        return list(endpoints)
    
    def detect_idor_patterns(self, url):
        """Detect IDOR patterns in URLs"""
        idor_findings = []
        
        for pattern in self.idor_patterns:
            matches = re.finditer(pattern, url, re.IGNORECASE)
            for match in matches:
                idor_info = {
                    'url': url,
                    'pattern': pattern,
                    'match': match.group(0),
                    'groups': match.groups(),
                    'parameter_name': self.extract_parameter_name(url, match),
                    'risk_level': self.assess_idor_risk(url, match)
                }
                idor_findings.append(idor_info)
        
        return idor_findings
    
    def extract_parameter_name(self, url, match):
        """Extract parameter name from URL match"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Check query parameters first
        for param in query_params:
            if match.group(0) in query_params[param][0]:
                return param
        
        # Check URL path
        path_parts = parsed.path.split('/')
        for i, part in enumerate(path_parts):
            if match.group(0) in part:
                if i > 0:
                    return path_parts[i-1]
        
        return 'id'
    
    def assess_idor_risk(self, url, match):
        """Assess risk level of IDOR pattern"""
        high_risk_keywords = ['user', 'profile', 'account', 'admin', 'order', 'payment', 'invoice']
        medium_risk_keywords = ['post', 'comment', 'message', 'file', 'document', 'product']
        
        url_lower = url.lower()
        match_lower = match.group(0).lower()
        
        if any(keyword in url_lower or keyword in match_lower for keyword in high_risk_keywords):
            return 'HIGH'
        elif any(keyword in url_lower or keyword in match_lower for keyword in medium_risk_keywords):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def test_idor_vulnerability(self, url, original_id):
        """Test for IDOR vulnerability by changing ID values"""
        test_ids = ['1', '2', '999', '9999', 'admin', 'test', 'guest']
        
        for test_id in test_ids:
            if test_id == original_id:
                continue
            
            # Create test URL
            test_url = url.replace(original_id, test_id)
            
            try:
                response = self.session.get(test_url, timeout=10, verify=False)
                
                # Analyze response for potential IDOR
                if response.status_code == 200:
                    content_length = len(response.content)
                    
                    # Check if response is significantly different
                    if content_length > 100:  # Not just an empty error page
                        return {
                            'vulnerable': True,
                            'test_url': test_url,
                            'test_id': test_id,
                            'status_code': response.status_code,
                            'content_length': content_length,
                            'response_snippet': response.text[:200]
                        }
                        
            except Exception as e:
                continue
        
        return {'vulnerable': False}
    
    def analyze_cache_headers(self, response, url):
        """Analyze cache-related headers"""
        cache_info = {
            'url': url,
            'cache_headers': {},
            'cache_status': 'UNKNOWN',
            'cacheable': False,
            'caching_directives': []
        }
        
        for header in self.cache_headers:
            if header in response.headers:
                cache_info['cache_headers'][header] = response.headers[header]
        
        # Determine cache status
        if 'cf-cache-status' in response.headers:
            cache_info['cache_status'] = response.headers['cf-cache-status'].upper()
        elif 'x-cache-status' in response.headers:
            cache_info['cache_status'] = response.headers['x-cache-status'].upper()
        elif 'x-cache' in response.headers:
            cache_info['cache_status'] = response.headers['x-cache'].upper()
        elif 'cache-control' in response.headers:
            cache_control = response.headers['cache-control'].lower()
            if 'no-cache' in cache_control or 'no-store' in cache_control:
                cache_info['cache_status'] = 'NO-CACHE'
            elif 'private' in cache_control:
                cache_info['cache_status'] = 'PRIVATE'
            elif 'public' in cache_control:
                cache_info['cache_status'] = 'PUBLIC'
                cache_info['cacheable'] = True
        
        # Extract caching directives
        if 'cache-control' in response.headers:
            directives = response.headers['cache-control'].split(',')
            cache_info['caching_directives'] = [d.strip() for d in directives]
        
        return cache_info
    
    def analyze_security_headers(self, response, url):
        """Analyze security headers"""
        security_info = {
            'url': url,
            'present_headers': {},
            'missing_headers': [],
            'security_score': 0
        }
        
        for header in self.security_headers_list:
            if header in response.headers:
                security_info['present_headers'][header] = response.headers[header]
                security_info['security_score'] += 10
            else:
                security_info['missing_headers'].append(header)
        
        return security_info
    
    def detect_technologies(self, response, url):
        """Detect web technologies"""
        tech_info = {
            'url': url,
            'technologies': []
        }
        
        # Check headers for technology signatures
        for header, signatures in self.tech_signatures.items():
            if header in response.headers:
                header_value = response.headers[header]
                for tech, pattern in signatures.items():
                    if re.search(pattern, header_value, re.IGNORECASE):
                        tech_info['technologies'].append({
                            'name': tech,
                            'source': f'Header: {header}',
                            'version': self.extract_version(header_value, pattern)
                        })
        
        # Check content for technology signatures
        content = response.text.lower()
        
        # Check for common frameworks
        framework_signatures = {
            'jQuery': r'jquery[-\d.]*\.js',
            'Bootstrap': r'bootstrap[-\d.]*\.js|bootstrap[-\d.]*\.css',
            'React': r'react[-\d.]*\.js|react\.dom',
            'Angular': r'angular[-\d.]*\.js|ng-app',
            'Vue.js': r'vue[-\d.]*\.js',
            'WordPress': r'wp-content|wp-includes',
            'Drupal': r'drupal\.js|sites/default',
            'Joomla': r'joomla|/media/',
            'Magento': r'mage\.js|skin/frontend',
        }
        
        for tech, pattern in framework_signatures.items():
            if re.search(pattern, content):
                tech_info['technologies'].append({
                    'name': tech,
                    'source': 'Content analysis',
                    'version': 'Unknown'
                })
        
        return tech_info
    
    def extract_version(self, header_value, pattern):
        """Extract version from header value"""
        version_match = re.search(r'[\d.]+', header_value)
        return version_match.group(0) if version_match else 'Unknown'
    
    def check_info_disclosure(self, response, url):
        """Check for information disclosure"""
        disclosure_info = {
            'url': url,
            'disclosures': []
        }
        
        content = response.text
        
        # Check for common information disclosures
        disclosure_patterns = {
            'Email addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'Phone numbers': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
            'IP addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'Error messages': r'(error|exception|warning|fatal)\s*[:\n]',
            'Stack traces': r'at\s+[\w.$]+\([^)]*\)',
            'Database errors': r'(mysql|postgresql|oracle|sqlserver)\s+error',
            'File paths': r'[/\\][a-zA-Z]:[/\\]|[/\\](home|var|usr|opt)[/\\]',
            'Comments with sensitive info': r'<!--.*?(password|secret|key|token).*?-->',
            'Debug information': r'debug|trace|verbose',
        }
        
        for disclosure_type, pattern in disclosure_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches[:5]:  # Limit to first 5 matches per type
                disclosure_info['disclosures'].append({
                    'type': disclosure_type,
                    'value': match.group(0)[:100],  # Limit length
                    'line': content[:match.start()].count('\n') + 1
                })
        
        return disclosure_info
    
    def analyze_endpoint(self, url):
        """Comprehensive endpoint analysis"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            
            analysis = {
                'url': url,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': response.headers.get('content-type', ''),
                'response_time': response.elapsed.total_seconds(),
            }
            
            # IDOR analysis
            idor_findings = self.detect_idor_patterns(url)
            if idor_findings:
                for idor_finding in idor_findings:
                    # Test for actual vulnerability
                    if idor_finding['groups']:
                        original_id = idor_finding['groups'][-1]  # Get the last group (usually the ID)
                        vuln_test = self.test_idor_vulnerability(url, original_id)
                        idor_finding.update(vuln_test)
                
                analysis['idor_findings'] = idor_findings
            
            # Cache analysis
            analysis['cache_analysis'] = self.analyze_cache_headers(response, url)
            
            # Security headers analysis
            analysis['security_headers'] = self.analyze_security_headers(response, url)
            
            # Technology detection
            analysis['technologies'] = self.detect_technologies(response, url)
            
            # Information disclosure
            analysis['info_disclosure'] = self.check_info_disclosure(response, url)
            
            return analysis
            
        except Exception as e:
            return {
                'url': url,
                'error': str(e)
            }
    
    def run_comprehensive_analysis(self, endpoints):
        """Run comprehensive analysis on all endpoints"""
        endpoints_list = list(endpoints)  # Convert to list to avoid modification during iteration
        self.log_info(f"Starting comprehensive analysis of {len(endpoints_list)} endpoints")
        
        analysis_results = []
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Analyzing endpoints...", total=len(endpoints_list))
            
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self.analyze_endpoint, endpoint) for endpoint in endpoints_list]
                
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        analysis_results.append(result)
                        
                        # Extract IDOR findings
                        if 'idor_findings' in result:
                            for idor_finding in result['idor_findings']:
                                if idor_finding.get('vulnerable', False):
                                    self.idor_endpoints.append(idor_finding)
                        
                        # Extract cache analysis
                        if 'cache_analysis' in result:
                            self.cache_analysis.append(result['cache_analysis'])
                        
                        # Extract security headers
                        if 'security_headers' in result:
                            url = result['security_headers']['url']
                            self.security_headers[url] = result['security_headers']
                        
                        # Extract technologies
                        if 'technologies' in result:
                            for tech in result['technologies']['technologies']:
                                if tech not in self.technologies:
                                    self.technologies.append(tech)
                        
                        # Extract info disclosure
                        if 'info_disclosure' in result:
                            if result['info_disclosure']['disclosures']:
                                self.info_disclosure.append(result['info_disclosure'])
                        
                    except Exception as e:
                        self.log_error(f"Error in analysis: {str(e)}")
                    
                    progress.advance(task)
        
        return analysis_results
    
    def save_results(self):
        """Save analysis results"""
        # Save IDOR findings
        with open(self.output_dir / 'idor.txt', 'w') as f:
            for idor in self.idor_endpoints:
                f.write(f"URL: {idor['url']}\n")
                f.write(f"Pattern: {idor['pattern']}\n")
                f.write(f"Parameter: {idor['parameter_name']}\n")
                f.write(f"Risk Level: {idor['risk_level']}\n")
                if idor.get('vulnerable'):
                    f.write(f"VULNERABLE: Test URL - {idor['test_url']}\n")
                f.write("-" * 80 + "\n")
        
        # Save cache analysis
        with open(self.output_dir / 'cache_analysis.json', 'w') as f:
            json.dump(self.cache_analysis, f, indent=2)
        
        # Save security headers
        with open(self.output_dir / 'security_headers.json', 'w') as f:
            json.dump(self.security_headers, f, indent=2)
        
        # Save technologies
        with open(self.output_dir / 'technologies.json', 'w') as f:
            json.dump(self.technologies, f, indent=2)
        
        # Save information disclosure
        with open(self.output_dir / 'info_disclosure.json', 'w') as f:
            json.dump(self.info_disclosure, f, indent=2)
        
        # Save summary
        summary = {
            'total_endpoints_analyzed': len(self.security_headers),
            'idor_vulnerabilities_found': len(self.idor_endpoints),
            'cache_issues_found': len([c for c in self.cache_analysis if c['cache_status'] != 'UNKNOWN']),
            'technologies_detected': len(self.technologies),
            'info_disclosures_found': len(self.info_disclosure),
            'average_security_score': sum(sh.get('security_score', 0) for sh in self.security_headers.values()) / len(self.security_headers) if self.security_headers else 0
        }
        
        with open(self.output_dir / 'analysis_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
    
    def display_summary(self):
        """Display analysis summary"""
        table = Table(title="IDOR & Security Analysis Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="magenta")
        table.add_column("Details", style="green")
        
        # Count IDOR by risk level
        idor_by_risk = {}
        vulnerable_idor = 0
        for idor in self.idor_endpoints:
            risk = idor['risk_level']
            idor_by_risk[risk] = idor_by_risk.get(risk, 0) + 1
            if idor.get('vulnerable', False):
                vulnerable_idor += 1
        
        table.add_row("IDOR Patterns", str(len(self.idor_endpoints)), f"{vulnerable_idor} vulnerable")
        for risk, count in idor_by_risk.items():
            table.add_row(f"  - {risk} Risk", str(count), "")
        
        # Cache analysis
        cache_by_status = {}
        for cache in self.cache_analysis:
            status = cache['cache_status']
            cache_by_status[status] = cache_by_status.get(status, 0) + 1
        
        table.add_row("Cache Analysis", str(len(self.cache_analysis)), "Headers analyzed")
        for status, count in cache_by_status.items():
            table.add_row(f"  - {status}", str(count), "")
        
        # Security headers
        avg_score = sum(sh.get('security_score', 0) for sh in self.security_headers.values()) / len(self.security_headers) if self.security_headers else 0
        table.add_row("Security Headers", str(len(self.security_headers)), f"Avg Score: {avg_score:.1f}/100")
        
        # Technologies
        table.add_row("Technologies", str(len(self.technologies)), "Frameworks/Servers detected")
        
        # Info disclosure
        total_disclosures = sum(len(info['disclosures']) for info in self.info_disclosure)
        table.add_row("Info Disclosures", str(total_disclosures), "Sensitive data found")
        
        console.print(table)
        
        # Display critical findings
        if vulnerable_idor > 0:
            console.print(f"\n🚨 CRITICAL: {vulnerable_idor} IDOR vulnerabilities found!", style="red bold")
        
        if avg_score < 50:
            console.print(f"\n⚠️  WARNING: Low security header score ({avg_score:.1f}/100)", style="yellow bold")
        
        if total_disclosures > 10:
            console.print(f"\n⚠️  WARNING: High information disclosure ({total_disclosures} findings)", style="yellow bold")
    
    def run_analysis(self):
        """Main analysis function"""
        self.log_info(f"Starting IDOR & Cache analysis for {self.base_url}")
        
        # Load endpoints from previous scripts
        endpoints = self.load_endpoints()
        self.log_info(f"Loaded {len(endpoints)} endpoints for analysis")
        
        # Run comprehensive analysis
        analysis_results = self.run_comprehensive_analysis(endpoints)
        
        # Save results
        self.save_results()
        
        # Display summary
        self.display_summary()
        
        self.log_success(f"IDOR & Cache analysis completed! Results saved to {self.output_dir}")

def main():
    parser = argparse.ArgumentParser(description='IDOR & Cache Analyzer')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--output', '-o', default='recon_results', help='Output directory')
    
    args = parser.parse_args()
    
    analyzer = IDORCacheAnalyzer(args.domain, args.output)
    analyzer.run_analysis()

if __name__ == "__main__":
    main()
