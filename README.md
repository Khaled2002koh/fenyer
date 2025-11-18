🔍 Advanced Web Security Reconnaissance Tool
A comprehensive Python-based reconnaissance suite for web security assessment and penetration testing.

🚀 Features
Script 1: Domain Analyzer & Endpoint Finder
Domain Interaction: Follow redirects (301/302) and interact with target domains
Parameter Discovery: Find hidden parameters from HTML responses
Endpoint Extraction: Discover all endpoints and request them
Method Analysis: Analyze HTTP methods (GET/POST/OPTIONS/PATCH/PUT)
JavaScript Detection: Find and analyze JS files
External Domain Detection: Identify calls to third-party domains
Script 2: JavaScript Secret Scanner
Advanced Secret Detection: Uses sophisticated regex patterns to find:
AWS tokens and access keys
Google API keys and OAuth tokens
GitHub tokens and client IDs
Slack tokens and webhooks
JWT tokens and authentication headers
Generic API keys and secrets
Private keys and certificates
Database connection strings
Email addresses and sensitive data
Recursive Analysis: Crawls discovered JS files recursively
Endpoint Discovery: Finds API endpoints in JavaScript code
Status Code Testing: Tests all discovered endpoints
Script 3: IDOR & Cache Analyzer
IDOR Detection: Advanced pattern matching for Insecure Direct Object Reference vulnerabilities
Vulnerability Testing: Actual testing of IDOR patterns with different ID values
Cache Analysis: Comprehensive cache header analysis (miss/hit/other)
Security Headers: Checks for missing security headers
Technology Detection: Identifies web technologies and frameworks
Information Disclosure: Detects sensitive information leaks
Script 4: Wayback Machine Discovery
Historical URL Discovery: Uses Wayback Machine API to find historical endpoints
Pattern Recognition: Identifies common URL patterns and structures
Status Code Analysis: Tests discovered endpoints and categorizes by response
Interesting Endpoint Filtering: Categorizes findings (admin panels, config files, backups)
Subdomain Discovery: Extracts subdomains from historical data

#### 📦 Installation
```
# Clone the repository
git clone <repository-url>
cd recon_tool

# Install dependencies
pip install -r requirements.txt

# Make scripts executable (Linux/Mac)
chmod +x *.py
```
#### 🎯 Usage
Run All Scripts
```
python main.py example.com
```

#### Run Individual Scripts
```
# Script 1: Domain Analysis
python script1_domain_analyzer.py example.com

# Script 2: JavaScript Analysis
python script2_js_analyzer.py example.com

# Script 3: IDOR & Cache Analysis
python script3_idor_analyzer.py example.com

# Script 4: Wayback Machine
python script4_wayback.py example.com

```

#### With Custom Output Directory
```
python main.py example.com --output my_recon_results
```
#### Run Specific Script
```
python main.py example.com --script 2
```

#### 📊 Output Files
**Each script generates comprehensive output files:**
```
General Output Files
endpoints.txt - Discovered URLs
js_files.txt - JavaScript files found
forms.json - HTML forms with parameters
parameters.json - Extracted parameters
external_domains.txt - Third-party domains
Script-Specific Outputs
Script 1 Outputs
request_methods.json - HTTP method analysis
js_analysis.json - JavaScript file analysis
Script 2 Outputs
js_secrets.json - Found secrets and tokens
js_endpoints.txt - Endpoints from JavaScript
api_endpoints.txt - API endpoints discovered
endpoint_status.json - Status code testing results
successful_endpoints.txt - 200/401/403 endpoints
Script 3 Outputs
idor.txt - IDOR vulnerabilities found
cache_analysis.json - Cache header analysis
security_headers.json - Security header assessment
technologies.json - Detected technologies
info_disclosure.json - Information disclosure findings
analysis_summary.json - Overall analysis summary
Script 4 Outputs
way.txt - Successful endpoints from Wayback Machine (200/401/403)
wayback_all_urls.txt - All historical URLs
wayback_by_status.json - URLs grouped by status code
wayback_url_patterns.json - Common URL patterns
wayback_parameters.txt - Discovered parameters
wayback_subdomains.txt - Found subdomains
wayback_interesting.json - Categorized interesting endpoints
```
#### 🔧 Advanced Features
**Multi-threading**
**All scripts use concurrent processing for faster analysis:**
```
Script 1: Parallel endpoint crawling
Script 2: Multi-threaded JavaScript analysis
Script 3: Concurrent security testing
Script 4: Parallel endpoint testing
Smart Filtering
False positive reduction for secret detection
URL normalization and deduplication
Intelligent pattern matching
Context-aware vulnerability testing
Comprehensive Reporting
Rich console output with progress bars
Detailed JSON reports for further analysis
Categorized findings by risk level
Summary statistics and metrics
```
#### 🛡️ Security Considerations
**Responsible Usage:**
```
Only use on domains you own or have permission to test
Respect rate limits and implement delays
Do not exploit discovered vulnerabilities
Follow responsible disclosure practices
Privacy Protection
No data is sent to external services (except Wayback Machine API)
All analysis is performed locally
Sensitive findings are stored locally only
```
#### 📈 Performance Optimization
```
Memory Management
Streaming processing for large datasets
Efficient data structures
Garbage collection optimization
Network Optimization
Connection pooling and reuse
Configurable timeouts
Retry mechanisms for failed requests
Concurrent Processing
Thread-safe operations
Configurable worker pools
Resource usage monitoring
```
#### 🔄 Integration
Chain Mode
```
Scripts are designed to work together:

Script 1 → Script 2 (JS files)
Script 2 → Script 1 (New endpoints)
Script 2 → Script 3 (API endpoints)

All scripts → Comprehensive report
Custom Extensions
Modular design for easy extension
Plugin architecture support
Custom pattern definitions
API integration capabilities
```

#### 🐛 Troubleshooting
Common Issues
SSL Certificate Errors: Scripts disable SSL verification by default
Rate Limiting: Implement delays between requests
Memory Issues: Process data in chunks for large targets
Network Timeouts: Increase timeout values for slow targets
Debug Mode
Enable verbose logging:

```
python script1_domain_analyzer.py example.com --verbose
```
#### 📝 License
This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems.

#### 🤝 Contributing

Contributions are welcome. Please make sure to follow these guidelines:
Write clean, maintainable Python code that respects established best practices.
Implement solid error handling across all new features.
Provide clear and complete documentation for every contribution.
Thoroughly test your changes before submitting a pull request.

#### 📞 Support
For issues and questions:
email: pipodzarmy@gmail.com
Check the troubleshooting section
Review the documentation
Create detailed issue reports

**⚠️ Disclaimer: This tool is for authorized security testing only. Users must ensure they have proper permission before testing any systems. The authors are not responsible for misuse of this software.**