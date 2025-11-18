#!/usr/bin/env python3
"""
Recon Tool - Advanced Web Security Reconnaissance Suite
Author: Security Analyst
Description: Multi-script reconnaissance tool for web security assessment
"""

import os
import sys
import argparse
from pathlib import Path

def banner():
    """Display tool banner"""
    banner_text = """
  sSSs    sSSs   .S_sSSs     .S S.     sSSs   .S_sSSs    
 d%%SP   d%%SP  .SS~YS%%b   .SS SS.   d%%SP  .SS~YS%%b   
d%S'    d%S'    S%S   `S%b  S%S S%S  d%S'    S%S   `S%b  
S%S     S%S     S%S    S%S  S%S S%S  S%S     S%S    S%S  
S&S     S&S     S%S    S&S  S%S S%S  S&S     S%S    d*S  
S&S_Ss  S&S_Ss  S&S    S&S   SS SS   S&S_Ss  S&S   .S*S  
S&S~SP  S&S~SP  S&S    S&S    S S    S&S~SP  S&S_sdSSS   
S&S     S&S     S&S    S&S    SSS    S&S     S&S~YSY%b   
S*b     S*b     S*S    S*S    S*S    S*b     S*S   `S%b  
S*S     S*S.    S*S    S*S    S*S    S*S.    S*S    S%S  
S*S      SSSbs  S*S    S*S    S*S     SSSbs  S*S    S&S  
S*S       YSSP  S*S    SSS    S*S      YSSP  S*S    SSS  
SP              SP            SP             SP          
Y               Y             Y              Y           
                                             email: pipodzarmy@gmail.com
                                             https://github.com/Khaled2002koh    
"""
    print(banner_text)

def main():
    banner()
    
    parser = argparse.ArgumentParser(description='Advanced Web Security Reconnaissance Tool')
    parser.add_argument('domain', help='Target domain (e.g., example.com)')
    parser.add_argument('--script', '-s', choices=['1', '2', '3', '4', 'all'], 
                       default='all', help='Script to run (1-4 or all)')
    parser.add_argument('--output', '-o', default='recon_results', 
                       help='Output directory for results')
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    print(f"🎯 Target: {args.domain}")
    print(f"📁 Output Directory: {output_dir.absolute()}")
    print(f"🔧 Running Script(s): {args.script}")
    print("=" * 60)
    
    if args.script == 'all' or args.script == '1':
        print("\n🚀 Running Script 1: Domain Analyzer & Endpoint Finder")
        os.system(f"python3 script1_domain_analyzer.py {args.domain} --output {output_dir}")
    
    if args.script == 'all' or args.script == '2':
        print("\n🚀 Running Script 2: JavaScript Secret Scanner")
        os.system(f"python3 script2_js_analyzer.py {args.domain} --output {output_dir}")
    
    if args.script == 'all' or args.script == '3':
        print("\n🚀 Running Script 3: IDOR & Cache Analyzer")
        os.system(f"python3 script3_idor_analyzer.py {args.domain} --output {output_dir}")
    
    if args.script == 'all' or args.script == '4':
        print("\n🚀 Running Script 4: Wayback Machine Discovery")
        os.system(f"python3 script4_wayback.py {args.domain} --output {output_dir}")
    
    print("\n✅ Reconnaissance completed!")
    print(f"📊 Results saved in: {output_dir.absolute()}")

if __name__ == "__main__":
    main()