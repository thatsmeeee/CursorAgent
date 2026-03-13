#!/usr/bin/env python3
"""
PHP Security Agent - AI-powered vulnerability scanner for PHP code
Detects SQL injection, XSS, unsafe database queries, and missing input validation
"""

import os
import sys
import argparse
from pathlib import Path
from dotenv import load_dotenv
from scanner import PHPVulnerabilityScanner
from utils import print_banner, print_results, calculate_performance_score

def main():
    """Main entry point for the PHP Security Agent"""
    parser = argparse.ArgumentParser(
        description="PHP Security Agent - AI-powered vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.php scan file.php
  python agent.php scan /path/to/project/
  python agent.php benchmark
        """
    )
    
    parser.add_argument(
        'action',
        choices=['scan', 'benchmark'],
        help='Action to perform: scan a file or run benchmark'
    )
    
    parser.add_argument(
        'target',
        nargs='?',
        help='PHP file or directory to scan'
    )
    
    parser.add_argument(
        '--api-provider',
        choices=['openai', 'claude'],
        default='openai',
        help='AI API provider to use (default: openai)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file for results (JSON format)'
    )
    
    args = parser.parse_args()
    
    # Load environment variables
    load_dotenv()
    
    # Validate API key
    if args.api_provider == 'openai':
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            print("ERROR: OPENAI_API_KEY environment variable is required")
            sys.exit(1)
    else:
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if not api_key:
            print("ERROR: ANTHROPIC_API_KEY environment variable is required")
            sys.exit(1)
    
    # Initialize scanner
    scanner = PHPVulnerabilityScanner(
        api_provider=args.api_provider,
        api_key=api_key,
        verbose=args.verbose
    )
    
    print_banner()
    
    if args.action == 'scan':
        if not args.target:
            print("ERROR: Target file or directory is required for scanning")
            sys.exit(1)
        
        target_path = Path(args.target)
        if not target_path.exists():
            print(f"ERROR: Target path '{args.target}' does not exist")
            sys.exit(1)
        
        print(f"🔍 Scanning: {target_path}")
        print("=" * 50)
        
        # Perform scan
        results = scanner.scan_target(target_path)
        
        # Display results
        print_results(results, args.verbose)
        
        # Calculate and display performance score
        score = calculate_performance_score(results)
        print(f"\n📊 Performance Score: {score}/10,000")
        
        # Save to file if requested
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"📄 Results saved to: {args.output}")
        
        # Exit with error code if vulnerabilities found
        if results.get('vulnerabilities'):
            sys.exit(1)
    
    elif args.action == 'benchmark':
        print("🏃 Running benchmark tests...")
        benchmark_file = Path(__file__).parent / 'tests' / 'vulnerable_sample.php'
        
        if not benchmark_file.exists():
            print("ERROR: Benchmark file not found")
            sys.exit(1)
        
        # Run benchmark scan
        import time
        start_time = time.time()
        results = scanner.scan_target(benchmark_file)
        end_time = time.time()
        
        scan_time = end_time - start_time
        vulnerabilities_found = len(results.get('vulnerabilities', []))
        
        print(f"\n⏱️  Scan completed in {scan_time:.2f} seconds")
        print(f"🎯 Vulnerabilities found: {vulnerabilities_found}")
        
        # Calculate benchmark score
        score = calculate_performance_score(results)
        print(f"📊 Performance Score: {score}/10,000")
        
        # Display results
        print_results(results, verbose=True)

if __name__ == "__main__":
    main()
