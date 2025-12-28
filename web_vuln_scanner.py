"""
Mini Web Vulnerability Scanner & Attack Detector
Main application file - Entry point for the scanner
"""

import os
import sys
import json
from datetime import datetime
from db_config import DatabaseManager
from scanner.sqli_scanner import SQLIScanner
from scanner.xss_scanner import XSSScanner


class WebVulnerabilityScanner:
    """Main scanner application"""
    
    def __init__(self):
        """Initialize the scanner"""
        self.db = DatabaseManager()
        self.sqli_scanner = SQLIScanner()
        self.xss_scanner = XSSScanner()
        self.scan_id = None
        self.vulnerabilities = []
        
        # Create reports directory if it doesn't exist
        os.makedirs('reports', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
    
    def initialize_database(self):
        """Initialize database connection and tables"""
        print("\n" + "="*60)
        print("Initializing Database Connection...")
        print("="*60)
        
        # Create database if it doesn't exist
        if not self.db.create_database():
            print("Failed to create database. Please check MySQL connection.")
            return False
        
        # Connect to database
        if not self.db.connect():
            print("Failed to connect to database.")
            print("Please ensure:")
            print("  1. MySQL/XAMPP is running")
            print("  2. Database 'web_scanner_db' exists")
            print("  3. Credentials in db_config.py are correct")
            return False
        
        # Create tables
        if not self.db.create_tables():
            print("Failed to create tables.")
            return False
        
        print("✓ Database connected successfully")
        return True
    
    def scan_url(self, target_url):
        """
        Perform vulnerability scan on target URL
        
        Args:
            target_url: URL to scan
        """
        print("\n" + "="*60)
        print("WEB VULNERABILITY SCAN")
        print("="*60)
        print(f"Target URL: {target_url}")
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        # Validate URL
        if not target_url.startswith(('http://', 'https://')):
            print("Error: URL must start with http:// or https://")
            return
        
        # Save scan to database
        self.scan_id = self.db.save_scan(target_url)
        if not self.scan_id:
            print("Error: Failed to save scan to database")
            return
        
        print(f"\nScan ID: {self.scan_id}")
        print("\nStarting vulnerability scan...")
        print("-"*60)
        
        # Run SQL Injection scan
        print("\n[1/2] Running SQL Injection Scanner...")
        sqli_vulns = self.sqli_scanner.scan_url(target_url)
        self.vulnerabilities.extend(sqli_vulns)
        
        # Run XSS scan
        print("\n[2/2] Running XSS Scanner...")
        xss_vulns = self.xss_scanner.scan_url(target_url)
        self.vulnerabilities.extend(xss_vulns)
        
        # Save vulnerabilities to database
        self._save_vulnerabilities()
        
        # Display results
        self._display_results()
        
        # Generate reports
        self._generate_reports()
    
    def _save_vulnerabilities(self):
        """Save detected vulnerabilities to database"""
        for vuln in self.vulnerabilities:
            self.db.save_vulnerability(
                self.scan_id,
                vuln['type'],
                vuln.get('parameter', 'N/A'),
                vuln['severity'],
                vuln['payload']
            )
    
    def _display_results(self):
        """Display scan results in console"""
        print("\n" + "="*60)
        print("SCAN RESULTS SUMMARY")
        print("="*60)
        
        total_vulns = len(self.vulnerabilities)
        
        if total_vulns == 0:
            print("\n✓ No vulnerabilities detected!")
            print("The target URL appears to be secure against the tested attacks.")
        else:
            print(f"\n⚠ Total Vulnerabilities Found: {total_vulns}")
            
            # Count by severity
            high_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'HIGH')
            medium_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'MEDIUM')
            low_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'LOW')
            
            print(f"\nSeverity Breakdown:")
            print(f"  HIGH:   {high_count}")
            print(f"  MEDIUM: {medium_count}")
            print(f"  LOW:    {low_count}")
            
            # Group by type
            print(f"\nVulnerability Details:")
            print("-"*60)
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n[{i}] {vuln['type']}")
                print(f"    Severity: {vuln['severity']}")
                print(f"    Parameter: {vuln.get('parameter', 'N/A')}")
                print(f"    Payload: {vuln['payload'][:80]}...")
                if 'url' in vuln:
                    print(f"    Test URL: {vuln['url'][:100]}...")
        
        print("\n" + "="*60)
    
    def _generate_reports(self):
        """Generate JSON and TXT reports"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Generate JSON report
        json_report = {
            'scan_id': self.scan_id,
            'scan_time': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities
        }
        
        json_filename = f'reports/scan_report_{timestamp}.json'
        with open(json_filename, 'w') as f:
            json.dump(json_report, f, indent=2)
        
        # Generate TXT report
        txt_filename = f'reports/scan_report_{timestamp}.txt'
        with open(txt_filename, 'w') as f:
            f.write("="*60 + "\n")
            f.write("WEB VULNERABILITY SCAN REPORT\n")
            f.write("="*60 + "\n\n")
            f.write(f"Scan ID: {self.scan_id}\n")
            f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Vulnerabilities: {len(self.vulnerabilities)}\n\n")
            
            if self.vulnerabilities:
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    f.write(f"\n[{i}] {vuln['type']}\n")
                    f.write(f"    Severity: {vuln['severity']}\n")
                    f.write(f"    Parameter: {vuln.get('parameter', 'N/A')}\n")
                    f.write(f"    Payload: {vuln['payload']}\n")
                    if 'url' in vuln:
                        f.write(f"    Test URL: {vuln['url']}\n")
                    f.write("-"*60 + "\n")
            else:
                f.write("\nNo vulnerabilities detected.\n")
        
        print(f"\n✓ Reports generated:")
        print(f"  - {json_filename}")
        print(f"  - {txt_filename}")
    
    def show_scan_history(self):
        """Display recent scan history"""
        print("\n" + "="*60)
        print("SCAN HISTORY")
        print("="*60)
        
        history = self.db.get_scan_history(limit=10)
        
        if not history:
            print("No scan history found.")
        else:
            print(f"\n{'ID':<5} {'URL':<40} {'Scan Time':<20}")
            print("-"*60)
            for record in history:
                scan_id, url, scan_time = record
                url_short = url[:37] + "..." if len(url) > 40 else url
                print(f"{scan_id:<5} {url_short:<40} {str(scan_time):<20}")
    
    def cleanup(self):
        """Close database connection"""
        if self.db:
            self.db.disconnect()


def main():
    """Main entry point"""
    scanner = WebVulnerabilityScanner()
    
    try:
        # Initialize database
        if not scanner.initialize_database():
            print("\nExiting...")
            return
        
        while True:
            print("\n" + "="*60)
            print("MINI WEB VULNERABILITY SCANNER")
            print("="*60)
            print("\nOptions:")
            print("  1. Scan URL for vulnerabilities")
            print("  2. View scan history")
            print("  3. Exit")
            
            choice = input("\nEnter your choice (1-3): ").strip()
            
            if choice == '1':
                target_url = input("\nEnter target URL to scan: ").strip()
                if target_url:
                    scanner.scan_url(target_url)
                else:
                    print("Error: URL cannot be empty")
            
            elif choice == '2':
                scanner.show_scan_history()
            
            elif choice == '3':
                print("\nThank you for using Mini Web Vulnerability Scanner!")
                break
            
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
    
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        scanner.cleanup()


if __name__ == "__main__":
    main()

