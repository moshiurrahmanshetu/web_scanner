"""
SQL Injection Scanner Module
Detects SQL injection vulnerabilities in web applications
"""

import sys
import os
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from payloads import SQLI_PAYLOADS, SQL_ERROR_PATTERNS


class SQLIScanner:
    """Scans for SQL Injection vulnerabilities"""
    
    def __init__(self, timeout=10):
        """
        Initialize SQL Injection scanner
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def scan_url(self, url):
        """
        Scan a URL for SQL injection vulnerabilities
        
        Args:
            url: Target URL to scan
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Parse URL to extract parameters
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            if not query_params:
                # If no query parameters, try POST method or return empty
                return vulnerabilities
            
            # Test each parameter
            for param_name in query_params.keys():
                
                for payload in SQLI_PAYLOADS:
                    # Create modified parameters
                    test_params = parse_qs(parsed_url.query)
                    original_value = query_params[param_name][0]
                    test_params[param_name] = [original_value + payload]

                    
                    # Reconstruct URL with payload
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment
                    ))
                    
                    try:
                        # Send request with payload
                        response = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                        
                        # Check for SQL error patterns in response
                        if self._check_sql_errors(response.text):
                            vuln = {
                                'type': 'SQL Injection',
                                'parameter': param_name,
                                'severity': 'HIGH',
                                'payload': payload,
                                'url': test_url,
                                'status_code': response.status_code
                            }
                            vulnerabilities.append(vuln)
                            break  # Found vulnerability, move to next parameter
                    
                    except requests.exceptions.RequestException as e:
                        continue
            
            # Also test POST method if GET parameters exist
            if query_params:
                vulnerabilities.extend(self._test_post_method(url, query_params))
            
        except Exception as e:
            # Log error silently for web app
            pass
        
        return vulnerabilities
    
    def _test_post_method(self, url, query_params):
        """Test SQL injection via POST method"""
        vulnerabilities = []
        
        try:
            parsed_url = urlparse(url)
            base_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                '',
                parsed_url.fragment
            ))
            
            for param_name in query_params.keys():
                for payload in SQLI_PAYLOADS[:5]:  # Test first 5 payloads for POST
                    data = {param_name: payload}
                    
                    try:
                        response = self.session.post(base_url, data=data, timeout=self.timeout, allow_redirects=True)
                        
                        if self._check_sql_errors(response.text):
                            vuln = {
                                'type': 'SQL Injection',
                                'parameter': param_name,
                                'severity': 'HIGH',
                                'payload': payload,
                                'url': base_url,
                                'method': 'POST',
                                'status_code': response.status_code
                            }
                            vulnerabilities.append(vuln)
                            break
                    
                    except requests.exceptions.RequestException:
                        continue
        
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def _check_sql_errors(self, response_text):
        """
        Check if response contains SQL error patterns
        
        Args:
            response_text: HTML/text response from server
            
        Returns:
            True if SQL error pattern found, False otherwise
        """
        response_lower = response_text.lower()
        
        for pattern in SQL_ERROR_PATTERNS:
            if pattern.lower() in response_lower:
                return True
        
        return False

