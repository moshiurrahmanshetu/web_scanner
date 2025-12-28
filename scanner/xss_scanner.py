"""
XSS (Cross-Site Scripting) Scanner Module
Detects reflected XSS vulnerabilities in web applications
"""

import sys
import os
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from payloads import XSS_PAYLOADS, XSS_DETECTION_PATTERNS


class XSSScanner:
    """Scans for Cross-Site Scripting vulnerabilities"""
    
    def __init__(self, timeout=10):
        """
        Initialize XSS scanner
        
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
        Scan a URL for XSS vulnerabilities
        
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
                return vulnerabilities
            
            # Test each parameter
            for param_name in query_params.keys():
                
                for payload in XSS_PAYLOADS:
                    # Create modified parameters
                    test_params = parse_qs(parsed_url.query)
                    test_params[param_name] = [payload]
                    
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
                        response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                        
                        # Check if payload is reflected in response
                        if self._check_xss_reflection(response.text, payload):
                            # Determine severity
                            severity = self._determine_severity(response.text, payload)
                            
                            vuln = {
                                'type': 'Reflected XSS',
                                'parameter': param_name,
                                'severity': severity,
                                'payload': payload,
                                'url': test_url,
                                'status_code': response.status_code
                            }
                            vulnerabilities.append(vuln)
                            break  # Found vulnerability, move to next parameter
                    
                    except requests.exceptions.RequestException as e:
                        continue
            
            # Also test POST method
            if query_params:
                vulnerabilities.extend(self._test_post_method(url, query_params))
            
        except Exception as e:
            # Log error silently for web app
            pass
        
        return vulnerabilities
    
    def _test_post_method(self, url, query_params):
        """Test XSS via POST method"""
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
                for payload in XSS_PAYLOADS[:5]:  # Test first 5 payloads for POST
                    data = {param_name: payload}
                    
                    try:
                        response = self.session.post(base_url, data=data, timeout=self.timeout, allow_redirects=False)
                        
                        if self._check_xss_reflection(response.text, payload):
                            severity = self._determine_severity(response.text, payload)
                            
                            vuln = {
                                'type': 'Reflected XSS',
                                'parameter': param_name,
                                'severity': severity,
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
    
    def _check_xss_reflection(self, response_text, payload):
        """
        Check if XSS payload is reflected in the response
        
        Args:
            response_text: HTML/text response from server
            payload: The XSS payload that was sent
            
        Returns:
            True if payload is reflected, False otherwise
        """
        # Check if payload appears in response (basic reflection check)
        if payload in response_text:
            return True
        
        # Check for encoded variations
        import html
        if html.escape(payload) in response_text:
            return True
        
        return False
    
    def _determine_severity(self, response_text, payload):
        """
        Determine severity of XSS vulnerability
        
        Args:
            response_text: HTML/text response from server
            payload: The XSS payload
            
        Returns:
            Severity level (HIGH, MEDIUM, LOW)
        """
        # If payload is directly reflected without encoding, it's HIGH severity
        if payload in response_text:
            # Check if it's in a script tag or event handler context
            if '<script>' in payload.lower() or 'onerror=' in payload.lower() or 'onload=' in payload.lower():
                return 'HIGH'
            return 'MEDIUM'
        
        # If encoded but still present, it's MEDIUM
        import html
        if html.escape(payload) in response_text:
            return 'MEDIUM'
        
        return 'LOW'

