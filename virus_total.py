"""
VirusTotal URL Checker
Handles URL extraction and scanning via VirusTotal API
"""
import re
import base64
import time
import requests


class VirusTotalChecker:
    """Check URLs using VirusTotal API"""
    
    def __init__(self, api_key):
        """Initialize VirusTotal checker"""
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}
        
        # VirusTotal endpoints
        self.url_scan_endpoint = "https://www.virustotal.com/api/v3/urls"
        self.url_report_endpoint = "https://www.virustotal.com/api/v3/urls/{}"
        
        # Settings
        self.max_retries = 5
        self.retry_delay = 3
    
    def extract_urls(self, text):
        """Extract all URLs from text - preserve EXACT format as found"""
        # Pattern to match URLs with or without protocol
        url_pattern = r'\b(?:(?:https?://)?(?:www\.)?)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?(?:[/?#][^\s]*)?\b'
        
        urls  = re.findall(url_pattern, text)
    
        unique_urls = []
        seen = set()

        for url in urls:
            # Clean trailing punctuation (like 'Visit google.com.')
            clean_url = url.strip('.,!?;:)')
            
            if clean_url not in seen:
                seen.add(clean_url)
                unique_urls.append(clean_url)
                
        return unique_urls
        
    def check_url(self, url):
        """
        Check URL using VirusTotal API
    
        """
        try:
            
            # Submit URL to VirusTotal
            scan_response = requests.post(
                self.url_scan_endpoint,
                headers=self.headers,
                data={"url": url},  
                timeout=10
            )
            
            if scan_response.status_code != 200:
                # If exact URL fails, try with http:// prefix as fallback
                if not url.startswith(('http://', 'https://')):
                    print(f"  Retry with http:// prefix...")
                    
                return {
                    'error': f'VirusTotal API error: {scan_response.status_code}',
                    'url': url
                }
            
            scan_data = scan_response.json()
            url_id = scan_data['data']['id']
            
            # Poll for results
            for attempt in range(self.max_retries):
                time.sleep(self.retry_delay)
                report_url = self.url_report_endpoint.format(url_id)
                report_response = requests.get(report_url, headers=self.headers, timeout=10)
                
                if report_response.status_code == 400:
                    if attempt < self.max_retries - 1:
                        continue
                    else:
                        # Try to get cached report
                        return self.get_cached_report(url)
                
                if report_response.status_code != 200:
                    if attempt < self.max_retries - 1:
                        continue
                    return {'error': 'Could not retrieve report', 'url': url}
                
                # Parse results
                report_data = report_response.json()
                stats = report_data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total_engines = sum(stats.values())
                is_harmful = malicious > 0 or suspicious > 0
                
                result = {
                    'url': url,  
                    'is_harmful': is_harmful,
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'total_engines': total_engines,
                    'status': 'HARMFUL' if is_harmful else 'SAFE',
                    'details': f"{malicious} engines flagged as malicious, {suspicious} as suspicious",
                    'exact_match': True  
                }
                
                print(f"  Result: {result['status']} ({malicious}M/{suspicious}S)")
                return result
                
        except Exception as e:
            print(f"  Error: {str(e)}")
            return {'error': f'Error checking URL: {str(e)}', 'url': url}
    
    
    
    def get_cached_report(self, url):
        """
        Try to get cached report from VirusTotal
        First tries exact URL, then tries with http:// if needed
        """
        # Try exact URL first
        cached = self._try_cached_lookup(url)
        if cached:
            return cached
        
        # If no protocol and lookup failed, try with http://
        if not url.startswith(('http://', 'https://')):
            prefixed = f"http://{url}"
            cached = self._try_cached_lookup(prefixed)
            if cached:
                cached['url'] = url  # Show original
                cached['scanned_as'] = prefixed
                cached['exact_match'] = False
                return cached
        
        return {'error': 'Analysis in progress - retry in a moment', 'url': url}
    
    def _try_cached_lookup(self, url):
        """Internal method to try cached lookup for specific URL"""
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            report_response = requests.get(report_url, headers=self.headers, timeout=10)
            
            if report_response.status_code == 200:
                report_data = report_response.json()
                stats = report_data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                is_harmful = malicious > 0 or suspicious > 0
                
                return {
                    'url': url,
                    'is_harmful': is_harmful,
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'status': 'HARMFUL' if is_harmful else 'SAFE',
                    'cached': True,
                    'exact_match': True,
                    'details': f"{malicious} engines flagged as malicious, {suspicious} as suspicious (cached)"
                }
        except Exception:
            pass
        
        return None