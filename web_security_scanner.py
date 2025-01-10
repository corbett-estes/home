import requests
from bs4 import BeautifulSoup
import logging
import time
from urllib.parse import urljoin, parse_qs, urlparse
import sys
import re
import warnings
warnings.filterwarnings('ignore')

def check_dependencies():
    """Check and install required dependencies"""
    required_packages = {
        'beautifulsoup4': 'bs4',
        'requests': 'requests',
        'lxml': 'lxml'
    }

    missing_packages = []

    for package, import_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print("\nMissing required packages. Please install:")
        print(f"pip install {' '.join(missing_packages)}")
        sys.exit(1)

class WebSecurityScanner:
    def __init__(self):
        self.logger = self.setup_logging()

    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_scan.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)

    def initialize_scanner(self, url, delay=0.5, verify_ssl=False, cookies=None, headers=None):
        """Initialize scanner with user-provied settings"""
        self.base_url = url.rstrip('/')
        self.delay = delay
        self.session = requests.Session()
        self.findings = []
        self.tested_urls = set()

        self.session.verify = verify_ssl
        if not verify_ssl:
            requests.packages.urllib3.disable_warnings()

        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)

    def test_xss(self, url, param_name, method='GET', current_value=''):
        """Test for XSS vulnerabilities."""
        payloads = [
            '<script>alert(/XSS/)</script>',
            '"><script>alert(/XSS/)</script>',
            '<img src=x onerror=alert(/XSS/)>',
            '<svg onload=alert(/XSS/)',
            '"onmouseover="alert(/XSS/)',
            '<!--<script>alert(/XSS/)</script>-->',
            '<body onload=alert(/XSS/)>',
            '<img src="" onerror="alert(/XSS/)">',
            '<ScRiPt>alert(/XSS/)</ScRiPt>',
            'javascript:alert(/XSS/)',
            '"><iframe src="javascript:alert(/XSS/)">',
            '`onmouseover=alert(/XSS/)',
            '<scr<script>ipt>alert(1)</scr</script>ipt>'
        ]

        for payload in payloads:
            try:
                if method == 'GET':
                    response = self.session.get(
                        url,
                        params={param_name: payload},
                        allow_redirects=True
                    )
                else:
                    data = {param_name: payload},
                    response = self.session.post(
                        url,
                        data=data,
                        allow_redirects=True
                    )

                if payload.lower() in response.text.lower():
                    soup = BeautifulSoup(response.text, 'lxml')
                    script_tags = soup.find_all('script')
                    event_handlers = soup.find_all(attrs=lambda x: x and any(attr for attr in x if attr.startswith('on')))

                    if script_tags or event_handlers:
                        self.log_finding(
                            'XSS Vulnerability',
                            f'XSS payload reflected in {method} parameter: {param_name}',
                            {
                                'url': url,
                                'parameter': param_name,
                                'method': method,
                                'payload': payload,
                                'context': 'script_tag' if script_tags else 'event_handler'
                            }
                        )
                        return

            except Exception as e:
                self.logger.error(f"Error testing XSS: {str(e)}")

            time.sleep(self.delay)
    
    def test_sqli(self, url, param_name, method='GET', current_value=''):
        """Test for SQLi vulnerabilities."""
        payloads = [
            "' OR '1'='1",
            "admin' --",
            "'OR 1=1--",
            "' UNION SELECT NULL--",
            "')) OR 1=1--",
            "' OR '1'='1'#",
            "1' ORDER BY 10--",
            "1 UNION SELECT null,null,null--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(1)))a)--",
            "1' AND (SELECT COUNT(*) FROM information.schema.tables)>0--",
            "' OR '1'='1'--",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--"
        ]

        try:
            if method.upper() == 'GET':
                baseline = self.session.get(
                    url,
                    params={param_name: current_value or 'normal'},
                )
            else:
                baseline = self.session.post(
                    url,
                    data={param_name: current_value or 'normal'},
                )

            baseline_len = len(baseline.text)
            baseline_time = baseline.elapsed.total_seconds()

            for payload in payloads:
                try:
                    start_time = time.time()
                    if method.upper() == 'GET':
                        response = self.session.get(
                            url,
                            params={param_name: payload},
                        )
                    else:
                        response = self.session.post(
                            url,
                            data={param_name: payload},
                        )

                    response_time = time.time() - start_time

                    sql_errors = [
                        'sql syntax',
                        'mysql_fetch',
                        'sqlite3',
                        'ORA-01756',
                        'postgresql',
                        'SQL syntax.*MySQL',
                        'Warning.mysql_.*',
                        'valid MySQL result',
                        'MariaDB',
                        'SQL Server',
                        'Microsoft OLE DB Provider for SQL Server',
                        'PostgreSQL.*ERROR',
                        'Warning.*pg_.*',
                        'Oracle.*Driver',
                        'Warning.*oci_.*',
                        'microsoft sql server',
                        'mysql_num_rows'
                    ]

                    response_text = response.text.lower()

                    #Check for various types of SQLi
                    if any(error.lower() in response.text for error in sql_errors):
                        self.log_finding(
                            'SQLi',
                            f'SQL error detected in {method} parameter: {param_name}',
                            {
                                'url': url,
                                'parameter': param_name,
                                'method': method,
                                'payload': payload,
                                'type': 'Error-based'
                            }
                        )
                        return

                    #check for time-based SQLi
                    if response_time > baseline_time + 1:
                        self.log_finding(
                            'Potential SQLi',
                            f'Time-based SQLi detected in {method} parameter: {param_name}',
                            {
                                'url': url,
                                'parameter': param_name,
                                'method': method,
                                'payload': payload,
                                'type': 'Time-based',
                                'baseline_time': baseline_time,
                                'response_time': response_time
                            }
                        )
                        return

                    #check for boolean-based SQLi
                    response_len = len(response.text)
                    if abs(response_len - baseline_len) > 50:
                        self.log_finding(
                            'Potential SQLi',
                            f'Response length anomaly in {method} parameter: {param_name}',
                            {
                                'url': url,
                                'parameter': param_name,
                                'method': method,
                                'payload': payload,
                                'type': 'Boolean-based',
                                'baseline_length': baseline_len,
                                'response_length': response_len
                            }
                        )
                        return

                except Exception as e:
                    self.logger.error(f"Error testing SQLi payload {payload}: {str(e)}")

                time.sleep(self.delay)

        except Exception as e:
            self.logger.error(f"Error getting baseline for SQLi testing: {str(e)}")

    def extract_params_from_url(self, url):
        """Extract parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return params

    def crawl_and_test(self, url):
        """Recursively crawl and test pages."""
        if url in self.tested_urls or not url.startswith(self.base_url):
            return

        self.tested_urls.add(url)
        print(f"\n[*] Testing URL: {url}")

        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.content, 'lxml')

            params = self.extract_params_from_url(url)
            for param in params:
                self.test_xss(url, param, 'GET')
                self.test_sqli(url, param, 'GET')

            for form in soup.find_all('form'):
                action = form.get('action', '')
                if not action:
                    action = url
                action_url = urljoin(url, action)
                method = form.get('method', 'get').upper()

                for input_field in form.find_all(['input', 'textarea']):
                    param_name = input_field.get('name')
                    if param_name:
                        current_value = input_field.get('value', '')
                        print(f"[*] Testing form parameter: {param_name}")
                        self.test_xss(action_url, param_name, method, current_value)
                        self.test_sqli(action_url, param_name, method, current_value)

            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    absolute_url = urljoin(url, href)
                    if absolute_url.startswith(self.base_url):
                        self.crawl_and_test(absolute_url)

        except Exception as e:
            self.logger.error(f"Error crawling {url}: {str(e)}")

    def log_finding(self, vuln_type, description, details):
        """Log a security finding."""
        finding = {
            'type': vuln_type,
            'description': description,
            'details': details,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.findings.append(finding)
        print(f"\n[+] Found {vuln_type}")
        print(f"Description: {description}")
        print(f"Details: {details}\n")

def run_web_security_scan():
    """Main function to run the web security scanner"""
    try:
        print("\n === SQLi & XSS Web App Scanner === ")

        #get target URL
        while True:
            target_url = input("\nEnter the target URL: ").strip()
            if target_url:
                if not target_url.startswith(('http://', 'https://')):
                    target_url = 'http://' + target_url
                break
            print("Please enter a valid URL!")

        #get scan options
        print("\nScan Options:")
        delay = input("Enter delay between requests (default: 0.5s): ").strip()
        delay = float(delay) if delay else 0.5

        verify_ssl = input("Verify SSL certificates? (y/N): ").lower().strip() == 'y'

        #initialize and run scanner
        scanner = WebSecurityScanner()
        scanner.initialize_scanner(target_url, delay=delay, verify_ssl=verify_ssl)

        print("\n[*] Starting test...")
        print(f"[*] Target: {target_url}")
        print("[*] Starting crawl and test...")

        scanner.crawl_and_test(scanner.base_url)

        print("\n[*] Testing complete!")
        print(f"[*] Total findings: {len(scanner.findings)}")
        print(f"[*] Tested URLs: {len(scanner.tested_urls)}")

        input("\nPress Enter to return to main menu...")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        input("\nPress Enter to return to main menu...")
    except Exception as e:
        print(f"\n[!] Error during scan: {str(e)}")
        input("\nPress Enter to return to main menu...")

if __name__ == "__main__":
    run_web_security_scan()