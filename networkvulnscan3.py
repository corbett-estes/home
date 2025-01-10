import nmap
import sys
import socket
import ipaddress
from termcolor import colored
import threading
import time
import re

def get_service_version(service):
    """
    Extract and format service version information.
    """
    version_info = []

    if 'product' in service:
        version_info.append(service['product'])
    if 'version' in service:
        version_info.append(service['version'])
    if 'extrainfo' in service:
        version_info.append(f"({service['extrainfo']})")

    return ' '.join(version_info) if version_info else 'Unknown'

class ScanProgress:
    def __init__(self):
        self.is_scanning = False
        self.current_host = None
        self.hosts_completed = 0
        self.total_hosts = 0
        self.lock = threading.Lock() #add thread safety

    def update_status(self, host=None):
        with self.lock:
            if host:
                self.current_host = host
                self.hosts_completed += 1

class ProgressNmap(nmap.PortScanner):
    def __init__(self, progress_tracker):
        nmap.PortScanner.__init__(self)
        self.progress_tracker = progress_tracker

    def _callback_result(self, host, scan_result):
        """
        Callback function to track scan progress for each host
        """
        if scan_result.get('scan', False):
            self.progress_tracker.update_status(host)                    

def print_progress(progress):
    """
    Display scanning progress in real time.
    """
    spinner = ['|', '/', '-', '\\']
    idx = 0

    while progress.is_scanning:
        status = colored(spinner[idx], 'cyan')
        host_info = f"Current Host: {progress.current_host}" if progress.current_host else "Initializing scan..."
        progress_info = f"Progress: {progress.hosts_completed}/{progress.total_hosts} hosts" if progress.total_hosts > 0 else ""

        #clear line and print progress
        sys.stdout.write('\r' + ' ' * 100 + '\r') #clear line
        sys.stdout.write(f"{status} Scanning... {host_info} {progress_info}")
        sys.stdout.flush()

        idx = (idx + 1) % len(spinner)
        time.sleep(0.1)

    #clear line after scanning is complete
    sys.stdout.write('\r' + ' ' * 100 + '\r')
    sys.stdout.flush()

def validate_network(network):
    """
    Validate the network input is a valid IP or CIDR notation.
    """
    try:
        #attempt to convert to network object to validate
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        print(colored("Invalid network address. Use IP or CIDR notation (e.g., 192.168.1.0/24)", "red"))
        return False

def get_active_hosts(network):
    """
    Perform a quick ping scan to find active hosts.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn') #ping scan
    return [host for host in nm.all_hosts() if nm[host].state() == 'up']

def categorize_vulnerability(severity):
    """
    Categorize vulnerability based on severity.
    """
    categories = {
        'Critical': [],
        'High': [],
        'Medium': [],
        'Low': []
    }

    for category, vulns in categories.items():
        if severity in vulns:
            return category
    return 'Low' #default classification

def scan_network(network, progress):
    """
    Perform network vulnerability scan.
    """
    try:
        print(colored(f"\n[*] Performing initial host discovery on network: {network}", "blue"))

        #first, do a quick ping scan to find active hosts
        active_hosts = get_active_hosts(network)
        progress.total_hosts = len(active_hosts)

        if progress.total_hosts == 0:
            print(colored("\n[!] No active hosts found in the target network.", "yellow"))
            return

        print(colored(f"[+] Found {progress.total_hosts} active hosts", "green"))

        #initialize custom nmap scanner with progress tracking
        nm = ProgressNmap(progress)
        progress.is_scanning = True

        #start progress display thread
        progress_thread = threading.Thread(target=print_progress, args=(progress,))
        progress_thread.daemon = True
        progress_thread.start()

        #perform scan with NSE vulnerability scripts on active hosts
        print(colored("\n[*] Starting vulnerability scan on active network hosts: ", "blue"))

        #organized vulnerability tracking
        vulnerabilities = {
            'Critical': [],
            'High': [],
            'Medium': [],
            'Low': []
        }

        services = {}

        #scan each active host individually for better progress tracking
        for host in active_hosts:
            nm.scan(hosts=network, arguments='-sV --version-intensity 9 -sC -p- --script=vuln -O -T4 --open')

            if host in nm.all_hosts() and nm[host].state() == 'up':
                services[host] = []
                
                #check for open ports and vulnerabilities
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        version_info = get_service_version(service)

                        #store service information
                        services[host].append({
                            'port': port,
                            'protocol': proto,
                            'service': service.get('name', 'Unknown'),
                            'version': version_info
                        })
                        
                        #extract vulnerability information
                        if 'script' in service:
                            for script, result in service['script'].items():
                                if 'vulners' in script or 'vuln' in script:
                                    severity = categorize_vulnerability(script)
                                    vulnerabilities[severity].append({
                                        'host': host,
                                        'port': port,
                                        'service': service.get('name', 'Unknown'),
                                        'script': script,
                                        'result': result
                                    })

        #stop progress display
        progress.is_scanning = False
        time.sleep(0.5) #allow progress thread to complete

        #display service information for each host
        print(colored("\n[*] Service Version Information:", "blue"))
        for host in services:
            print(colored(f"\nHost: {host}", "green"))
            if services[host]:
                for service in sorted(services[host], key=lambda x: x['port']):
                    print(colored(
                        f" Port {service['port']}/{service['protocol']}: "f"{service['service']} - Version: {service['version']}", "cyan"
                    ))

            else:
                print(colored(" No open ports found", "yellow"))

        #display vulnerabilities, sorted by severity
        print(colored("\n[!] Vulnerability Summary:", "yellow"))
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if vulnerabilities[severity]:
                print(colored(f"\n{severity} Vulnerabilities:",
                'red' if severity == 'Critical' else
                'magenta' if severity == 'High' else
                'yellow' if severity == 'Medium' else
                'blue'))
                for vuln in vulnerabilities[severity]:
                    print(colored(f" Host: {vuln['host']} | Port: {vuln['port']} | "
                    f"Service: {vuln['service']} | "
                    f"Script: {vuln['script']}",
                    'red' if severity == 'Critical' else
                    'magenta' if severity == 'High' else
                    'yellow' if severity == 'Medium' else
                    'blue'))
    
    except Exception as e:
        progress.is_scanning = False #ensure progress display stops on error
        print(colored(f"\n[!] Scanning error: {e}", "red"))

def main():
    print(colored("Network Vulnerability Scanner", "green"))
    print(colored("WARNING: Only scan networks you own or have explicit permission to scan!", "red"))

    #initialize progress tracker
    progress = ScanProgress()

    #prompt for network input
    while True:
        network = input(colored("\nEnter target network (CIDR notation, e.g. 192.168.1.0/24): ", "cyan")).strip()

        if validate_network(network):
            try:
                scan_network(network, progress)
                break
            except KeyboardInterrupt:
                progress.is_scanning = False #ensure progress display stops
                print(colored("\n[!] Scan interrupted by user.", "yellow"))
                sys.exit(0)

if __name__ == "__main__":
    main()