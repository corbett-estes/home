import socket
import requests
import sys
import nmap
import datetime
import subprocess
from subprocess import Popen, PIPE
import paramiko
import os
import logging
import dns.resolver
import re
import argparse
from pwn import *
from web_security_scanner import run_web_security_scan
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def validate_ip(ip):
    """Validate IP address format"""
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(ip):
        #check each octet
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    return False

def validate_url(url):
    """Validate URL format"""
    pattern = re.compile(
        r'^(http:\/\/www\.|https:\/\/www\.|http:\/\/)?[a-zA-Z0-9]'
        r'+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,5}(:[0-9]{1,5})?(\/.*)?$'
    )
    return bool(pattern.match(url))

def nmap_initial(target):
    """Run initial nmap scan"""
    print(f"\n[*] Starting initial nmap scan on {target}")
    print("[*] This may take several minutes...")

    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-sC -sV -p- -T4')
        
        print("\n[+] Scan Results:")
        for host in nm.all_hosts():
            print(f"\nHost: {host}")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    print(f"Port {port}\tState: {service['state']}\t" f"Service: {service['name']}\tVersion: {service.get('version', 'unknown')}")
                    if 'script' in service:
                        print("Script output:")
                        for script, output in service['script'].items():
                            print(f"\t{script}: {output}")

    except Exception as e:
        print(f"[-] Scan failed: {str(e)}")
        return

def nmap_vuln_scan(target):
    """Run nmap vulnerability scan"""
    print(f"\n[*] Starting nmap vulnerability scan on {target}")
    print("[*] This may take several minutes...")

    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-sC -sV -p- --script=vuln -T4 --open')
        
        print("\n[+] nmap Vulnerability Scan Results:")
        for host in nm.all_hosts():
            print(f"\nHost: {host}")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    print(f"Port {port}")
                    print(f"State: {service['state']}")
                    print(f"Service: {service['name']}")
                    print(f"Version: {service.get('version', 'unknown')}")
                    if 'script' in service:
                        print("Vulnerabilities found:")
                        for script, output in service['script'].items():
                            print(f"\t{script}:")
                            print(f"\t{output}\n")

    except Exception as e:
        print(f"[-] Vulnerability scan failed: {str(e)}")
        return

def perform_dns_lookup():
    """Perform DNS lookup on a provided domain"""
    website = input("\n[?] Enter domain: ")

    try:
        a_records = dns.resolver.resolve(website, 'A')
        print("\n[+] DNS Lookup Results:")
        for record in a_records:
            print(f"IP Address {record}")

        try:
            mx_records = dns.resolver.resolve(website, 'MX')
            print("\nMail Servers:")
            for record in mx_records:
                print(f"Mail Server: {record.exchange} (Priority: {record.preference})")
        except:
            pass

        try:
            ns_records = dns.resolver.resolve(website, 'NS')
            print("\nName Servers:")
            for record in ns_records:
                print(f"Name Server: {record}")
        except:
            pass

    except dns.resolver.NXDOMAIN:
        print("[-] Domain does not exist.")
    except dns.resolver.NoAnswer:
        print("[-] No DNS records found.")
    except Exception as e:
        print(f"[-] DNS lookup failed: {str(e)}")

def port_scanner():
    target = input("Which IP do you want to scan?: ")
    target_ip = socket.gethostbyname(target)
    print("Looking for open ports on host:", target_ip)

    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = sock.connect_ex((target_ip, port))
        if(conn == 0) :
            print(f"Port {port} is open.")
        sock.close()

def http_headers():
    url = input("\n[?] For which HTTP URL (http://www.inserturl.com) would you like to collect headers?: ")

    if not validate_url(url):
        print("[-] Invalid URL format")
        return

    print(f"\n[*] Checking HTTP headers for {url}")

    try:
        response = requests.get(url, verify=False, timeout=10)
        
        print("\n[+] HTTP Headers: ")
        for header, value in response.headers.items():
            print(f"{header}: {value}")

        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'X-Frame-Options': 'Clickjacking Protection',
            'X-Content-Type-Options': 'MIME Sniffing Protection',
            'Content-Security-Policy': 'CSP',
            'X-XSS-Protection': 'XSS Protection',
            'Referrer-Policy': 'Referrer Policy'
        }

        print("\n[+] Security Header Analysis:")
        for header, description in security_headers.items():
            if header in response.headers:
                print(f"{description}: Present - {response.headers[header]}")
            else:
                print(f"{description}: Missing")

    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {str(e)}")

def nikto_scan():
    """Run Nikto scan with basic options and return the output."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    url = input("\nEnter target URL (or 'quit' to exit): ").strip()

    #create output directory if it doesn't exist
    output_dir = "nikto_scans"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    #generate output filename
    output_file = f"{output_dir}/nikto_scan_{timestamp}.txt"

    try:
        #construct Nikto command
        nikto_cmd = [
            "nikto",
            "-host", url,
            "-output", output_file,
            "-Format", "txt"
        ]

        print(f"\n[+] Starting Nikto scan against {url}")
        print(f"[+] Output will be saved to: {output_file}")

        #execute Nikto scan
        process = subprocess.Popen(
            nikto_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        #print real-time output
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())

        return_code = process.poll()

        if return_code == 0:
            print(f"\n[+] Scan completed successfully!")
            print(f"[+] Results saved to: {output_file}")
            return True
        else:
            print("\n[X] Error during scan execution")
            return False

    except subprocess.SubprocessError as e:
        print(f"\n[X] Error executing Nikto: {str(e)}")
        return False
    except Exception as e:
        print(f"\n[X] Unexpected error: {str(e)}")
        return False

def brute_force_ssh():
    try:
        username = input ("Please enter the username at the target machine> ")
        path = input ("Please enter the path & name of the file containing the passwords> ") 
        if os.path.exists(path) == False:   
            print ("The password file does not exist!")
            sys.exit(1)
        target_ip = input ("Please enter the IP address of the target> ")
        try:
            socket.inet_aton(target_ip)
        except socket.error as e:
            print (e)
            sys.exit(2)
    except KeyboardInterrupt:
        print ("\nUser has interrupted the execution!\n")

    def ssh_connect(password, ret_code = 0):
        ssh = paramiko.SSHClient()                                      
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(target_ip, port=22, username=username,password=password)
        except paramiko.AuthenticationException:
            print ("Failed to authenticate! Password: %s" % (password))
            ret_code = 3
        except socket.error as e:
            ret_code = 4

        ssh.close()
        return ret_code

    pass_file = open(path, 'r', encoding="ISO-8859-1")                  

    for i in pass_file.readlines():
        password = i.strip("\n")

        try:
            response = ssh_connect(password)

            if response == 0:
                print ("Login successful! Password is: %s" % (password))
                # insert function call here
                sys.exit(0) 
            elif response == 1:
                print ("Login failed! Incorrect password: %s " % (password))
            elif response == 2:
                print ("Connection to the target failed!")
                sys.exit(5)

        except Exception as e:
            print (e)
            pass

    pass_file.close()

def priv_esc():
    #set up logging
    logging.basicConfig(filename='privilege_audit.log', level=logging.INFO)

    try:
        #get current process privileges
        current_uid = os.getuid()
        current_user = os.getlogin()

        log.info(f"Starting privilege audit as user: {current_user}")

        #check sudo config
        print(f"\n[*] Checking sudo privileges...")
        sudo_config = process(['sudo', '-l'])
        sudo_output = sudo_config.recvall().decode()
        log.info("Sudo privileges found:\n" + sudo_output)

        #check file permissions in important directories
        print(f"\n[*] Checking critical file permissions...")
        critical_dirs = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
        for path in critical_dirs:
            if os.path.exists(path):
                perms = os.stat(path)
                perm_output = f"Permissions for {path}: {oct(perms.st_mode)[-3]}"                
                log.info(perm_output)

        #check for SUID binaries
        print("\n[*] Checking for SUID binaries...")
        try:
            suid_check = subprocess.run(
                ['find', '/', '-perm', '-u=s', '-type', 'f'],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            ) 
            suid_bins = suid_check.stdout
            
            if suid_bins:
                log.info("SUID binaries found:\n" + suid_bins)
            else:
                log.info("No SUID binaries found.")            
                        
        except subprocess.SubprocessError as e:
            log.error(f"SUID check failed: {str(e)}")

    except Exception as e:
        error_msg = f"Audit failed: {str(e)}"       
        log.error(error_msg)

    print("[+] Detailed results saved in privilege_audit.log")
    log.info("Audit complete!")

    if __name__ == "__main__":
        #verify running with appropriate permissions
        if os.getuid() != 0:
            print("This script requires root privileges for system auditing.")
            print("Please run with appropriate authorization.")
            sys.exit(1)

        privilege_audit()

def main():
    print("Security Assessment Tool")

    while True:
        print("""
        Select an assessment type:
        1. Initial nmap scan (-sC -sV -p- -T4)
        2. nmap Vulnerability Scan
        3. DNS Lookup
        4. Find Open Ports for IP Address
        5. Enumerate HTTP Headers
        6. Web App Vulnerability Scan using Nikto
        7. Brute Force SSH
        8. Exploit SQLi & XSS
        9. Explore Common Privilege Escalations
        10.Exit
        """)

        choice = input("[?] Enter your choice (1-10): ")

        if choice == '1':
            target = input("[?] Enter target IP: ")
            if validate_ip(target):
                nmap_initial(target)
            else:
                print("[-] Invalid IP address format.")
        elif choice == '2':
            target = input("[?] Enter target IP: ")
            if validate_ip(target):
                nmap_vuln_scan(target)
        elif choice == '3':
            perform_dns_lookup()
        elif choice == '4':
            port_scanner()
        elif choice == '5':
            http_headers()
        elif choice == '6':
            nikto_scan()
        elif choice == '7':
            brute_force_ssh()
        elif choice == '8':
            run_web_security_scan()
        elif choice == '9':
            priv_esc()
        elif choice == '10':
            print("\n [*] Exiting...")
            break
        else:
            print("[-] Invalid choice. Please try again.")

        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()