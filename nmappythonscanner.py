import nmap
def scan_subnet(subnet):
    """
    Scan a subnet and retrieve details about hostnames, ports, and states.

    Parameters:
    subnet (str): The subnet to scan (e.g., 192.168.0.1/24").
    """

nm = nmap.PortScanner()
subnet = input("Which subnet would you like to scan? Use CIDR notation (e.g., 192.168.0.1/24): ")

print(f"Scanning subnet: {subnet}...")
try:
    nm.scan(hosts=subnet, arguments='-sC -sV -p- -T4')
    for host in nm.all_hosts():
        print(f"\nHost: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")
        
        for protocol in nm[host].all_protocols():
            print(f"Protocol: {protocol}")

            ports = nm[host][protocol].keys()
    
            for port in sorted(ports):
                port_info = nm[host][protocol][port]
                print(f"Port {port}, State: {port_info['state']}")

except Exception as e:
    print(f"An error occurred: {e}")

if __name__ == "__main__":
    scan_subnet(subnet)