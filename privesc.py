from pwn import *
import os
import sys
import subprocess

def privilege_audit():
    """
    A security testing script that safely checks system configurations and logs findings for authorized security assessments.
    """

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