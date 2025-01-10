import subprocess
import datetime
import os
import re
from urllib.parse import urlparse

def validate_url(url):
    """Validate the URL format."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def sanitize_filename(url):
    """Create a safe filename from URL."""
    clean_name = re.sub(r'[^a-zA-Z0-9]', '_', urlparse(url).netloc)
    return clean_name

def run_nikto_scan(target_url):
    """Run Nikto scan with basic options and return the output."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    #create output directory if it doesn't exist
    output_dir = "nikto_scans"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    #generate output filename
    output_file = f"{output_dir}/nikto_scan_{sanitize_filename(target_url)}_{timestamp}.txt"

    try:
        #construct Nikto command
        nikto_cmd = [
            "nikto",
            "-host", target_url,
            "-output", output_file,
            "-Format", "txt"
        ]

        print(f"\n[+] Starting Nikto scan against {target_url}")
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

def main():
    print("=== Nikto Website Vulnerability Scanner ===")

    while True:
        target_url = input("\nEnter target URL (or 'quit' to exit): ").strip()

        if target_url.lower() == 'quit':
            break

        if not validate_url(target_url):
            print("[X] Invalid URL format. Please include the scheme (http:// or https://)")
            continue
        
        if run_nikto_scan(target_url):
            choice = input("\nWould you like to scan another target? (y/n): ").strip().lower()
            if choice != 'y':
                break
        else:
            print("\n[X] Scan failed. Please check the error messages above.")
            continue

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Fatal error {str(e)}")
    finally:
        print("\n[+] Script execution completed.")