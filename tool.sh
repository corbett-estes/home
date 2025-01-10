#!/bin/bash

#function to validate IP address format
validate_ip() {
    local ip=$1
    local stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

#function to validate URL format
validate_url() {
    local url=$1
    if [[ $url =~ ^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/?.*$ ]]; then
        return 0
    else
        return 1
    fi
}

#function to check if required tools are installed
check_requirements() {
    local tools=("nmap" "dig" "curl" "nikto")
    local missing_tools=()

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo "Error: The following required tools are missing:"
        printf '%s\n' "${missing_tools[@]}"
        echo "Please install them before running this script."
        exit 1
    fi
}

#function for basic nmap scan
run_basic_nmap() {
    echo "Enter the target IP address:"
    read -r target_ip

    if validate_ip "$target_ip"; then
        echo "Running basic nmap scan on $target_ip..."
        nmap -sV -sC -p- -T4 "$target_ip"
    else
        echo "Invalid IP address format!"
    fi
}

#function for vulnerability nmap scan
run_vuln_nmap() {
    echo "Enter the target IP address:"
    read -r target_ip

    if validate_ip "$target_ip"; then
        echo "Running nmap vulnerability scan on $target_ip..."
        nmap -sV -sC -p- --script=vuln -T4 --open "$target_ip"
    else
        echo "Invalid IP address format!"
    fi
}

#function for DNS lookup
perform_dns_lookup() {
    echo "Enter the domain:"
    read -r domain

    echo "Performing DNS lookup for $domain..."
    dig +short "$domain"
}

#function for HTTP header recon
check_http_headers() {
    echo "Enter the target URL (including http:// or https://):"
    read -r url

    if validate_url "$url"; then
        echo "Checking HTTP headers for $url..."
        curl -I -L "$url"
    else
        echo "Invalid URL format!"
    fi
}

#function for Nikto scan
run_nikto_scan() {
    echo "Enter the target URL (including http:// or https://):"
    read -r url

    if validate_url "$url"; then
        echo "Running Nikto scan on $url..."
        nikto -h "$url"
    else
        echo "Invalid URL format!"
    fi
}

#function for SQLi & XSS exploitation
test_web_vulnerabilities() {
    echo "Enter the URL to test for SQLi & XSS vulnerabilities:"
    read -r base_url

    if validate_url "$base_url"; then
        echo "Testing for basic SQLi vulnerabilities..."
        
        #common SQLi test payloads
        sqli_payloads=(
            "1'OR'1'='1"
            "1+UNION+SELECT+NULL--"
            "1'OR+1=1--"
            "'OR+'1'='1"
        )

        #test each SQLi payload with proper encoding
        for payload in "${sqli_payloads[@]}"; do
            echo -e "\nTesting payload: $payload"
            test_url="${base_url}/?id=${payload}"
            echo "URL: $test_url"

            response=$(curl -L -s "$test_url")
            echo "Analyzing response..."

            if echo "$response" | grep -i -E "sql|syntax|mysql|postgresql|oracle|database|error|warning" > /dev/null; then
                echo "POTENTIAL VULNERABILITY: SQL error messages detected."
                echo "Found SQL-related terms in the response."
            elif echo "$response" | grep -i -E "404|403|500|unexpected|undefined|not found" > /dev/null; then
                echo "Request resulted in an error response."
            else
                echo "No obvious SQL errors detected - manual verification recommended."
            fi
        done

        echo -e "\nTesting for basic XSS vulnerabilities..."
        
        #common XSS test payloads (ULR-endoded versions)
        xss_payloads=(
            "%3Cscript%3Ealert%28%27test%27%29%3C%2Fscript%3E"
            "%3Cimg+src%3Dx+onerror%3Dalert%28%27test%27%29%3E"
            "%22%3E%3Cscript%3Ealert%28%27test%27%29%3C#2Fscript%3E"
            "javascript:alert%28%27test%27%29"
        )

        #test each XSS payload with proper encoding
        for payload in "${xss_payloads[@]}"; do
            echo -e "\nTesting payload: $payload"
            test_url="${base_url}/?search=${payload}"
            echo "URL: $test_url"

            #fetch and analyze response
            response=$(curl -L -s "$test_url")
            echo "Analyzing response..."

            #check if the payload is reflected in the response
            if echo "$response" | grep -i -E "script|alert|onerror|javascript:" > /dev/null; then
                echo "POTENTIAL XSS VULNERABILITY: XSS Payload was reflected in the response!"
            else
                echo "Payload not reflected in response..."
            fi
        done

        echo -e "\n SQLi/XSS Vulnerability testing complete. Please manually verify any potential findings."

    else
        echo "Invalid URL format!"
    fi
}

#main menu
main_menu() {
    while true; do
        echo -e "\nSecurity Testing Menu"
        echo "1. Run initial nmap scan (-sC -sV -p- -T4)"
        echo "2. Run nmap vulnerability scan (-sC -sV -p- --script=vuln -T4 --open)"
        echo "3. DNS lookup"
        echo "4. Check HTTP headers"
        echo "5. Run Nikto scan"
        echo "6. Test for SQLi & XSS vulnerabilities"
        echo "7. Exit"

        read -rp "Select an option (1-7): " choice

        case $choice in
            1) run_basic_nmap ;;
            2) run_vuln_nmap ;;
            3) perform_dns_lookup ;;
            4) check_http_headers ;;
            5) run_nikto_scan ;;
            6) test_web_vulnerabilities ;;
            7) echo "Exiting..."; exit 0 ;;
            *) echo "Invalid option. Please select 1-7." ;;
        esac

        echo -e "\nPress Enter to continue..."
        read -r
    done
}

#check requirements before starting
check_requirements

#display warning message
echo "WARNING: This script is for authorized testing only."
echo "Only use this tool on systems for which you have explicit testing authorization."
read -rp "Press Enter to continue..."

#start the main menu
main_menu