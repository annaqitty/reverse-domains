import socket
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ANSI escape codes for colors
CYAN = '\033[96m'
RED = '\033[91m'
RESET = '\033[0m'

# Global variables
total_found_hosts_count = 0
output_file = 'OUTPUT_HOST.txt'  # Default placeholder
output_lock = Lock()

def reverse_lookup(ip_address):
    global total_found_hosts_count
    try:
        # Perform reverse DNS lookup
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        
        # Process and clean up the hostname
        cleaned_hostname = hostname.replace("www.", "").replace('error:Invalid IPv4 address', '')\
                                   .replace('api.', '').replace('cpanel.', '').replace('webmail.', '')\
                                   .replace('webdisk.', '').replace('ftp.', '').replace('cpcalendars.', '')\
                                   .replace('cpcontacts.', '').replace('mail.', '').replace('ns1.', '')\
                                   .replace('ns2.', '').replace('ns3.', '').replace('ns4.', '')\
                                   .replace('autodiscover.', '')
        
        # Increment the total found hosts count
        with output_lock:
            global total_found_hosts_count
            total_found_hosts_count += 1
        return cleaned_hostname

    except Exception as e:
        print(f"{RED}Error reversing {ip_address}: {e}{RESET}")
        return None

def run_dns_enum(domain):
    try:
        # Run DNS enumeration and capture output
        result = subprocess.run(['dnsrecon', '-d', domain], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode != 0:
            print(f"{RED}Error running dnsrecon for {domain}. Return code: {result.returncode}{RESET}")
        return []
    except FileNotFoundError:
        print(f"{RED}dnsrecon not found. Install it to use this script.{RESET}")
        return []
    except Exception as e:
        print(f"{RED}Error running dnsrecon for {domain}: {e}{RESET}")
        return []

def get_subdomains(domain):
    try:
        # Run subdomain discovery and capture output
        result = subprocess.run(['sublist3r', '-d', domain], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode != 0:
            print(f"{RED}Error running sublist3r for {domain}. Return code: {result.returncode}{RESET}")
        return []
    except FileNotFoundError:
        print(f"{RED}sublist3r not found. Install it to use this script.{RESET}")
        return []
    except Exception as e:
        print(f"{RED}Error running sublist3r for {domain}: {e}{RESET}")
        return []

def process_ip(ip_address):
    hostname = reverse_lookup(ip_address)
    if hostname:
        with output_lock:
            # Write the cleaned hostname to file
            with open(output_file, 'a') as file:
                file.write(f"{hostname}\n")
        
        # Perform DNS enumeration to find associated domains
        dns_records = run_dns_enum(hostname)
        if dns_records:
            with output_lock:
                with open(output_file, 'a') as file:
                    for record in dns_records:
                        if record and record != hostname:
                            file.write(f"{record}\n")
        
        # Perform subdomain discovery
        subdomains = get_subdomains(hostname)
        if subdomains:
            with output_lock:
                with open(output_file, 'a') as file:
                    for subdomain in subdomains:
                        if subdomain and subdomain != hostname:
                            file.write(f"{subdomain}\n")

def read_ips_from_file(filename):
    try:
        with open(filename, 'r') as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"{RED}Input file {filename} not found.{RESET}")
        return []

def main():
    global output_file
    
    # Prompt user for input and output filenames
    input_file = input("Enter the name of the input file (e.g., IPS.txt): ")
    output_file = input("Enter the name of the output file (e.g., OUTPUT_HOST.txt): ")

    # Ensure the output file is empty before starting
    if os.path.exists(output_file):
        os.remove(output_file)

    # Read IP addresses from the input file
    ip_addresses = read_ips_from_file(input_file)
    if not ip_addresses:
        print(f"{RED}No valid IP addresses found in {input_file}.{RESET}")
        return

    # Define the number of threads
    num_threads = 300

    # Use ThreadPoolExecutor to handle threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_ip = {executor.submit(process_ip, ip): ip for ip in ip_addresses}
        
        # Wait for all futures to complete and handle exceptions
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                future.result()
            except Exception as e:
                print(f"{RED}Error processing {ip}: {e}{RESET}")

    # Print the total number of hosts found
    print(f"{CYAN}Total number of hosts found: {total_found_hosts_count}{RESET}")
    print(f"{CYAN}Results have been saved to {output_file}{RESET}")

if __name__ == "__main__":
    main()
