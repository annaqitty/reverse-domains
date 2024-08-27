import socket
import threading
import os

# Function to perform reverse DNS lookup and handle output
def reverse_lookup(ip_address, input_save):
    try:
        # Perform reverse DNS lookup
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        
        # Extract domain and subdomain from the hostname
        domain_parts = hostname.split('.')
        
        if len(domain_parts) >= 2:
            domain = '.'.join(domain_parts[-2:])
            subdomain = '.'.join(domain_parts[:-2]) if len(domain_parts) > 2 else None
        else:
            domain = hostname
            subdomain = None

        # Process and clean up the hostname
        cleaned_hostname = hostname.replace("www.", "").replace('error:Invalid IPv4 address', '')\
                                   .replace('api.', '').replace('cpanel.', '').replace('webmail.', '')\
                                   .replace('webdisk.', '').replace('ftp.', '').replace('cpcalendars.', '')\
                                   .replace('cpcontacts.', '').replace('mail.', '').replace('ns1.', '')\
                                   .replace('ns2.', '').replace('ns3.', '').replace('ns4.', '')\
                                   .replace('autodiscover.', '')
        
        # Write to file
        with open(input_save, 'a') as file:
            file.write(f"{cleaned_hostname}\n")

        print(f"Reverse {ip_address} > [1 Domain]")  # Adjust count as needed

    except Exception as e:
        print(f"Reverse {ip_address} > Error: {e}")

def read_ips_from_file(filename):
    with open(filename, 'r') as file:
        # Read IPs from the file and strip any leading/trailing whitespace
        return [line.strip() for line in file.readlines() if line.strip()]

def process_ips_in_threads(ip_addresses, input_save, num_threads):
    # Function to process IPs using multiple threads
    def worker():
        while ip_addresses:
            ip = ip_addresses.pop(0)
            reverse_lookup(ip, input_save)

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    # Define file paths and number of threads
    input_file = 'IPS.txt'
    output_file = 'OUTPUT_HOST.txt'
    num_threads = 300  # Number of threads

    # Ensure output file is empty before starting
    if os.path.exists(output_file):
        os.remove(output_file)

    # Read IP addresses from the input file
    ip_addresses = read_ips_from_file(input_file)

    # Process IP addresses with multiple threads
    process_ips_in_threads(ip_addresses, output_file, num_threads)

    print(f"Results have been written to {output_file}")
