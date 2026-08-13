import os
import re
import socket
import ipaddress
import threading
from queue import Queue
from urllib.parse import urlparse

import requests
from colorama import Fore, Style, init


# ============================================================
# WINDOWS POWERSHELL / CMD COLORS
# ============================================================

init(autoreset=True)

RED = Fore.LIGHTRED_EX
LIME = Fore.LIGHTGREEN_EX
ORANGE = Fore.LIGHTYELLOW_EX
CYAN = Fore.LIGHTCYAN_EX
WHITE = Fore.WHITE
GRAY = Fore.LIGHTBLACK_EX
YELLOW = Fore.LIGHTYELLOW_EX

BRIGHT = Style.BRIGHT


# ============================================================
# GLOBAL DATA
# ============================================================

all_results = set()
domains = set()
subdomains = set()

results_lock = threading.Lock()
write_lock = threading.Lock()
progress_lock = threading.Lock()

processed = 0
total_ips = 0

# One requests.Session per worker thread
session_local = threading.local()


# ============================================================
# UNWANTED PREFIXES
# ============================================================

UNWANTED_PREFIXES = {
    "www",
    "api",
    "cpanel",
    "webmail",
    "webdisk",
    "ftp",
    "cpcalendars",
    "cpcontacts",
    "mail",
    "ns1",
    "ns2",
    "ns3",
    "ns4",
    "ns5",
    "ns6",
    "autodiscover",
}


# ============================================================
# THREAD-LOCAL HTTP SESSION
# ============================================================

def get_session():
    """
    Return a separate requests.Session for each thread.
    """

    if not hasattr(session_local, "http_session"):

        new_session = requests.Session()

        new_session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "Chrome/120.0 Safari/537.36"
            )
        })

        session_local.http_session = new_session

    return session_local.http_session


# ============================================================
# UNIQUE OUTPUT FILENAME
# ============================================================

def get_output_filename(filename):

    if not os.path.exists(filename):
        return filename

    name, extension = os.path.splitext(filename)

    count = 2

    while True:

        new_filename = f"{name}({count}){extension}"

        if not os.path.exists(new_filename):
            return new_filename

        count += 1


# ============================================================
# IP VALIDATION
# ============================================================

def is_valid_ip(value):

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


# ============================================================
# HOSTNAME VALIDATION
# ============================================================

HOSTNAME_LABEL = re.compile(
    r"^(?!-)[a-z0-9-]{1,63}(?<!-)$",
    re.IGNORECASE
)


def is_valid_hostname(hostname):

    if not hostname:
        return False

    hostname = hostname.lower().strip().rstrip(".")

    if not hostname:
        return False

    if len(hostname) > 253:
        return False

    if is_valid_ip(hostname):
        return False

    parts = hostname.split(".")

    if len(parts) < 2:
        return False

    if len(parts[-1]) < 2:
        return False

    for part in parts:

        if not HOSTNAME_LABEL.match(part):
            return False

    return True


# ============================================================
# CLEAN HOSTNAME
# ============================================================

def clean_hostname(value):

    if not value:
        return None

    hostname = value.strip().lower()

    if "error:invalid ipv4 address" in hostname:
        return None

    # Extract hostname from URL
    if "://" in hostname:

        try:

            parsed = urlparse(hostname)

            hostname = parsed.hostname or ""

        except Exception:
            return None

    # Remove path
    hostname = hostname.split("/", 1)[0]

    # Remove trailing dot
    hostname = hostname.rstrip(".")

    if not is_valid_hostname(hostname):
        return None

    parts = hostname.split(".")

    # Remove unwanted prefixes only from beginning
    while len(parts) > 2 and parts[0] in UNWANTED_PREFIXES:
        parts.pop(0)

    cleaned = ".".join(parts)

    if not is_valid_hostname(cleaned):
        return None

    return cleaned


# ============================================================
# GET ROOT DOMAIN
# ============================================================

def get_root_domain(hostname):

    parts = hostname.split(".")

    if len(parts) < 2:
        return None

    return ".".join(parts[-2:])


# ============================================================
# SAVE RESULT LIVE
# ============================================================

def save_result(output_file, value):

    with write_lock:

        with open(
            output_file,
            "a",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            file.write(value + "\n")
            file.flush()


# ============================================================
# ADD DOMAIN / SUBDOMAIN
# ============================================================

def add_hostname(hostname, output_file):

    cleaned = clean_hostname(hostname)

    if not cleaned:
        return 0, 0

    root_domain = get_root_domain(cleaned)

    if not root_domain:
        return 0, 0

    new_domain = 0
    new_subdomain = 0
    items_to_save = []

    with results_lock:

        # Root domain
        if root_domain not in domains:

            domains.add(root_domain)

            new_domain = 1

            if root_domain not in all_results:

                all_results.add(root_domain)

                items_to_save.append(root_domain)

        # Subdomain
        if cleaned != root_domain:

            if cleaned not in subdomains:

                subdomains.add(cleaned)

                new_subdomain = 1

                if cleaned not in all_results:

                    all_results.add(cleaned)

                    items_to_save.append(cleaned)

    # Save after releasing results lock
    for item in items_to_save:
        save_result(output_file, item)

    return new_domain, new_subdomain


# ============================================================
# SOURCE 1: PTR / REVERSE DNS
# ============================================================

def lookup_ptr(ip):

    found = set()

    try:

        hostname, aliases, _ = socket.gethostbyaddr(ip)

        if hostname:
            found.add(hostname)

        for alias in aliases:

            if alias:
                found.add(alias)

    except (
        socket.herror,
        socket.gaierror,
        OSError
    ):
        pass

    return found


# ============================================================
# SOURCE 2: HACKERTARGET
# ============================================================

def lookup_hackertarget(ip):

    found = set()

    url = (
        "https://api.hackertarget.com/"
        "reverseiplookup/"
    )

    try:

        http_session = get_session()

        response = http_session.get(
            url,
            params={"q": ip},
            timeout=20
        )

        if response.status_code != 200:
            return found

        text = response.text.strip()

        if not text:
            return found

        text_lower = text.lower()

        error_indicators = (
            "error",
            "api count exceeded",
            "no records found",
            "api limit",
            "daily limit",
        )

        if any(
            indicator in text_lower
            for indicator in error_indicators
        ):
            return found

        for line in text.splitlines():

            hostname = line.strip().lower()

            if is_valid_hostname(hostname):
                found.add(hostname)

    except requests.RequestException:
        pass

    return found


# ============================================================
# SOURCE 3: URLSCAN.IO
# ============================================================

def lookup_urlscan(ip, api_key):

    found = set()

    if not api_key:
        return found

    url = "https://urlscan.io/api/v1/search/"

    headers = {
        "API-Key": api_key
    }

    params = {
        "q": f"page.ip:{ip}",
        "size": 100
    }

    try:

        http_session = get_session()

        response = http_session.get(
            url,
            headers=headers,
            params=params,
            timeout=30
        )

        if response.status_code == 429:
            return found

        if response.status_code != 200:
            return found

        data = response.json()

        results = data.get("results", [])

        for result in results:

            # Page hostname
            page = result.get("page", {})

            domain = page.get("domain")

            if domain:
                found.add(domain)

            # Hostname from task URL
            task = result.get("task", {})

            task_url = task.get("url")

            if task_url:

                try:

                    parsed = urlparse(task_url)

                    if parsed.hostname:
                        found.add(parsed.hostname)

                except Exception:
                    pass

    except (
        requests.RequestException,
        ValueError
    ):
        pass

    return found


# ============================================================
# PROCESS ONE IP
# ============================================================

def process_ip(ip, output_file, urlscan_api_key):

    global processed

    found_hostnames = set()

    source_counts = {
        "PTR": 0,
        "HT": 0,
        "URLSCAN": 0,
    }

    # --------------------------------------------------------
    # PTR
    # --------------------------------------------------------

    ptr_results = lookup_ptr(ip)

    source_counts["PTR"] = len(ptr_results)

    found_hostnames.update(ptr_results)

    # --------------------------------------------------------
    # HACKERTARGET
    # --------------------------------------------------------

    hackertarget_results = lookup_hackertarget(ip)

    source_counts["HT"] = len(
        hackertarget_results
    )

    found_hostnames.update(
        hackertarget_results
    )

    # --------------------------------------------------------
    # URLSCAN
    # --------------------------------------------------------

    urlscan_results = lookup_urlscan(
        ip,
        urlscan_api_key
    )

    source_counts["URLSCAN"] = len(
        urlscan_results
    )

    found_hostnames.update(
        urlscan_results
    )

    # --------------------------------------------------------
    # ADD RESULTS
    # --------------------------------------------------------

    ip_domains = 0
    ip_subdomains = 0

    for hostname in found_hostnames:

        new_domain, new_subdomain = add_hostname(
            hostname,
            output_file
        )

        ip_domains += new_domain
        ip_subdomains += new_subdomain

    # --------------------------------------------------------
    # PRINT PROGRESS
    # --------------------------------------------------------

    with progress_lock:

        processed += 1

        print(
            f"{GRAY}[{processed}/{total_ips}] "
            f"{BRIGHT}{RED}{ip} "
            f"{GRAY}| "
            f"{BRIGHT}{LIME}DOMAIN: {ip_domains} "
            f"{GRAY}| "
            f"{BRIGHT}{ORANGE}SUBDOMAIN: {ip_subdomains} "
            f"{GRAY}| "
            f"{CYAN}PTR:{source_counts['PTR']} "
            f"HT:{source_counts['HT']} "
            f"URLSCAN:{source_counts['URLSCAN']}"
        )


# ============================================================
# WORKER
# ============================================================

def worker(queue, output_file, urlscan_api_key):

    while True:

        ip = queue.get()

        try:

            if ip is None:
                break

            process_ip(
                ip,
                output_file,
                urlscan_api_key
            )

        except Exception as error:

            with progress_lock:

                print(
                    f"{BRIGHT}{RED}"
                    f"[ERROR] {ip} -> {error}"
                )

        finally:

            queue.task_done()


# ============================================================
# READ AND VALIDATE IPS
# ============================================================

def read_ips(filename):

    ips = set()
    invalid_count = 0

    try:

        with open(
            filename,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for line in file:

                ip = line.strip()

                if not ip:
                    continue

                if is_valid_ip(ip):
                    ips.add(ip)

                else:
                    invalid_count += 1

    except FileNotFoundError:

        print(
            f"{RED}[!] File not found: "
            f"{filename}"
        )

        return []

    except PermissionError:

        print(
            f"{RED}[!] Permission denied: "
            f"{filename}"
        )

        return []

    print(
        f"{LIME}[*] Unique valid IPs: "
        f"{WHITE}{len(ips)}"
    )

    if invalid_count:

        print(
            f"{YELLOW}[*] Invalid lines skipped: "
            f"{WHITE}{invalid_count}"
        )

    return sorted(ips)


# ============================================================
# THREAD INPUT
# ============================================================

def get_thread_count():

    while True:

        value = input(
            f"{CYAN}"
            "Enter number of threads [20]: "
        ).strip()

        if not value:
            return 20

        try:

            threads = int(value)

            if threads < 1:

                print(
                    f"{RED}[!] "
                    "Threads must be at least 1."
                )

                continue

            return threads

        except ValueError:

            print(
                f"{RED}[!] "
                "Please enter a valid number."
            )


# ============================================================
# MAIN
# ============================================================

def main():

    global total_ips

    print(
        f"\n{CYAN}{BRIGHT}"
        + "=" * 78
    )

    print(
        f"{WHITE}{BRIGHT}"
        "      MULTI-SOURCE REVERSE IP DOMAIN + SUBDOMAIN GRABBER"
    )

    print(
        f"{CYAN}{BRIGHT}"
        + "=" * 78
    )

    # Input file
    input_file = input(
        f"\n{CYAN}"
        "Enter IP input file "
        f"{GRAY}[IPS.txt]{CYAN}: "
    ).strip()

    if not input_file:
        input_file = "IPS.txt"

    # Output file
    output_file = input(
        f"{CYAN}"
        "Enter output file "
        f"{GRAY}[OUTPUT_HOST.txt]{CYAN}: "
    ).strip()

    if not output_file:
        output_file = "OUTPUT_HOST.txt"

    # urlscan API key
    urlscan_api_key = input(
        f"{CYAN}"
        "Enter urlscan.io API key "
        f"{GRAY}[leave blank to disable]{CYAN}: "
    ).strip()

    # Threads
    threads = get_thread_count()

    # Read IPs
    ips = read_ips(input_file)

    if not ips:

        print(
            f"\n{BRIGHT}{RED}"
            "[!] No valid IP addresses found."
        )

        return

    total_ips = len(ips)

    # Never create more threads than IPs
    threads = min(threads, total_ips)

    # Create safe output filename
    output_file = get_output_filename(
        output_file
    )

    # Create output file
    with open(
        output_file,
        "w",
        encoding="utf-8"
    ):
        pass

    # Start information
    print(
        f"\n{CYAN}"
        + "=" * 78
    )

    print(
        f"{WHITE}TOTAL IPS: "
        f"{LIME}{total_ips}"
    )

    print(
        f"{WHITE}THREADS: "
        f"{LIME}{threads}"
    )

    print(
        f"{WHITE}PTR: "
        f"{LIME}ENABLED"
    )

    print(
        f"{WHITE}HACKERTARGET: "
        f"{LIME}ENABLED"
    )

    if urlscan_api_key:

        print(
            f"{WHITE}URLSCAN: "
            f"{LIME}ENABLED"
        )

    else:

        print(
            f"{WHITE}URLSCAN: "
            f"{RED}DISABLED"
        )

    print(
        f"{WHITE}OUTPUT: "
        f"{CYAN}{output_file}"
    )

    print(
        f"{CYAN}"
        + "=" * 78
        + "\n"
    )

    # Create queue
    queue = Queue()

    for ip in ips:
        queue.put(ip)

    # Start worker threads
    workers = []

    for _ in range(threads):

        thread = threading.Thread(
            target=worker,
            args=(
                queue,
                output_file,
                urlscan_api_key
            ),
            daemon=True
        )

        thread.start()

        workers.append(thread)

    # Wait until all IPs are processed
    queue.join()

    # Stop workers
    for _ in workers:
        queue.put(None)

    for thread in workers:
        thread.join()

    # ========================================================
    # FINAL RESULTS
    # ========================================================

    print(
        f"\n{CYAN}{BRIGHT}"
        + "=" * 78
    )

    print(
        f"{WHITE}{BRIGHT}"
        "                           FINISHED"
    )

    print(
        f"{CYAN}{BRIGHT}"
        + "=" * 78
    )

    print(
        f"{WHITE}TOTAL IPS PROCESSED: "
        f"{CYAN}{processed}"
    )

    print(
        f"{WHITE}TOTAL UNIQUE DOMAINS: "
        f"{BRIGHT}{LIME}{len(domains)}"
    )

    print(
        f"{WHITE}TOTAL UNIQUE SUBDOMAINS: "
        f"{BRIGHT}{ORANGE}{len(subdomains)}"
    )

    print(
        f"{WHITE}TOTAL UNIQUE RESULTS: "
        f"{BRIGHT}{CYAN}{len(all_results)}"
    )

    print(
        f"{WHITE}SAVED TO: "
        f"{BRIGHT}{LIME}{output_file}"
    )

    print(
        f"{CYAN}{BRIGHT}"
        + "=" * 78
    )


if __name__ == "__main__":
    main()
