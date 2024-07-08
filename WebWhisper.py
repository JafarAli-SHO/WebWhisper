import argparse
import os
import re
import requests
import warnings
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree
from concurrent.futures import ThreadPoolExecutor, as_completed

warnings.filterwarnings('ignore')

# Branding for WebWhisper
SCRIPT_NAME = "WebWhisper"
LOGO ="""
\033[1;31m  W   W  \033[1;32m EEEEE  \033[1;33m BBBBB   \033[1;34m W   W  \033[1;35m H   H  \033[1;36m IIIII  \033[1;37m SSSSS  \033[1;31m PPPPP  \033[1;32m EEEEE  \033[1;33m RRRRR
\033[1;31m  W   W  \033[1;32m E      \033[1;33m B    B  \033[1;34m W   W  \033[1;35m H   H  \033[1;36m   I    \033[1;37m S      \033[1;31m P   P  \033[1;32m E      \033[1;33m R    R
\033[1;31m  W W W  \033[1;32m EEEE   \033[1;33m BBBBB   \033[1;34m W W W  \033[1;35m HHHHH  \033[1;36m   I    \033[1;37m SSSSS  \033[1;31m PPPPP  \033[1;32m EEEE   \033[1;33m RRRRR
\033[1;31m  WW WW  \033[1;32m E      \033[1;33m B    B  \033[1;34m WW WW  \033[1;35m H   H  \033[1;36m   I    \033[1;37m     S  \033[1;31m P      \033[1;32m E      \033[1;33m R  R
\033[1;31m   W W   \033[1;32m EEEEE  \033[1;33m BBBBB   \033[1;34m  W W   \033[1;35m H   H  \033[1;36m IIIII  \033[1;37m SSSSS  \033[1;31m P      \033[1;32m EEEEE  \033[1;33m R   RR
"""

print(LOGO)
print(f"{SCRIPT_NAME} - The professional web crawling tool for red teamers")

def is_link(link):
    """Check if the link is valid."""
    return not re.match(r'^(mailto|javascript|tel):', link)

def fetch_robots_txt(main_url):
    """Fetch URLs from robots.txt."""
    robots_url = urljoin(main_url, "/robots.txt")
    robots = set()
    try:
        response = requests.get(robots_url, timeout=10)  # Increased timeout for robots.txt fetch
        if response.status_code == 200:
            for line in response.text.split('\n'):
                if line.startswith('Disallow: '):
                    path = line.split(' ')[1]
                    if path:
                        robots.add(urljoin(main_url, path))
    except Exception as e:
        print(f"Failed to fetch robots.txt: {e}")
    return robots

def fetch_sitemap_xml(main_url):
    """Fetch URLs from sitemap.xml."""
    sitemap_url = urljoin(main_url, "/sitemap.xml")
    urls = set()
    try:
        response = requests.get(sitemap_url, timeout=10)  # Increased timeout for sitemap.xml fetch
        if response.status_code == 200:
            tree = ElementTree.fromstring(response.content)
            for elem in tree.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}loc'):
                urls.add(elem.text)
    except Exception as e:
        print(f"Failed to fetch sitemap.xml: {e}")
    return urls

def fetch_urls(url):
    """Fetch URLs from the given webpage."""
    urls = set()
    try:
        response = requests.get(url, timeout=10)  # Increased timeout for fetching initial URLs
        if response.status_code == 200:
            matches = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
            for match in matches:
                full_url = urljoin(url, match.split('#')[0])
                if is_link(full_url):
                    urls.add(full_url)
    except Exception as e:
        print(f"Failed to fetch {url}: {e}")
    return urls

def fetch_files(url):
    """Fetch file URLs from the given webpage."""
    file_types = re.compile(r'.*\.(pdf|jpg|jpeg|png|gif|bmp|doc|docx|xls|xlsx|ppt|pptx|txt|zip|rar|tar|gz|mp3|mp4|avi|mov|js)$', re.IGNORECASE)
    files = set()
    try:
        response = requests.get(url, timeout=10)  # Increased timeout for fetching files
        if response.status_code == 200:
            matches = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
            for match in matches:
                full_url = urljoin(url, match.split('#')[0])
                if file_types.match(full_url):
                    files.add(full_url)
    except Exception as e:
        print(f"Failed to fetch files from {url}: {e}")
    return files

def recursive_crawl(url, main_url, depth, max_depth, visited_urls, internal_urls, external_urls, files):
    """Recursively crawl the website to fetch URLs and files."""
    if depth > max_depth or url in visited_urls:
        return

    visited_urls.add(url)
    try:
        response = requests.get(url, timeout=10)  # Increased timeout for recursive crawling
        if response.status_code == 200:
            matches = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
            for match in matches:
                full_url = urljoin(url, match.split('#')[0])
                if is_link(full_url):
                    if full_url.startswith(main_url):
                        if full_url not in internal_urls:
                            internal_urls.add(full_url)
                            recursive_crawl(full_url, main_url, depth + 1, max_depth, visited_urls, internal_urls, external_urls, files)
                    else:
                        external_urls.add(full_url)
    except Exception as e:
        print(f"Failed to fetch {url}: {e}")

    try:
        file_urls = fetch_files(url)
        files.update(file_urls)
    except Exception as e:
        print(f"Failed to fetch files from {url}: {e}")

def search_sensitive_info_in_js(url):
    """Search for sensitive information in JavaScript files."""
    sensitive_info = set()
    try:
        response = requests.get(url, timeout=10)  # Increased timeout for searching sensitive info
        if response.status_code == 200:
            # Search for API keys
            api_key_matches = re.findall(r'["\']api[_-]?key["\']\s*:\s*[\'"]([^\'"]+)[\'"]', response.text, re.IGNORECASE)
            sensitive_info.update(api_key_matches)
            
            # Search for usernames
            username_matches = re.findall(r'["\']user(?:name)?["\']\s*:\s*[\'"]([^\'"]+)[\'"]', response.text, re.IGNORECASE)
            sensitive_info.update(username_matches)
            
            # Search for passwords
            password_matches = re.findall(r'["\']password["\']\s*:\s*[\'"]([^\'"]+)[\'"]', response.text, re.IGNORECASE)
            sensitive_info.update(password_matches)
            
            # Add more patterns as needed (e.g., access tokens, secrets, etc.)

    except Exception as e:
        print(f"Failed to fetch and search in {url}: {e}")
    
    return sensitive_info

def save_to_file(data, filepath):
    with open(filepath, 'w') as f:
        for item in data:
            f.write(f"{item}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', help='root URL', dest='root', required=True)
    parser.add_argument('-d', '--depth', help='crawl depth', dest='depth', type=int, default=2)
    parser.add_argument('-t', '--threads', help='number of threads', dest='threads', type=int, default=10)
    args = parser.parse_args()

    main_inp = args.root
    if not main_inp.startswith('http'):
        main_inp = 'http://' + main_inp

    main_url = main_inp.rstrip('/')
    crawl_depth = args.depth
    num_threads = args.threads

    internal_urls = set()
    external_urls = set()
    visited_urls = set()
    files = set()
    robots_urls = set()
    sitemap_urls = set()
    js_files = set()

    # Create output directory based on the website name
    domain = urlparse(main_url).netloc
    output_dir = domain
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print(f"Fetching URLs from {main_url}...")

    # Fetch initial URLs from the main page
    initial_urls = fetch_urls(main_url)
    for url in initial_urls:
        full_url = urljoin(main_url, url.split('#')[0])
        if full_url.startswith(main_url):
            internal_urls.add(full_url)
            if full_url.lower().endswith('.js'):
                js_files.add(full_url)
        else:
            external_urls.add(full_url)

    print("Fetching URLs from robots.txt...")
    robots_urls.update(fetch_robots_txt(main_url))
    internal_urls.update(robots_urls)

    print("Fetching URLs from sitemap.xml...")
    sitemap_urls.update(fetch_sitemap_xml(main_url))
    internal_urls.update(sitemap_urls)

    # Use threading for crawling
    print(f"Starting recursive crawling up to depth {crawl_depth} with {num_threads} threads...")
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(recursive_crawl, url, main_url, 0, crawl_depth, visited_urls, internal_urls, external_urls, files) for url in internal_urls]

        for future in as_completed(futures):
            future.result()

    # Fetch JavaScript files and search for sensitive information
    sensitive_info = set()
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        js_futures = [executor.submit(search_sensitive_info_in_js, url) for url in js_files]
        for future in as_completed(js_futures):
            sensitive_info.update(future.result())

    # Save sensitive information to a file
    save_to_file(sensitive_info, os.path.join(output_dir, "sensitive_info.txt"))

    # Save JS URLs to a separate file
    save_to_file(js_files, os.path.join(output_dir, "jsfiles.txt"))

    # Save the results to files
    save_to_file(internal_urls, os.path.join(output_dir, "internal_urls.txt"))
    save_to_file(external_urls, os.path.join(output_dir, "external_urls.txt"))
    save_to_file(robots_urls, os.path.join(output_dir, "robots_urls.txt"))
    save_to_file(sitemap_urls, os.path.join(output_dir, "sitemap_urls.txt"))
    save_to_file(files, os.path.join(output_dir, "files.txt"))

    print(f"\nResults saved in {output_dir} directory:")
    print(f"Total internal URLs fetched: {len(internal_urls)}")
    print(f"Total external URLs fetched: {len(external_urls)}")
    print(f"Total URLs from robots.txt fetched: {len(robots_urls)}")
    print(f"Total URLs from sitemap.xml fetched: {len(sitemap_urls)}")
    print(f"Total files fetched: {len(files)}")
    print(f"Total JS files fetched: {len(js_files)}")
    print(f"Total sensitive information found: {len(sensitive_info)}")

if __name__ == '__main__':
    main()
