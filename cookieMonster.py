import json
from urllib.parse import urlparse
from collections import Counter

def parse_har_file(filename):
    with open(filename, 'r') as file:
        har_data = json.load(file)
        return har_data

har_data = parse_har_file('myhar_final.har')


def extract_sld(url):
    parsed_url = urlparse(url)
    domain_parts = parsed_url.netloc.split('.')
    if len(domain_parts) > 2:
        return '.'.join(domain_parts[-2:])
    return parsed_url.netloc

third_party_requests = {}

for site, data in har_data.items():
    site_sld = extract_sld(site)
    third_party_requests[site] = []

    for entry in data['log']['entries']:
        request_domain = extract_sld(entry['request']['url'])
        if request_domain != site_sld:
            third_party_requests[site].append(request_domain)

# Count the occurrence of each third-party domain across all sites
all_third_parties = [domain for site_domains in third_party_requests.values() for domain in site_domains]
third_party_counter = Counter(all_third_parties)
top_10_third_parties = third_party_counter.most_common(10)


third_party_cookies = {}

for site, data in har_data.items():
    site_sld = extract_sld(site)
    third_party_cookies[site] = []

    for entry in data['log']['entries']:
        response_domain = extract_sld(entry['request']['url'])
        if response_domain != site_sld:
            cookies = entry['response'].get('cookies', [])
            third_party_cookies[site].extend([cookie['name'] for cookie in cookies])

# Count the occurrence of each third-party cookie across all sites
all_third_party_cookies = [cookie for site_cookies in third_party_cookies.values() for cookie in site_cookies]
third_party_cookie_counter = Counter(all_third_party_cookies)
top_10_third_party_cookies = third_party_cookie_counter.most_common(10)
