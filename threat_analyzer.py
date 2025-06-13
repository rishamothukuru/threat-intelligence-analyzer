import os
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        print("\n[+] VirusTotal IP Info:")
        print(f" - Harmless: {stats['harmless']}")
        print(f" - Malicious: {stats['malicious']}")
        print(f" - Suspicious: {stats['suspicious']}")
    else:
        print("[-] VirusTotal Error:", response.status_code)

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()['data']
        print("\n[+] AbuseIPDB IP Info:")
        print(f" - Abuse Score: {data['abuseConfidenceScore']}")
        print(f" - Country: {data['countryCode']}")
        print(f" - ISP: {data['isp']}")
        print(f" - Total Reports: {data['totalReports']}")
    else:
        print("[-] AbuseIPDB Error:", response.status_code)

def main():
    ip = input("Enter IP address to check: ")
    check_virustotal(ip)
    check_abuseipdb(ip)

if __name__ == "__main__":
    main()
