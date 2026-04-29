#!/usr/bin/env python3
"""
SUBTZ - Advanced Passive Subdomain Enumeration Framework
By: AniipID
Open Source | No API keys required | Async Engine (fixed event loop)
"""

import argparse
import re
import sys
import json
import os
import asyncio
from collections import OrderedDict
from urllib.parse import urlparse
import aiohttp
from colorama import init, Fore, Style

init(autoreset=True)

# ========== BANNER ==========
BANNER = r"""
  ██████  █    ██  ██████  ▄▄▄█████▓ ██▒   █▓
▒██    ▒  ██  ▓██▒██    ▒  ▓  ██▒ ▓▒▓██░   █▒
░ ▓██▄   ▓██  ▒██░ ▓██▄    ▒ ▓██░ ▒░ ▓██  █▒░
  ▒   ██▒▓▓█  ░██░ ▒   ██▒ ░ ▓██▓ ░   ▒██ █░░
▒██████▒▒▒▒█████▓▒██████▒▒   ▒██▒ ░    ▒▀█░  
▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒▒ ▒▓▒ ▒ ░   ▒ ░░      ░ ▐░  
░ ░▒  ░ ░░░▒░ ░ ░░ ░▒  ░ ░     ░       ░ ░░  
░  ░  ░   ░░░ ░  ░  ░  ░     ░           ░░  
      ░     ░          ░                ░   
"""

CREDIT = "By: AniipID"

# ========== GLOBAL CONFIG ==========
CONCURRENT_LIMIT = 20
TIMEOUT = aiohttp.ClientTimeout(total=25, connect=10)

def clean_domain(domain):
    domain = domain.lower().strip()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    return domain.rstrip('.')

async def fetch(session, url, method='GET', **kwargs):
    """Async fetch with retry."""
    for attempt in range(2):
        try:
            async with session.request(method, url, timeout=TIMEOUT, **kwargs) as resp:
                if resp.status == 200:
                    return await resp.text()
                elif resp.status == 429:
                    await asyncio.sleep(2)
                    continue
                else:
                    return None
        except Exception:
            await asyncio.sleep(0.5)
    return None

# ========== SOURCE FETCH FUNCTIONS ==========
async def fetch_crtsh(session, domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    text = await fetch(session, url)
    if text:
        try:
            data = json.loads(text)
            return [entry['name_value'].strip().lstrip('*.').lower() for entry in data]
        except (json.JSONDecodeError, TypeError):
            pass
    # Fallback text output
    url2 = f"https://crt.sh/?q=%25.{domain}&output=text"
    text = await fetch(session, url2)
    if text:
        subs = []
        for line in text.splitlines():
            parts = line.split()
            if parts:
                subs.append(parts[0].lower())
        return subs
    return []

async def fetch_certspotter(session, domain):
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    text = await fetch(session, url)
    if text:
        try:
            data = json.loads(text)
            subs = []
            for entry in data:
                for dns in entry.get('dns_names', []):
                    subs.append(dns.lstrip('*.').lower())
            return subs
        except (json.JSONDecodeError, TypeError):
            pass
    return []

async def fetch_otx(session, domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    text = await fetch(session, url)
    if text:
        try:
            data = json.loads(text)
            return [entry['hostname'].lower() for entry in data.get('passive_dns', [])]
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    return []

async def fetch_wayback(session, domain):
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=text&fl=original&collapse=urlkey"
    text = await fetch(session, url)
    if text:
        subs = set()
        for line in text.splitlines():
            line = line.strip()
            if line:
                parsed = urlparse(line)
                if parsed.hostname:
                    subs.add(parsed.hostname.lower())
        return list(subs)
    return []

async def fetch_rapiddns(session, domain):
    url = f"https://rapiddns.io/subdomain/{domain}?full=1#result"
    text = await fetch(session, url)
    if text:
        subs = re.findall(r'<td>([^<]+)</td>', text)
        return [s.lower() for s in subs if domain in s and '.' in s]
    return []

async def fetch_bufferover(session, domain):
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    text = await fetch(session, url)
    if text:
        try:
            data = json.loads(text)
            entries = data.get('FDNS_A', []) + data.get('RDNS', [])
            subs = [entry.split(',')[1] if ',' in entry else entry for entry in entries]
            return [s.lower() for s in subs if '.' in s]
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    return []

async def fetch_riddler(session, domain):
    url = f"https://riddler.io/search/exportcsv?q=pld:{domain}"
    text = await fetch(session, url)
    if text:
        pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(domain)
        return list(set(re.findall(pattern, text, re.IGNORECASE)))
    return []

async def fetch_anubis(session, domain):
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    text = await fetch(session, url)
    if text:
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [s.lower() for s in data]
        except (json.JSONDecodeError, TypeError):
            pass
    return []

async def fetch_subdomaincenter(session, domain):
    url = f"https://api.subdomain.center/?domain={domain}"
    text = await fetch(session, url)
    if text:
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [s.lower() for s in data]
        except (json.JSONDecodeError, TypeError):
            pass
    return []

async def fetch_urlscan(session, domain):
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    text = await fetch(session, url)
    if text:
        try:
            data = json.loads(text)
            return [item['page']['domain'].lower() for item in data.get('results', [])]
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    return []

async def fetch_hackertarget(session, domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    text = await fetch(session, url)
    if text:
        lines = text.splitlines()
        return [line.split(',')[0].lower() for line in lines if ',' in line and '.' in line]
    return []

async def fetch_threatcrowd(session, domain):
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    text = await fetch(session, url)
    if text:
        try:
            data = json.loads(text)
            return [s.lower() for s in data.get('subdomains', [])]
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    return []

async def fetch_threatminer(session, domain):
    url = f"https://api.threatminer.org/v2/domain.php?domain={domain}&rt=5"
    text = await fetch(session, url)
    if text:
        try:
            data = json.loads(text)
            if data.get('status_code') == '200':
                return [s.lower() for s in data.get('results', [])]
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    return []

async def fetch_virustotal_ui(session, domain):
    url = f"https://www.virustotal.com/ui/domains/{domain}/subdomains?limit=40"
    headers = {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    text = await fetch(session, url, headers=headers)
    if text:
        try:
            data = json.loads(text)
            return [item['id'].lower().replace('https://', '').replace('http://', '') for item in data.get('data', [])]
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    return []

async def fetch_commoncrawl(session, domain):
    indexes = ["CC-MAIN-2023-50", "CC-MAIN-2024-10", "CC-MAIN-2024-22"]
    all_subs = set()
    for idx in indexes:
        url = f"http://index.commoncrawl.org/{idx}-index?url=*.{domain}&output=json"
        text = await fetch(session, url)
        if text:
            for line in text.splitlines():
                if line.strip():
                    try:
                        obj = json.loads(line)
                        url_str = obj.get('url', '')
                        parsed = urlparse(url_str)
                        if parsed.hostname:
                            all_subs.add(parsed.hostname.lower())
                    except (json.JSONDecodeError, TypeError):
                        continue
    return list(all_subs)

async def fetch_dnsbufferover_tls(session, domain):
    url = f"https://tls.bufferover.run/dns?q=.{domain}"
    text = await fetch(session, url)
    if text:
        try:
            data = json.loads(text)
            entries = data.get('Results', [])
            subs = []
            for entry in entries:
                if ',' in entry:
                    subs.append(entry.split(',')[0].strip().lower())
            return subs
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    return []

async def fetch_synapsint(session, domain):
    url = "https://synapsint.com/report.php"
    data = {"name": f"https://{domain}"}
    try:
        async with session.post(url, data=data, timeout=TIMEOUT) as resp:
            if resp.status == 200:
                text = await resp.text()
                pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(domain)
                return list(set(re.findall(pattern, text, re.IGNORECASE)))
    except Exception:
        pass
    return []

# ========== SOURCE REGISTRY (urutan menentukan tampilan) ==========
SOURCES = OrderedDict([
    ("crt.sh", fetch_crtsh),
    ("Certspotter", fetch_certspotter),
    ("AlienVault OTX", fetch_otx),
    ("Wayback Machine", fetch_wayback),
    ("RapidDNS", fetch_rapiddns),
    ("BufferOver.run", fetch_bufferover),
    ("tls.BufferOver.run", fetch_dnsbufferover_tls),
    ("Riddler", fetch_riddler),
    ("Anubis DB", fetch_anubis),
    ("Subdomain Center", fetch_subdomaincenter),
    ("URLScan.io", fetch_urlscan),
    ("HackerTarget", fetch_hackertarget),
    ("ThreatCrowd", fetch_threatcrowd),
    ("ThreatMiner", fetch_threatminer),
    ("VirusTotal UI", fetch_virustotal_ui),
    ("CommonCrawl", fetch_commoncrawl),
    ("Synapsint", fetch_synapsint),
])

# ========== ASYNC WORKER ==========
async def worker(domain, semaphore, source_name, source_func, all_subs, results, verbose):
    async with semaphore:
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=10)) as session:
                raw = await source_func(session, domain)
                pattern = re.compile(r'(?:^|\.)' + re.escape(domain) + r'$')
                valid = set()
                for s in raw:
                    s = s.strip().lower().rstrip('.')
                    if s.startswith('*.'):
                        s = s[2:]
                    if pattern.search(s):
                        valid.add(s)
                results[source_name] = len(valid)
                all_subs.update(valid)
                print(Fore.GREEN + f"  [✓] {source_name}: {len(valid)} subdomains")
        except Exception as e:
            results[source_name] = 0
            msg = f"  [✗] {source_name}: failed"
            if verbose:
                msg += f" ({e})"
            print(Fore.RED + msg)

async def run_enum(domain, threads, verbose):
    semaphore = asyncio.Semaphore(threads)
    all_subs = set()
    results = {}
    tasks = [asyncio.create_task(worker(domain, semaphore, name, func, all_subs, results, verbose))
             for name, func in SOURCES.items()]
    await asyncio.gather(*tasks)
    return all_subs, results

def print_banner():
    print(Fore.CYAN + BANNER)
    try:
        term_width = os.get_terminal_size().columns
    except:
        term_width = 80
    credit_line = CREDIT.center(term_width)
    print(Style.BRIGHT + Fore.WHITE + credit_line)
    print()

def main():
    parser = argparse.ArgumentParser(description="SUBTZ - Passive Subdomain Enumeration Framework By AniipID")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", help="Output file to save subdomains")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Concurrent workers (default: 20)")
    parser.add_argument("--no-banner", action="store_true", help="Hide banner")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed errors")
    args = parser.parse_args()

    verbose = args.verbose
    if not args.no_banner:
        print_banner()

    domain = clean_domain(args.domain)
    print(Fore.GREEN + f"[+] Target: {domain}")
    print(Fore.WHITE + f"[*] Running Mohon Bersabar...\n")

    # ✅ Gunakan asyncio.run() – tidak ada lagi deprecation warning
    all_subs, results = asyncio.run(run_enum(domain, args.threads, verbose))

    print(f"\n{Fore.CYAN}[+] Enumeration complete.")
    print(Fore.GREEN + f"    Total unique subdomains: {len(all_subs)}")
    success = sum(1 for v in results.values() if v > 0)
    print(Fore.GREEN + f"    Successful sources: {success}/{len(SOURCES)}")

    sorted_subs = sorted(all_subs)
    if args.output:
        with open(args.output, 'w') as f:
            f.write('\n'.join(sorted_subs) + '\n')
        print(Fore.WHITE + f"[+] Results saved to {args.output}")
    else:
        print(Fore.WHITE + "\n[*] Subdomains found:")
        for sub in sorted_subs:
            print(sub)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)
