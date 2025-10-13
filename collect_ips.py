import requests
from bs4 import BeautifulSoup
import re
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List
import ipaddress
import warnings

# 忽略SSL警告
warnings.filterwarnings('ignore')

class IPCrawler:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
        }
        
        # URL list
        self.urls = [
            'https://ip.164746.xyz',
            'https://cf.090227.xyz',
            'https://stock.hostmonit.com/CloudFlareYes',
            'https://www.wetest.vip/page/cloudflare/address_v4.html',
            'https://monitor.gacjie.cn/page/cloudflare/ipv4.html',
            'https://ipdb.api.030101.xyz/?type=bestcf',
            'https://ipdb.api.030101.xyz/?type=bestproxy',
            'https://www.visa.cn',
            'https://cf.877774.xyz',
            'https://ct.877774.xyz',
            'https://cmcc.877774.xyz',
            'https://cu.877774.xyz',
            'https://asia.877774.xyz',
            'https://eur.877774.xyz',
            'https://na.877774.xyz',
            'https://bpb.yousef.isegaro.com',
            'https://netlify-cname.xingpingcn.top',
            'https://vercel.001315.xyz',
            'https://vercel-cname.xingpingcn.top',
            'https://cnamefuckxxs.yuchen.icu',
            'https://cdn.2020111.xyz',
            'https://cf-cname.xingpingcn.top',
            'https://cfcdn.v6.rocks',
            'https://aliyun.2096.us.kg',
            'https://time.cloudflare.com',
            'https://checkout.shopify.com',
            'https://shopify.com',
            'https://time.is',
            'https://icook.hk',
            'https://icook.tw',
            'https://ip.sb',
            'https://japan.com',
            'https://malaysia.com',
            'https://russia.com',
            'https://singapore.com',
            'https://skk.moe',
            'https://www.visa.com',
            'https://www.visa.com.sg',
            'https://www.visa.com.hk',
            'https://www.visa.com.tw',
            'https://www.visa.co.jp',
            'https://www.visakorea.com',
            'https://www.gco.gov.qa',
            'https://www.gov.se',
            'https://www.gov.ua',
            'https://www.digitalocean.com',
            'https://www.csgo.com',
            'https://www.shopify.com',
            'https://www.whoer.net',
            'https://www.whatismyip.com',
            'https://www.ipget.net',
            'https://www.hugedomains.com',
            'https://www.udacity.com',
            'https://www.4chan.org',
            'https://www.okcupid.com',
            'https://www.glassdoor.com',
            'https://www.udemy.com',
            'https://www.baipiao.eu.org',
            'https://cdn.anycast.eu.org',
            'https://edgetunnel.anycast.eu.org',
            'https://alejandracaiccedo.com',
            'https://nc.gocada.co',
            'https://log.bpminecraft.com',
            'https://www.boba88slot.com',
            'https://gur.gov.ua',
            'https://www.zsu.gov.ua',
            'https://www.iakeys.com',
            'https://edtunnel-dgp.pages.dev',
            'https://www.d-555.com',
            'https://fbi.gov',
            'https://linux.do',
            'https://cloudflare.182682.xyz',
            'https://speed.marisalnc.com',
            'https://freeyx.cloudflare88.eu.org',
            'https://bestcf.top',
            'https://cfip.cfcdn.vip',
            'https://cf.0sm.com',
            'https://cf.zhetengsha.eu.org',
            'https://cloudflare.9jy.cc',
            'https://cf.zerone-cdn.pp.ua',
            'https://cfip.1323123.xyz',
            'https://cloudflare-ip.mofashi.ltd',
            'https://115155.xyz',
            'https://cname.xirancdn.us',
            'https://f3058171cad.002404.xyz',
            'https://8.889288.xyz',
            'https://cdn.tzpro.xyz',
            'https://cf.877771.xyz'
        ]
        
        # IP regex pattern
        self.ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        
        # IP:port regex pattern
        self.ip_port_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d{1,5}\b'
        
        self.unique_ips = set()
        self.unique_ip_ports = set()
        self.failed_urls = []
        self.success_count = 0
    
    def is_valid_ip(self, ip: str) -> bool:
        """Validate if IP address is valid and public"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Exclude private, loopback, reserved IPs
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast:
                return False
            # Exclude special ranges
            if ip.startswith(('0.', '10.', '127.', '169.254.', '192.168.', '224.', '240.', '255.')):
                return False
            # Check 172.16-31 private range
            parts = ip.split('.')
            if parts[0] == '172' and 16 <= int(parts[1]) <= 31:
                return False
            return True
        except (ValueError, IndexError):
            return False
    
    def extract_ips_from_html(self, html_content: str, url: str) -> Set[str]:
        """Extract IP addresses from HTML content"""
        ips = set()
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Method 1: Find IPs in all text content
            text_content = soup.get_text()
            ip_matches = re.findall(self.ip_pattern, text_content)
            
            # Method 2: Process table data
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows:
                    cells = row.find_all(['td', 'th'])
                    for cell in cells:
                        cell_text = cell.get_text(strip=True)
                        cell_ips = re.findall(self.ip_pattern, cell_text)
                        ip_matches.extend(cell_ips)
            
            # Method 3: Find in specific tags
            for tag in soup.find_all(['span', 'div', 'p', 'code', 'pre', 'li']):
                tag_text = tag.get_text(strip=True)
                tag_ips = re.findall(self.ip_pattern, tag_text)
                ip_matches.extend(tag_ips)
            
            # Method 4: Extract IP:port format
            ip_port_matches = re.findall(self.ip_port_pattern, text_content)
            for ip_port in ip_port_matches:
                ip = ip_port.split(':')[0]
                if self.is_valid_ip(ip):
                    self.unique_ip_ports.add(ip_port)
            
            # Validate and add valid IPs
            for ip in ip_matches:
                if self.is_valid_ip(ip):
                    ips.add(ip)
            
            if ips:
                print(f'Success: {url[:60]} - Found {len(ips)} IPs')
            else:
                print(f'No IPs: {url[:60]}')
            
        except Exception as e:
            print(f'Error parsing {url[:60]}: {str(e)[:50]}')
        
        return ips
    
    def fetch_url(self, url: str, retry: int = 2) -> str:
        """Fetch URL content with retry support"""
        for attempt in range(retry):
            try:
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    timeout=15,
                    verify=False,
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    response.encoding = response.apparent_encoding
                    return response.text
                else:
                    if attempt == retry - 1:
                        print(f'HTTP {response.status_code}: {url[:60]}')
                    
            except requests.exceptions.Timeout:
                if attempt == retry - 1:
                    print(f'Timeout: {url[:60]}')
            except requests.exceptions.SSLError:
                if attempt == retry - 1:
                    print(f'SSL Error: {url[:60]}')
            except requests.exceptions.ConnectionError:
                if attempt == retry - 1:
                    print(f'Connection Error: {url[:60]}')
            except requests.exceptions.RequestException as e:
                if attempt == retry - 1:
                    print(f'Request Error: {url[:60]} - {str(e)[:30]}')
                break
            except Exception as e:
                if attempt == retry - 1:
                    print(f'Unknown Error: {url[:60]} - {str(e)[:30]}')
                break
            
            if attempt < retry - 1:
                time.sleep(1)
        
        return None
    
    def crawl_single_url(self, url: str) -> Set[str]:
        """Crawl single URL"""
        print(f'Crawling: {url[:70]}...')
        html_content = self.fetch_url(url)
        
        if html_content:
            self.success_count += 1
            return self.extract_ips_from_html(html_content, url)
        else:
            self.failed_urls.append(url)
            return set()
    
    def crawl_all_urls(self, use_threading: bool = True, max_workers: int = 10):
        """Crawl all URLs"""
        print('=' * 70)
        print(f'Starting IP crawling... (Total: {len(self.urls)} URLs)')
        print('=' * 70)
        
        if use_threading:
            # Use multithreading
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_url = {executor.submit(self.crawl_single_url, url): url for url in self.urls}
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        ips = future.result()
                        self.unique_ips.update(ips)
                    except Exception as e:
                        print(f'Processing error: {url[:60]} - {str(e)[:50]}')
                        self.failed_urls.append(url)
        else:
            # Sequential crawling
            for url in self.urls:
                ips = self.crawl_single_url(url)
                self.unique_ips.update(ips)
                time.sleep(0.5)
    
    def sort_ips(self, ips: Set[str]) -> List[str]:
        """Sort IPs by numeric order"""
        try:
            return sorted(ips, key=lambda ip: [int(part) for part in ip.split('.')])
        except:
            return sorted(ips)
    
    def save_to_file(self, filename: str = 'ip.txt'):
        """Save IP addresses to file"""
        print('\n' + '=' * 70)
        print('Saving results...')
        print('=' * 70)
        
        # Remove old file
        if os.path.exists(filename):
            os.remove(filename)
        
        if self.unique_ips:
            sorted_ips = self.sort_ips(self.unique_ips)
            
            with open(filename, 'w', encoding='utf-8') as file:
                for ip in sorted_ips:
                    file.write(ip + '\n')
            
            print(f'Saved {len(sorted_ips)} unique IPs to {filename}')
            
            # Show first 10 IPs
            print('\nFirst 10 IPs:')
            for ip in sorted_ips[:10]:
                print(f'  - {ip}')
            if len(sorted_ips) > 10:
                print(f'  ... and {len(sorted_ips) - 10} more')
        else:
            print('No valid IPs found')
        
        # Save IP:port format if exists
        if self.unique_ip_ports:
            port_filename = 'ip_with_port.txt'
            if os.path.exists(port_filename):
                os.remove(port_filename)
            
            sorted_ip_ports = sorted(self.unique_ip_ports)
            with open(port_filename, 'w', encoding='utf-8') as file:
                for ip_port in sorted_ip_ports:
                    file.write(ip_port + '\n')
            
            print(f'\nSaved {len(sorted_ip_ports)} IP:port entries to {port_filename}')
    
    def print_statistics(self):
        """Print statistics"""
        print('\n' + '=' * 70)
        print('Statistics')
        print('=' * 70)
        print(f'Total URLs: {len(self.urls)}')
        print(f'Success: {self.success_count}')
        print(f'Failed: {len(self.failed_urls)}')
        print(f'Unique IPs: {len(self.unique_ips)}')
        if self.unique_ip_ports:
            print(f'IP:Port entries: {len(self.unique_ip_ports)}')
        
        if self.failed_urls:
            print(f'\nFailed URLs ({len(self.failed_urls)}):')
            for url in self.failed_urls[:5]:
                print(f'  - {url}')
            if len(self.failed_urls) > 5:
                print(f'  ... and {len(self.failed_urls) - 5} more')
    
    def add_custom_url(self, url: str):
        """Add custom URL"""
        if url not in self.urls:
            self.urls.append(url)
            print(f'Added custom URL: {url}')
    
    def run(self):
        """Run crawler"""
        start_time = time.time()
        
        try:
            self.crawl_all_urls(use_threading=True, max_workers=10)
            self.save_to_file()
            self.print_statistics()
        except KeyboardInterrupt:
            print('\n\nInterrupted by user, saving collected data...')
            self.save_to_file()
            self.print_statistics()
        except Exception as e:
            print(f'\n\nProgram error: {e}')
            if self.unique_ips:
                print('Saving collected data...')
                self.save_to_file()
        
        elapsed_time = time.time() - start_time
        print(f'\nTotal time: {elapsed_time:.2f} seconds')
        print('=' * 70)


def main():
    """Main function"""
    print("""
===============================================================
               IP Address Batch Crawler Tool
                      Version 2.0
===============================================================
    """)
    
    crawler = IPCrawler()
    
    # Add custom URLs if needed
    # crawler.add_custom_url('https://example.com/ips')
    
    try:
        crawler.run()
    except Exception as e:
        print(f'\nProgram crashed: {e}')
        print('Please check your network connection')


if __name__ == '__main__':
    main()
