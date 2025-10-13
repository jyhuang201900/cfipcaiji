import requests
from bs4 import BeautifulSoup
import re
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List
import ipaddress

class IPCrawler:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
        }
        
        # 扩展的URL列表
        self.urls = [
            'https://ip.164746.xyz',
            'https://cf.090227.xyz',
            'https://stock.hostmonit.com/CloudFlareYes',
            'https://www.wetest.vip/page/cloudflare/address_v4.html',
            'https://monitor.gacjie.cn/page/cloudflare/ipv4.html',
            'https://ipdb.api.030101.xyz/?type=bestcf',
            'https://ipdb.api.030101.xyz/?type=bestproxy',
            'https://www.visa.cn',
            'https://www.visa.cn',
    'https://cf.877774.xyz',
    'https://ct.877774.xyz',
    'https://cmcc.877774.xyz',
    'https://cu.877774.xyz',
    'https://asia.877774.xyz',
    'https://eur.877774.xyz',
    'https://na.877774.xyz',
    'https://bpb.yousef.isegaro.com',
    
    
    'https://netlify-cname.xingpingcn.top'，
    'https://vercel.001315.xyz'，
    'https://vercel-cname.xingpingcn.top'，
    'https://cnamefuckxxs.yuchen.icu',
    'https://cdn.2020111.xyz'，
    'https://cf-cname.xingpingcn.top'，
    'https://cfcdn.v6.rocks'，
    'https://aliyun.2096.us.kg'，
    'https://cf.090227.xyz'，
    'https://time.cloudflare.com'，
    'https://checkout.shopify.com'，
    'https://shopify.com',
    'https://time.is',
    'https://icook.hk',
    'https://icook.tw'，
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
        
        # IP正则表达式
        self.ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        
        # IP:端口格式的正则表达式
        self.ip_port_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d{1,5}\b'
        
        self.unique_ips = set()
        self.unique_ip_ports = set()
    
    def is_valid_ip(self, ip: str) -> bool:
        """验证IP地址是否有效且为公网IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            # 排除私有IP、回环IP、保留IP等
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast:
                return False
            # 排除一些特殊范围
            if ip.startswith(('0.', '10.', '127.', '169.254.', '172.', '192.168.', '224.', '240.', '255.')):
                return False
            return True
        except ValueError:
            return False
    
    def extract_ips_from_html(self, html_content: str, url: str) -> Set[str]:
        """从HTML内容中提取IP地址"""
        ips = set()
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # 方法1: 查找所有文本内容中的IP
            text_content = soup.get_text()
            ip_matches = re.findall(self.ip_pattern, text_content)
            
            # 方法2: 特别处理表格数据
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows:
                    cells = row.find_all(['td', 'th'])
                    for cell in cells:
                        cell_text = cell.get_text(strip=True)
                        cell_ips = re.findall(self.ip_pattern, cell_text)
                        ip_matches.extend(cell_ips)
            
            # 方法3: 查找特定标签
            for tag in soup.find_all(['span', 'div', 'p', 'code', 'pre', 'li']):
                tag_text = tag.get_text(strip=True)
                tag_ips = re.findall(self.ip_pattern, tag_text)
                ip_matches.extend(tag_ips)
            
            # 方法4: 提取IP:端口格式
            ip_port_matches = re.findall(self.ip_port_pattern, text_content)
            for ip_port in ip_port_matches:
                ip = ip_port.split(':')[0]
                if self.is_valid_ip(ip):
                    self.unique_ip_ports.add(ip_port)
            
            # 验证并添加有效的IP
            for ip in ip_matches:
                if self.is_valid_ip(ip):
                    ips.add(ip)
            
            print(f'✓ {url} - 找到 {len(ips)} 个有效IP')
            
        except Exception as e:
            print(f'✗ 解析 {url} 的HTML内容失败: {e}')
        
        return ips
    
    def fetch_url(self, url: str, retry: int = 3) -> str:
        """获取URL内容，支持重试"""
        for attempt in range(retry):
            try:
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    timeout=10,
                    verify=False  # 如果遇到SSL证书问题
                )
                
                if response.status_code == 200:
                    return response.text
                else:
                    print(f'⚠ {url} 返回状态码: {response.status_code}')
                    
            except requests.exceptions.Timeout:
                print(f'⏱ {url} 请求超时 (尝试 {attempt + 1}/{retry})')
            except requests.exceptions.ConnectionError:
                print(f'⚠ {url} 连接失败 (尝试 {attempt + 1}/{retry})')
            except requests.exceptions.RequestException as e:
                print(f'✗ {url} 请求失败: {e}')
                break
            
            if attempt < retry - 1:
                time.sleep(2)  # 重试前等待
        
        return None
    
    def crawl_single_url(self, url: str) -> Set[str]:
        """爬取单个URL"""
        print(f'🔍 正在爬取: {url}')
        html_content = self.fetch_url(url)
        
        if html_content:
            return self.extract_ips_from_html(html_content, url)
        return set()
    
    def crawl_all_urls(self, use_threading: bool = True, max_workers: int = 5):
        """爬取所有URL"""
        print('=' * 60)
        print('开始爬取IP地址...')
        print('=' * 60)
        
        if use_threading:
            # 使用多线程并发爬取
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_url = {executor.submit(self.crawl_single_url, url): url for url in self.urls}
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        ips = future.result()
                        self.unique_ips.update(ips)
                    except Exception as e:
                        print(f'✗ 处理 {url} 时出错: {e}')
        else:
            # 串行爬取
            for url in self.urls:
                ips = self.crawl_single_url(url)
                self.unique_ips.update(ips)
                time.sleep(1)  # 避免请求过快
    
    def sort_ips(self, ips: Set[str]) -> List[str]:
        """按IP地址的数字顺序排序"""
        return sorted(ips, key=lambda ip: [int(part) for part in ip.split('.')])
    
    def save_to_file(self, filename: str = 'ip.txt'):
        """保存IP地址到文件"""
        # 删除旧文件
        if os.path.exists(filename):
            os.remove(filename)
        
        if self.unique_ips:
            sorted_ips = self.sort_ips(self.unique_ips)
            
            with open(filename, 'w', encoding='utf-8') as file:
                for ip in sorted_ips:
                    file.write(ip + '\n')
            
            print('=' * 60)
            print(f'✓ 已保存 {len(sorted_ips)} 个唯一IP地址到 {filename}')
            print('=' * 60)
            
            # 显示前10个IP作为示例
            print('\n前10个IP地址:')
            for ip in sorted_ips[:10]:
                print(f'  • {ip}')
            if len(sorted_ips) > 10:
                print(f'  ... 还有 {len(sorted_ips) - 10} 个')
        else:
            print('✗ 未找到有效的IP地址')
        
        # 如果有IP:端口格式的数据，也保存
        if self.unique_ip_ports:
            port_filename = 'ip_with_port.txt'
            if os.path.exists(port_filename):
                os.remove(port_filename)
            
            sorted_ip_ports = sorted(self.unique_ip_ports)
            with open(port_filename, 'w', encoding='utf-8') as file:
                for ip_port in sorted_ip_ports:
                    file.write(ip_port + '\n')
            
            print(f'\n✓ 已保存 {len(sorted_ip_ports)} 个IP:端口到 {port_filename}')
    
    def add_custom_url(self, url: str):
        """添加自定义URL"""
        if url not in self.urls:
            self.urls.append(url)
            print(f'✓ 已添加自定义URL: {url}')
    
    def run(self):
        """运行爬虫"""
        start_time = time.time()
        
        # 禁用SSL警告
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.crawl_all_urls(use_threading=True, max_workers=5)
        self.save_to_file()
        
        elapsed_time = time.time() - start_time
        print(f'\n⏱ 总耗时: {elapsed_time:.2f} 秒')


def main():
    crawler = IPCrawler()
    
    # 可以添加更多自定义URL
    # crawler.add_custom_url('https://example.com/ips')
    
    crawler.run()


if __name__ == '__main__':
    main()
