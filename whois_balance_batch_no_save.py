import requests
import time
from collections import defaultdict
import tldextract
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import time
import sys
from tqdm import tqdm

# disable ssl警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# 设置每秒的请求次数上限
tps = 20

def get_domain_dict(domains):
    # 使用字典来存储每个顶级域名的域名列表
    domain_dict = defaultdict(list)
    for domain in domains:
        tld = tldextract.extract(domain).suffix
        # 将域名添加到对应的顶级域名列表中
        domain_dict[tld].append(domain)
    return domain_dict
        

def fetch_data(domain):
    api = f"http://localhost:4567/whois/{domain}"
    try:
        response = requests.get(url=api, verify=False, timeout=60)
        
        response.raise_for_status()  # 确保响应状态码是200
        
        result = response.json()
        code = result.get("code")
        
        # 检查响应状态码
        if code == 102:
            # 处理whois超时错误
            print(f"请求超时，服务暂时不可用{domain} {api}")
            return None

        if code == 0 or code == 101:
            data = result.get('data')
            return domain
        
        if code == 103:
            msg = result.get('msg')
            print(f"whois服务错误: {domain} {msg}")
            data = result.get('data')
            # save_to_mongodb(domain, data)
            return None
        
        if code == 104:
            msg = result.get('msg')
            print(f"其他错误: {domain} {msg} {api}")
            return None

    except Exception as e:
        print(f"请求WHOIS信息失败: {domain} {e}")

    

def process_domains_in_batches(domains):
    # 先查询mongodb，得到不在数据库中的域名
    # dms = look_in_mongodb(domains)
    dms = domains
    dm_num = len(dms)
    print(len(dms))
    print(dms[0:20])
    domain_dict = get_domain_dict(dms)
    results = []
    processed_num = 0
    # 创建一个线程池
    with ThreadPoolExecutor(max_workers=tps) as executor:
        while domain_dict:
            futures = []
            start_time = time.time()
            for tld in list(domain_dict.keys()):
                # 取出并删除该顶级域名列表的第一个域名
                domain = domain_dict[tld].pop(0)
                # 创建一个任务来发送请求
                future = executor.submit(fetch_data, domain)
                futures.append(future)
                processed_num += 1
                # 如果该顶级域名的列表为空，则删除该顶级域名
                if not domain_dict[tld]:
                    del domain_dict[tld]
            # 等待所有任务完成
            for future in concurrent.futures.as_completed(futures):
                response = future.result()
                # 这里你可以添加你自己的处理代码
                if response:
                    results.append(response)
            print(f"whois successed/processed/all {len(results)}/{processed_num}/{dm_num}")
            # 限制每秒的请求次数
            time.sleep(max(0, start_time + 1 - time.time()))
    return results

if __name__ == "__main__":
    file_path = sys.argv[1]
    with open(file_path, "r") as f:
        lines = f.readlines()
    domains = [str(line).strip().strip('"') for line in lines]
    # dms = look_in_mongodb(domains)
    # print(len(dms))
    results = process_domains_in_batches(domains)
    print(f"whois successed {len(results)}/{len(domains)}")
    
