import re
from collections import defaultdict
from datetime import datetime

class SmartDNSLogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.query_results = defaultdict(list)  # 成功解析结果
        self.query_counts = defaultdict(int)   # 查询次数
        self.dns_servers = defaultdict(set)    # DNS服务器
        self.failed_queries = defaultdict(list)  # 失败的查询记录
        self._parse_log()

    def _parse_log(self):
        # 正则表达式模式
        query_pattern = r'request: ([\w\.-]+), qtype: (\d+), id: (\d+), group: (\w+)'
        result_pattern = r'result: ([\w\.-]+), qtype: (\d+), rtt: ([\d.]+) ms, ([a-fA-F0-9:\.]+)'
        server_pattern = r'query result from server ([\d:\.]+|\[[\w:]+\]):\d+, type: \d+, domain: ([\w\.-]+) qtype: (\d+)'
        failure_pattern = r'request: ([\w\.-]+), qtype: (\d+), id: (\d+).*?(timeout|no answer|refused|error)'

        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    # 匹配查询请求
                    query_match = re.search(query_pattern, line)
                    if query_match:
                        domain, qtype, query_id, group = query_match.groups()
                        domain = domain.lower()
                        print(f"Found query: {domain} (ID: {query_id})")  # 调试输出
                        self.query_counts[domain] += 1

                    # 匹配解析结果（成功）
                    result_match = re.search(result_pattern, line)
                    if result_match:
                        domain, qtype, rtt, ip = result_match.groups()
                        domain = domain.lower()
                        print(f"Found result: {domain}")  # 调试输出
                        self.query_results[domain].append({
                            'qtype': int(qtype),
                            'ip': ip,
                            'rtt': float(rtt)
                        })

                    # 匹配使用的DNS服务器
                    server_match = re.search(server_pattern, line)
                    if server_match:
                        server, domain, qtype = server_match.groups()
                        domain = domain.lower()
                        print(f"Found server for: {domain}")  # 调试输出
                        self.dns_servers[domain].add(server)

                    # 匹配失败情况
                    failure_match = re.search(failure_pattern, line)
                    if failure_match:
                        domain, qtype, query_id, reason = failure_match.groups()
                        domain = domain.lower()
                        print(f"Found failed query: {domain} (Reason: {reason})")  # 调试输出
                        self.failed_queries[domain].append({
                            'qtype': int(qtype),
                            'reason': reason,
                            'query_id': query_id
                        })

        except FileNotFoundError:
            print(f"错误：找不到文件 {self.log_file}")
        except Exception as e:
            print(f"解析日志时出错：{e}")

    def analyze_domain(self, domain):
        """分析特定域名的DNS解析情况，包括IPv4和IPv6所有记录及总数"""
        domain = domain.lower()  # 输入域名转换为小写
        if domain not in self.query_counts and domain not in self.failed_queries:
            return f"未找到域名 {domain} 的任何记录"

        # 1. DNS服务器信息
        servers = self.dns_servers.get(domain, set())
        server_count = len(servers)

        # 2. 查询次数
        query_count = self.query_counts.get(domain, 0)

        # 3. 成功解析的IP地址
        ips_by_type = defaultdict(set)  # 使用set去重
        results = self.query_results.get(domain, [])
        for result in results:
            ips_by_type[result['qtype']].add(result['ip'])  # 去重存储

        # 计算IPv4和IPv6总数
        ipv4_ips = ips_by_type.get(1, set())  # qtype 1 为 A 记录 (IPv4)
        ipv6_ips = ips_by_type.get(28, set())  # qtype 28 为 AAAA 记录 (IPv6)
        total_unique_ips = len(ipv4_ips) + len(ipv6_ips)  # 总唯一IP数

        # 4. 失败记录
        failed = self.failed_queries.get(domain, [])

        # 输出结果
        output = [
            f"\n域名: {domain} 的解析结果:",
            f"1. DNS服务器信息:",
            f"   - 通过 {server_count} 个DNS服务器查询: {', '.join(servers) if servers else '无'}",
            f"2. 总查询次数: {query_count} 次",
            f"3. 成功解析的IP地址 (共 {total_unique_ips} 个唯一IP):"
        ]

        # IPv4记录
        output.append("   - IPv4 (A 记录):")
        if ipv4_ips:
            output.append(f"     - 共 {len(ipv4_ips)} 个: {', '.join(ipv4_ips)}")
        else:
            output.append("     - 无")

        # IPv6记录
        output.append("   - IPv6 (AAAA 记录):")
        if ipv6_ips:
            output.append(f"     - 共 {len(ipv6_ips)} 个: {', '.join(ipv6_ips)}")
        else:
            output.append("     - 无")

        # 成功解析详情
        output.append("4. 成功解析详细记录:")
        if results:
            for result in results:
                qtype_name = "A" if result['qtype'] == 1 else "AAAA" if result['qtype'] == 28 else f"Type {result['qtype']}"
                output.append(f"   - {qtype_name}: {result['ip']} (RTT: {result['rtt']}ms)")
        else:
            output.append("   - 无")

        # 失败记录
        output.append("5. 查询失败记录:")
        if failed:
            for fail in failed:
                qtype_name = "A" if fail['qtype'] == 1 else "AAAA" if fail['qtype'] == 28 else f"Type {fail['qtype']}"
                output.append(f"   - {qtype_name} 查询失败 (ID: {fail['query_id']}, 原因: {fail['reason']})")
        else:
            output.append("   - 无")

        return "\n".join(output)

def main():
    # 提示用户输入日志文件路径
    while True:
        log_file = input("请输入SmartDNS日志文件路径: ").strip()
        try:
            # 尝试打开文件以验证路径有效性
            with open(log_file, 'r') as f:
                pass
            break
        except FileNotFoundError:
            print(f"错误：文件 {log_file} 不存在，请重新输入。")
        except Exception as e:
            print(f"错误：无法打开文件 {log_file} ({e})，请重新输入。")

    # 初始化分析器
    analyzer = SmartDNSLogAnalyzer(log_file)
    
    # 进入域名查询循环
    while True:
        domain = input("\n请输入要查询的域名 (输入 'quit' 退出): ").strip()
        if domain.lower() == 'quit':
            break
        
        result = analyzer.analyze_domain(domain)
        print(result)

if __name__ == "__main__":
    # 创建一个示例日志文件（仅用于测试）
    sample_log = """
    request: beacons.gvt2.com, qtype: 1, id: 123, group: default
    result: beacons.gvt2.com, qtype: 1, rtt: 5.2 ms, 142.250.190.78
    query result from server 8.8.8.8:53, type: 1, domain: beacons.gvt2.com qtype: 1
    request: dns.google, qtype: 1, id: 124, group: default
    result: dns.google, qtype: 1, rtt: 4.7 ms, 8.8.8.8
    result: dns.google, qtype: 1, rtt: 4.9 ms, 8.8.4.4
    request: dns.google, qtype: 28, id: 125, group: default
    result: dns.google, qtype: 28, rtt: 5.0 ms, 2001:4860:4860::8888
    result: dns.google, qtype: 28, rtt: 5.1 ms, 2001:4860:4860::8844
    request: example.com, qtype: 1, id: 126, group: default, timeout
    """
    with open("smartdns_sample.log", "w") as f:
        f.write(sample_log)
    
    main()
