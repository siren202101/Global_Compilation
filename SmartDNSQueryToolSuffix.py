# SmartDNSAnalyzer - A tool to analyze SmartDNS logs and query DNS records

import re
from collections import defaultdict

class SmartDNSAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.query_results = defaultdict(list)  # 成功解析结果
        self.query_counts = defaultdict(int)   # 查询次数
        self.dns_servers = defaultdict(set)    # DNS服务器
        self.failed_queries = defaultdict(list)  # 失败的查询记录
        self.query_groups = defaultdict(set)   # 域名使用的分组
        self._parse_log()

    def _parse_log(self):
        # 正则表达式模式
        query_pattern = r'query ([\w\.-]+) from 127\.0\.0\.1, qtype: (\d+), id: (\d+), query-num: \d+'
        result_pattern = r'result: ([\w\.-]+), qtype: (\d+), rtt: ([\d.]+) ms, ([a-fA-F0-9:\.]+)'
        server_pattern = r'query result from server ([\d:\[\w\]]+):\d+, type: \d+, domain: ([\w\.-]+) qtype: (\d+)'
        failure_pattern = r'request: ([\w\.-]+), qtype: (\d+), id: (\d+).*?(timeout|no answer|refused|error)'
        group_pattern = r'result: ([\w\.-]+), client: 127\.0\.0\.1, qtype: (\d+), id: \d+, group: ([\w_]+), time: ([\d.]+)ms'

        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    # 匹配查询请求
                    query_match = re.search(query_pattern, line)
                    if query_match:
                        domain, qtype, query_id = query_match.groups()
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

                    # 匹配分组信息
                    group_match = re.search(group_pattern, line)
                    if group_match:
                        domain, qtype, group, time = group_match.groups()
                        domain = domain.lower()
                        print(f"Found group for {domain}: {group}")  # 调试输出
                        self.query_groups[domain].add(group)

        except FileNotFoundError:
            print(f"错误：找不到文件 {self.log_file}")
        except Exception as e:
            print(f"解析日志时出错：{e}")

    def analyze_domain(self, domain, is_suffix=False):
        """分析域名或域名后缀的DNS解析情况"""
        domain = domain.lower()

        if is_suffix:
            # 后缀查询：查找所有匹配后缀的域名
            matching_domains = [d for d in self.query_counts.keys() if d.endswith(domain)]
            if not matching_domains:
                return f"未找到包含后缀 {domain} 的任何域名记录"

            # 统计所有匹配域名的信息
            total_queries = 0
            all_servers = set()
            all_groups = set()
            ips_by_type = defaultdict(set)
            total_failed = 0

            output = [f"\n后缀 {domain} 的解析统计:"]
            output.append(f"1. 匹配的域名总数: {len(matching_domains)}")
            output.append(f"2. 匹配的域名列表: {', '.join(matching_domains)}")

            for d in matching_domains:
                total_queries += self.query_counts.get(d, 0)
                all_servers.update(self.dns_servers.get(d, set()))
                all_groups.update(self.query_groups.get(d, set()))
                results = self.query_results.get(d, [])
                for result in results:
                    ips_by_type[result['qtype']].add(result['ip'])
                total_failed += len(self.failed_queries.get(d, []))

            ipv4_ips = ips_by_type.get(1, set())
            ipv6_ips = ips_by_type.get(28, set())
            total_unique_ips = len(ipv4_ips) + len(ipv6_ips)

            output.extend([
                f"3. 总DNS服务器数: {len(all_servers)}",
                f"   - 服务器列表: {', '.join(all_servers) if all_servers else '无'}",
                f"4. 总查询次数: {total_queries} 次",
                f"5. 使用过的分组: {', '.join(all_groups) if all_groups else '无'}",
                f"6. 成功解析的IP地址 (共 {total_unique_ips} 个唯一IP):",
                "   - IPv4 (A 记录):",
                f"     - 共 {len(ipv4_ips)} 个: {', '.join(ipv4_ips) if ipv4_ips else '无'}",
                "   - IPv6 (AAAA 记录):",
                f"     - 共 {len(ipv6_ips)} 个: {', '.join(ipv6_ips) if ipv6_ips else '无'}",
                f"7. 总失败查询次数: {total_failed} 次"
            ])

            return "\n".join(output)

        else:
            # 完整域名查询
            if domain not in self.query_counts and domain not in self.failed_queries:
                return f"未找到域名 {domain} 的任何记录"

            servers = self.dns_servers.get(domain, set())
            server_count = len(servers)
            query_count = self.query_counts.get(domain, 0)
            ips_by_type = defaultdict(set)
            results = self.query_results.get(domain, [])
            for result in results:
                ips_by_type[result['qtype']].add(result['ip'])
            ipv4_ips = ips_by_type.get(1, set())
            ipv6_ips = ips_by_type.get(28, set())
            total_unique_ips = len(ipv4_ips) + len(ipv6_ips)
            failed = self.failed_queries.get(domain, [])
            groups = self.query_groups.get(domain, set())

            output = [
                f"\n域名: {domain} 的解析结果:",
                f"1. DNS服务器信息:",
                f"   - 通过 {server_count} 个DNS服务器查询: {', '.join(servers) if servers else '无'}",
                f"2. 总查询次数: {query_count} 次",
                f"3. 使用过的分组:",
                f"   - {', '.join(groups) if groups else '无'}",
                f"4. 成功解析的IP地址 (共 {total_unique_ips} 个唯一IP):"
            ]

            output.append("   - IPv4 (A 记录):")
            if ipv4_ips:
                output.append(f"     - 共 {len(ipv4_ips)} 个: {', '.join(ipv4_ips)}")
            else:
                output.append("     - 无")

            output.append("   - IPv6 (AAAA 记录):")
            if ipv6_ips:
                output.append(f"     - 共 {len(ipv6_ips)} 个: {', '.join(ipv6_ips)}")
            else:
                output.append("     - 无")

            output.append("5. 成功解析详细记录:")
            if results:
                for result in results:
                    qtype_name = "A" if result['qtype'] == 1 else "AAAA" if result['qtype'] == 28 else f"Type {result['qtype']}"
                    output.append(f"   - {qtype_name}: {result['ip']} (RTT: {result['rtt']}ms)")
            else:
                output.append("   - 无")

            output.append("6. 查询失败记录:")
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
            with open(log_file, 'r') as f:
                pass
            break
        except FileNotFoundError:
            print(f"错误：文件 {log_file} 不存在，请重新输入。")
        except Exception as e:
            print(f"错误：无法打开文件 {log_file} ({e})，请重新输入。")

    # 初始化分析器
    analyzer = SmartDNSAnalyzer(log_file)
    
    # 进入查询循环
    while True:
        query = input("\n请输入要查询的域名或后缀 (输入 'quit' 退出): ").strip()
        if query.lower() == 'quit':
            break
        
        # 判断是完整域名还是后缀（简单规则：后缀通常较短且不含多个点）
        is_suffix = '.' not in query or query.count('.') < 2
        result = analyzer.analyze_domain(query, is_suffix=is_suffix)
        print(result)

if __name__ == "__main__":
    # 测试用日志
    sample_log = """[2025-04-04 01:24:46,227][DEBUG][     dns_server.c:7228] query yt3.ggpht.com from 127.0.0.1, qtype: 65, id: 4974, query-num: 1
[2025-04-04 01:24:46,227][ INFO][     dns_server.c:2392] result: yt3.ggpht.com, client: 127.0.0.1, qtype: 65, id: 4974, group: cn_dns, time: 0ms
[2025-04-04 01:24:47,415][DEBUG][     dns_server.c:7228] query play.google.com from 127.0.0.1, qtype: 65, id: 44788, query-num: 1
[2025-04-04 01:24:47,415][ INFO][     dns_server.c:2392] result: play.google.com, client: 127.0.0.1, qtype: 65, id: 44788, group: cn_dns, time: 0ms
[2025-04-04 01:24:47,980][DEBUG][     dns_server.c:7228] query rr5---sn-o097znsd.googlevideo.com from 127.0.0.1, qtype: 65, id: 5674, query-num: 1
[2025-04-04 01:24:47,980][ INFO][     dns_server.c:2392] result: rr5---sn-o097znsd.googlevideo.com, client: 127.0.0.1, qtype: 65, id: 5674, group: cn_dns, time: 0ms
[2025-04-04 01:24:47,980][DEBUG][     dns_server.c:7228] query rr5---sn-o097znsd.googlevideo.com from 127.0.0.1, qtype: 1, id: 35240, query-num: 1
[2025-04-04 01:24:48,153][DEBUG][     dns_server.c:4654] query result from server 2606:4700:0000:0000:0000:0000:6810:f9f9:443, type: 3, domain: rr5---sn-o097znsd.googlevideo.com qtype: 1 rcode: 0, id: 35240
[2025-04-04 01:24:48,153][ INFO][     dns_server.c:2614] result: rr5---sn-o097znsd.googlevideo.com, qtype: 1, rtt: 0.1 ms, 172.217.134.138
[2025-04-04 01:24:48,153][ INFO][     dns_server.c:2392] result: rr5---sn-o097znsd.googlevideo.com, client: 127.0.0.1, qtype: 1, id: 35240, group: fq_dns, time: 173ms
[2025-04-04 01:24:47,981][DEBUG][     dns_server.c:7228] query rr5---sn-o097znsd.googlevideo.com from 127.0.0.1, qtype: 28, id: 4667, query-num: 3
[2025-04-04 01:24:48,157][ INFO][     dns_server.c:2618] result: rr5---sn-o097znsd.googlevideo.com, qtype: 28, rtt: 0.1 ms, 2607:f8b0:4005:0011:0000:0000:0000:000a
[2025-04-04 01:24:48,157][ INFO][     dns_server.c:4510] result: rr5---sn-o097znsd.googlevideo.com, client: 127.0.0.1, qtype: 28, id: 4667, group: fq_dns, time: 176ms"""
    with open("smartdns_sample.log", "w") as f:
        f.write(sample_log)
    
    main()
