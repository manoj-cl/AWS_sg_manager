from ipaddress import ip_network
from collections import defaultdict


# ============================================================
# 1. CIDR containment check
# ============================================================
def is_cidr_within_range(requested_cidr: str, existing_cidr: str) -> bool:
    req = ip_network(requested_cidr, strict=False)
    ex = ip_network(existing_cidr, strict=False)
    return req.subnet_of(ex)


# ============================================================
# 2. Port range normalization
# ============================================================
def normalize_port(port):
    """
    Convert port to a (start, end) tuple.
    Supports:
        - single int → (p, p)
        - tuple/list → (start, end)
    """
    if isinstance(port, int):
        return (port, port)

    if isinstance(port, (tuple, list)) and len(port) == 2:
        return (int(port[0]), int(port[1]))

    raise ValueError(f"Invalid port format: {port}")


# ============================================================
# 3. Check if a requested port range is covered by existing rule
# ============================================================
def is_port_range_covered(req_start, req_end, ex_start, ex_end):
    """
    True if existing rule fully covers the requested range.
    """
    return req_start >= ex_start and req_end <= ex_end


# ============================================================
# 4. Rule exists check — now supports port ranges
# ============================================================
def rule_exists(existing_rules: list, requested_cidr: str, req_start: int, req_end: int) -> bool:

    for rule in existing_rules:
        ex_protocol = rule.get("IpProtocol", "tcp")  # Protocol ignored for now since user didn't request protocol logic

        # Existing port range
        ex_start = rule.get("FromPort")
        ex_end = rule.get("ToPort")

        # If port range not defined, skip
        if ex_start is None or ex_end is None:
            continue

        # Port coverage
        if not is_port_range_covered(req_start, req_end, ex_start, ex_end):
            continue

        # CIDR coverage check
        for cidr in rule.get("IpRanges", []):
            existing_cidr = cidr.get("CidrIp")
            if is_cidr_within_range(requested_cidr, existing_cidr):
                return True

    return False


# ============================================================
# 5. Normalize IP to CIDR
# ============================================================
def normalize_to_cidr(ip: str) -> str:
    if "/" not in ip:
        return f"{ip}/32"
    return ip


# ============================================================
# 6. Merge port ranges for optimization
# ============================================================
def merge_port_ranges(ranges):
    """
    Merge overlapping or adjacent port ranges.
    Input: [(1000,1003), (1004,1005), (2000,2005)]
    Output: [(1000,1005), (2000,2005)]
    """
    if not ranges:
        return []

    ranges = sorted(ranges, key=lambda r: r[0])
    merged = [ranges[0]]

    for cur_start, cur_end in ranges[1:]:
        last_start, last_end = merged[-1]

        if cur_start <= last_end + 1:  # overlapping or adjacent
            merged[-1] = (last_start, max(last_end, cur_end))
        else:
            merged.append((cur_start, cur_end))

    return merged


# ============================================================
# 7. Evaluate requested rules
# ============================================================
def evaluate_rules(requested_ips, requested_ports, existing_rules):
    rules_to_add = []
    rules_skipped = []

    for ip in requested_ips:
        cidr = normalize_to_cidr(ip)

        for port in requested_ports:
            req_start, req_end = normalize_port(port)

            if rule_exists(existing_rules, cidr, req_start, req_end):
                rules_skipped.append((cidr, (req_start, req_end)))
            else:
                rules_to_add.append((cidr, (req_start, req_end)))

    # Merge port ranges by CIDR
    return merge_by_cidr(rules_to_add), rules_skipped


# ============================================================
# 8. Group and merge ports by CIDR
# ============================================================
def merge_by_cidr(rules_to_add):
    cidr_to_ports = defaultdict(list)

    for cidr, (start, end) in rules_to_add:
        cidr_to_ports[cidr].append((start, end))

    merged_output = []

    for cidr, port_ranges in cidr_to_ports.items():
        merged_ranges = merge_port_ranges(port_ranges)
        for r in merged_ranges:
            merged_output.append((cidr, r))

    return merged_output


# ============================================================
# 9. Prepare final AWS rules (Already optimized)
# ============================================================
def prepare_rules_for_aws(merged_rules):
    aws_rules = []

    for cidr, (start, end) in merged_rules:
        rule = {
            "IpProtocol": "tcp",   # user did not request udp support here
            "FromPort": start,
            "ToPort": end,
            "IpRanges": [{"CidrIp": cidr}]
        }
        aws_rules.append(rule)

    return aws_rules

# ============================================================
# 10. Dynamic user input collection
# ============================================================
def get_dynamic_user_input():
    """
    INPUT FORMAT #1 (multiple IPs in one line):
        Enter IPs: 10.0.0.3, 11.1.2.3/26

    INPUT FORMAT #2 (one IP at a time):
        Enter IP: 10.0.0.3
        Enter ports: ...

    RETURNS:
      {
        "10.0.0.3": [(8003,8003), (8080,8085)],
        "11.1.2.3/26": [(443,443), (1000,1002)]
      }
    """

    result = {}

    print("\nEnter multiple IPs or CIDRs (comma-separated).")
    print("Example: 10.0.0.3, 11.1.2.3/26, 192.168.1.0/24")
    
    ips_input = input("Enter IPs: ").strip()

    # Split by comma and clean whitespace
    ips = [ip.strip() for ip in ips_input.split(",")]

    for ip in ips:
        ports_str = input(f"Enter ports for {ip} (comma separated, ranges allowed): ").strip()
        port_ranges = []

        for item in ports_str.split(","):
            item = item.strip()

            if "-" in item:
                a, b = item.split("-")
                port_ranges.append((int(a), int(b)))
            else:
                p = int(item)
                port_ranges.append((p, p))

        result[ip] = port_ranges
        print("---")

    return result

# ============================================================
# =============== EXAMPLE TEST ================================
# ============================================================

if __name__ == "__main__":
    
    # 1. Dynamically take input from user
    user_input = get_dynamic_user_input()
    
    # user_input example:
    # {
    #   "10.0.0.3": [(8003,8003), (8004,8004), (8080,8085)],
    #   "11.1.2.3/26": [(443,443), (1000,1002)]
    # }

    # 2. Convert user input to two separate lists
    requested_ips = list(user_input.keys())
    requested_ports = []   # combined ports across all IPs
    
    # We evaluate IP-by-IP because ports differ per IP
    all_results = []

    # Simulated existing SG rules
    existing_rules = [
        {
            "IpProtocol": "tcp",
            "FromPort": 8000,
            "ToPort": 8010,
            "IpRanges": [
                {"CidrIp": "10.0.0.0/8"},
                {"CidrIp": "172.16.0.0/12"}
            ]
        }
    ]

    # 3. Per-IP evaluation
    for ip, ports in user_input.items():

        # Convert list of ranges into list of original port formats
        requested_ports_for_ip = ports
        
        merged, skipped = evaluate_rules([ip], requested_ports_for_ip, existing_rules)

        aws_ready = prepare_rules_for_aws(merged)

        all_results.append({
            "ip": ip,
            "merged_to_add": merged,
            "skipped": skipped,
            "aws_output": aws_ready
        })

    # 4. Output
    for r in all_results:
        print("\n=======================================")
        print(f"Results for IP: {r['ip']}")
        print("Rules to Add (merged):", r["merged_to_add"])
        print("Rules Skipped:", r["skipped"])
        print("AWS Ready:", r["aws_output"])
        print("=======================================")