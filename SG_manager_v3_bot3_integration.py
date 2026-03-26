import boto3
from ipaddress import ip_network
from collections import defaultdict


# ------------------------------------------------------------
# 1. CIDR containment check
# ------------------------------------------------------------
def is_cidr_within_range(requested_cidr: str, existing_cidr: str) -> bool:
    req = ip_network(requested_cidr, strict=False)
    ex = ip_network(existing_cidr, strict=False)
    return req.subnet_of(ex)

2
# ------------------------------------------------------------
# 2. Normalize port → always return (start, end)
# ------------------------------------------------------------
def normalize_port(port):
    if isinstance(port, int):
        return (port, port)
    if isinstance(port, (tuple, list)) and len(port) == 2:
        return (int(port[0]), int(port[1]))
    raise ValueError(f"Invalid port format: {port}")


# ------------------------------------------------------------
# 3. Check if port range is covered
# ------------------------------------------------------------
def is_port_range_covered(req_start, req_end, ex_start, ex_end):
    return req_start >= ex_start and req_end <= ex_end


# ------------------------------------------------------------
# 4. Check if requested CIDR+port_range exists in AWS rules
# ------------------------------------------------------------
def rule_exists(existing_rules, requested_cidr, req_start, req_end):
    for rule in existing_rules:
        ex_start = rule.get("FromPort")
        ex_end = rule.get("ToPort")

        if ex_start is None or ex_end is None:
            continue

        if not is_port_range_covered(req_start, req_end, ex_start, ex_end):
            continue

        for cidr in rule.get("IpRanges", []):
            ex_cidr = cidr.get("CidrIp")
            if is_cidr_within_range(requested_cidr, ex_cidr):
                return True
    return False


# ------------------------------------------------------------
# 5. Normalize IP to CIDR
# ------------------------------------------------------------
def normalize_to_cidr(ip):
    if "/" not in ip:
        return f"{ip}/32"
    return ip


# ------------------------------------------------------------
# 6. Merge overlapping/adjacent port ranges
# ------------------------------------------------------------
def merge_port_ranges(ranges):
    if not ranges:
        return []

    ranges = sorted(ranges, key=lambda x: x[0])
    merged = [ranges[0]]

    for start, end in ranges[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))

    return merged


# ------------------------------------------------------------
# 7. Group port ranges by CIDR
# ------------------------------------------------------------
def merge_by_cidr(rules_to_add):
    cidr_map = defaultdict(list)

    for cidr, (start, end) in rules_to_add:
        cidr_map[cidr].append((start, end))

    merged_output = []

    for cidr, ranges in cidr_map.items():
        merged = merge_port_ranges(ranges)
        for r in merged:
            merged_output.append((cidr, r))

    return merged_output


# ------------------------------------------------------------
# 8. Evaluate all rules
# ------------------------------------------------------------
def evaluate_rules(requested_ips, requested_ports_by_ip, existing_rules):
    final_to_add = []
    final_skipped = []

    for ip in requested_ips:
        cidr = normalize_to_cidr(ip)

        for (req_start, req_end) in requested_ports_by_ip[ip]:
            if rule_exists(existing_rules, cidr, req_start, req_end):
                final_skipped.append((cidr, (req_start, req_end)))
            else:
                final_to_add.append((cidr, (req_start, req_end)))

    merged = merge_by_cidr(final_to_add)
    return merged, final_skipped


# ------------------------------------------------------------
# 9. Convert to AWS IpPermissions format
# ------------------------------------------------------------
def prepare_rules_for_aws(merged_rules):
    aws_rules = []

    for cidr, (start, end) in merged_rules:
        aws_rules.append({
            "IpProtocol": "tcp",
            "FromPort": start,
            "ToPort": end,
            "IpRanges": [{"CidrIp": cidr}]
        })

    return aws_rules


# ------------------------------------------------------------
# 10. Fetch existing SG rules from AWS
# ------------------------------------------------------------
def get_existing_sg_rules(sg_id):
    ec2 = boto3.client("ec2")
    sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    return sg["IpPermissions"]


# ------------------------------------------------------------
# 11. Push rules to AWS SG
# ------------------------------------------------------------
def push_rules_to_aws(sg_id, aws_permissions):
    if not aws_permissions:
        print("\nNo new rules to add. Security Group is already up to date.")
        return

    ec2 = boto3.client("ec2")

    print("\nAdding rules to AWS...")
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=aws_permissions
    )
    print("Successfully added rules.")


# ------------------------------------------------------------
# 12. User input handler
# ------------------------------------------------------------
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


# ------------------------------------------------------------
# 13. (Optional) Get multiple SG IDs from user
# ------------------------------------------------------------
def get_sg_ids_from_user():
    """
    Accept multiple AWS Security Group IDs in one input.
    Example:
        sg-123abc, sg-456def
    Returns:
        ["sg-123abc", "sg-456def"]
    """
    s = input("Enter AWS Security Group IDs (comma-separated): ").strip()
    sg_ids = [x.strip() for x in s.split(",") if x.strip()]
    return sg_ids

# ------------------------------------------------------------
# MAIN PROGRAM
# ------------------------------------------------------------
if __name__ == "__main__":

    # 1. Get multiple SG IDs
    sg_ids = get_sg_ids_from_user()

    # 2. Get dynamic user input for all IPs and ports
    user_input = get_dynamic_user_input()

    # 3. Iterate each SG separately
    for sg_id in sg_ids:
        print("\n====================================================")
        print(f"Processing Security Group: {sg_id}")
        print("====================================================")

        # Fetch existing rules from AWS
        existing_rules = get_existing_sg_rules(sg_id)

        # Evaluate requested rules
        merged_to_add, skipped = evaluate_rules(
            requested_ips=list(user_input.keys()),
            requested_ports_by_ip=user_input,
            existing_rules=existing_rules
        )

        # Convert result to AWS format
        aws_rules = prepare_rules_for_aws(merged_to_add)

        # Display summary
        print("\nMerged Rules To Add:", merged_to_add)
        print("Rules Skipped:", skipped)
        print("AWS Payload:", aws_rules)

        # Push rules to AWS
        push_rules_to_aws(sg_id, aws_rules)

    print("\nAll SGs processed successfully.")