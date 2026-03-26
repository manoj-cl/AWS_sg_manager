from ipaddress import ip_network

def is_cidr_within_range(requested_cidr: str, existing_cidr: str) -> bool:
    """
    Check if the requested CIDR is within the existing CIDR range.

    :param requested_cidr: The CIDR notation of the requested IP range (e.g., '10.30.2.3/32')
    :param existing_cidr: The CIDR notation of the existing IP range (e.g., '10.0.0.0/8')
    :return: True if the requested CIDR is within the existing CIDR range, False otherwise
    """
    # Convert CIDR notation to IP network objects
    requested = ip_network(requested_cidr, strict=False)    # strict=False allows for host addresses to be treated as /32 networks
    existing = ip_network(existing_cidr, strict=False)      # strict=False allows for host addresses to be treated as /32 networks
    return requested.subnet_of(existing)

def rule_exists(existing_rules: list, requested_cidr: str, requested_port: int) -> bool:
    """
    Check if a rule with the requested CIDR and port already exists in the list of existing rules.

    :param existing_rules: A list of existing rules, where each rule is a dictionary with 'Ip' and 'port' keys. 'Ip' is a list of CIDR notations, and 'port' is a tuple (from_port, to_port).
    :param requested_cidr: The CIDR notation of the requested IP range (e.g., '10.30.2.3/32')
    :param requested_port: The port number of the requested rule
    :return: True if the rule exists, False otherwise
    """

    for rule in existing_rules:
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')

        # Check if the requested port falls within the existing rule's port range
        if from_port <= requested_port <= to_port:
            for cidr in rule.get('IpRanges', []):  # IpRanges is a list of dictionaries, each containing a 'CidrIp' key
                existing_cidr = cidr.get('CidrIp')
                
                # Check if the requested CIDR is within the existing CIDR range
                if is_cidr_within_range(requested_cidr, existing_cidr):
                    return True
    return False

def normalize_to_cidr(ip: str) -> str:
    """
    Normalize an IP address to CIDR notation. If the input is a single IP address without a subnet mask, it will be converted to a /32 CIDR.
    
    :param ip: The IP address or CIDR notation to normalize.
    :return: A string representing the normalized CIDR notation.
    """

    if '/' not in ip:
        return f"{ip}/32"
    return ip 

def evaluate_rules(requested_ips: list, requested_ports: list, existing_rules: list) -> tuple:
    """
    Evaluate the requested IPs and ports against the existing rules to determine which rules need to be added and which are skipped.
    """
    rules_to_add = []
    rules_skipped = []

    for ip in requested_ips:
        cidr = normalize_to_cidr(ip)

        for port in requested_ports:
            if rule_exists(existing_rules, cidr, port):
                rules_skipped.append((cidr, port))
            else:
                rules_to_add.append((cidr, port))
    return rules_to_add, rules_skipped

def prepare_rules_for_aws(rules_to_add: list) -> list:
    """
    Convert the list of rules to add into the format required by AWS Security Group rules.

    :param rules_to_add: A list of tuples, where each tuple contains a CIDR and a port (e.g., [('10.0.0.0/8', 8080)])
    :return: A list of dictionaries formatted for AWS Security Group rules.
    """

    aws_rules = []

    for cidr, port in rules_to_add:
        rule = {
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [
                {"CidrIp": cidr}
            ]
        }
        aws_rules.append(rule)
    return aws_rules















# TESTING  

# existing_rules = [
#     {
#         "FromPort": 8000,
#         "ToPort": 8010,
#         "IpRanges": [
#             {"CidrIp": "10.0.0.0/8"}
#         ]
#     }
# ]

existing_rules = [
        {
            "IpProtocol": "tcp",
            "FromPort": 8000,
            "ToPort": 8010,
            "IpRanges": [
            {"CidrIp": "10.0.0.0/8"},
            {"CidrIp": "172.16.0.0/12"}
            ]
        },
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [
            {"CidrIp": "203.0.113.10/32"}
            ]
        }
    ]


requested_ips = ["10.0.0.3", "11.1.2.3/26", "9.8.7.4", "172.16.0.0/12"]
requested_ports = [8003, 8005, 22, 8080]


rules_to_add, rules_skipped = evaluate_rules(
    requested_ips,
    requested_ports,
    existing_rules
)

aws_ready = prepare_rules_for_aws(rules_to_add)

print("Rules to Add:", rules_to_add)
print("Rules Skipped:", rules_skipped)
print("AWS Formatted:", aws_ready)












# print(is_cidr_within_range('10.30.2.3/24', '10.0.0.0/8'))
