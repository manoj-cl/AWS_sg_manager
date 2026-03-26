# Example usage of the variable name 'existing_rules' in the function 'rule_exists()'. 
# The existing rules would likely be retrieved from a database or an API call to a cloud provider's security group service.
```
existing_rules =
    [
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
```