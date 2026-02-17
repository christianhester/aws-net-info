# aws-net-info

A fast, universal AWS networking troubleshooting tool for network engineers. Query any EC2 instance, ENI, or IP address and instantly get all the relevant networking information you need — no more digging through the AWS console or parsing messy JSON.

## Why I Built This

As a network admin working across hundreds of AWS accounts daily, I found myself running the same AWS CLI commands over and over just to get basic networking info. This tool consolidates everything into a single command.

## What It Shows

For any given resource, the tool outputs:

- **Network Interface Info** — ENI ID, private IP, public IP, subnet (with CIDR), VPC (with all CIDRs)
- **VPC DNS Settings** — DNS Hostnames and DNS Support enabled/disabled (critical for Private Hosted Zone compatibility)
- **Security Groups** — All inbound and outbound rules, including multiple CIDRs, referenced security groups, IPv6 ranges, and prefix lists
- **Route Table** — All routes including IPv4, IPv6, and prefix list destinations
- **Network ACLs** — All inbound and outbound rules, sorted by rule number, including IPv6

## Requirements

- **AWS CLI** (v2 recommended)
- **jq** (`sudo apt install jq` or `brew install jq`)
- **Bash**
- AWS credentials configured (IAM user, instance profile, or SSO)

## Installation

```bash
# Clone the repo
git clone https://github.com/YOURUSERNAME/aws-net-info.git
cd aws-net-info

# Make the script executable
chmod +x aws-net-info.sh

# Optional: add an alias to your ~/.bashrc or ~/.zshrc
alias awsnet='/path/to/aws-net-info.sh'
source ~/.bashrc
```

## Usage

```bash
./aws-net-info.sh <instance-id|eni-id|ip-address> [aws-profile]
```

### Single Queries

```bash
# By instance ID
./aws-net-info.sh i-1234567890abcdef0

# By ENI ID
./aws-net-info.sh eni-1234567890abcdef0

# By private IP
./aws-net-info.sh 172.31.x.x

# By public IP
./aws-net-info.sh x.x.x.x

# With a specific AWS profile
./aws-net-info.sh i-1234567890abcdef0 prod-account
```

### Multi-Query (comma-separated, no spaces)

```bash
# Mix and match input types
./aws-net-info.sh 172.31.x.x,i-1234567890abcdef0,eni-1234567890abcdef0

# With a profile
./aws-net-info.sh i-1111111111,i-2222222222,i-3333333333 prod-account
```

### Help

```bash
./aws-net-info.sh --help
```

## Example Output

```
==========================================
INPUT: 172.31.x.x (ip)
==========================================

NETWORK INTERFACE INFO:
  ENI ID:     eni-1234567890abcdef0
  ENI Status: in-use
  Private IP: 172.31.x.x
  Public IP:  x.x.x.x
  Subnet:     subnet-1234567890abcdef0 (172.31.x.x/20)
  VPC:        vpc-1234567890abcdef0 (172.31.x.x/16)
    DNS Hostnames: true | DNS Support: true

ATTACHED INSTANCE INFO:
  Instance:   i-1234567890abcdef0
  Name:       my-instance
  State:      running

==========================================
SECURITY GROUPS
==========================================

Security Group: default (sg-1234567890abcdef0)
------------------------------------------
INBOUND RULES:
  ALL Traffic from SG:sg-1234567890abcdef0
  tcp Port 22 from 10.0.0.0/8
  tcp Port 443 from 0.0.0.0/0
  tcp Port 443 from ::/0

OUTBOUND RULES:
  ALL Traffic to 0.0.0.0/0

==========================================
ROUTE TABLE
==========================================

Route Table: rtb-1234567890abcdef0 (VPC Main)
------------------------------------------
ROUTES:
  172.31.x.x/16 -> local [active]
  0.0.0.0/0 -> igw-1234567890abcdef0 [active]
  pl-1234567890 -> vpce-1234567890abcdef0 [active]

==========================================
NETWORK ACLs
==========================================

Network ACL: acl-1234567890abcdef0
------------------------------------------
INBOUND RULES:
  Rule #100 [allow] ALL from 0.0.0.0/0
  Rule #32767 [deny] ALL from 0.0.0.0/0

OUTBOUND RULES:
  Rule #100 [allow] ALL to 0.0.0.0/0
  Rule #32767 [deny] ALL to 0.0.0.0/0

==========================================
```

## Multi-Query Output

```
========================================================================
MULTIPLE QUERY MODE: 3 resources
========================================================================

========================================================================
QUERY 1 of 3: 172.31.x.x
========================================================================
[full details...]

========================================================================
QUERY 2 of 3: i-1234567890abcdef0
========================================================================
[full details...]

========================================================================
SUMMARY
========================================================================
Total queries: 3
  Found:   3
  Failed:  0
========================================================================
```

## AWS Permissions Required

The IAM user or role running this script needs the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRouteTables",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpcAttribute"
      ],
      "Resource": "*"
    }
  ]
}
```

## Using With AWS SSO

If your organization uses AWS Identity Center (SSO):

```bash
# Configure a profile
aws configure sso

# Login
aws sso login --profile prod-account

# Use the script with your profile
./aws-net-info.sh 172.31.x.x prod-account
```

## Tips

- **No spaces** in multi-query: use `ip1,ip2,ip3` not `ip1, ip2, ip3`
- Works with **public or private IPs** — the script tries both automatically
- If an ENI is **not attached** to an instance, instance fields are omitted
- VPCs with **multiple CIDRs** show all CIDRs comma-separated
- Security group rules with **multiple sources** each get their own line
- **IPv6** is fully supported in security groups, route tables, and NACLs

## Compatible Environments

- Linux terminals
- macOS Terminal
- Git Bash (Windows)
- AWS CloudShell
- EC2 Instance Connect
- Systems Manager Session Manager
- SSH / PuTTY

## License

MIT
