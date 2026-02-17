#!/bin/bash

# Quick AWS Network Info - Universal Edition
# Usage: ./aws-net-info.sh <instance-id|eni-id|ip-address> [profile]

show_help() {
    cat << EOF
AWS Network Info Tool - Universal Edition

USAGE:
    $0 <input> [profile] [options]

INPUTS:
    instance-id         EC2 instance ID (e.g., i-1234567890abcdef0)
    eni-id             Network interface ID (e.g., eni-1234567890abcdef0)
    ip-address         Public or private IP (e.g., 172.31.x.x or x.x.x.x)
    multiple-inputs    Comma-separated list (e.g., i-1234567890abcdef0,172.31.x.x,eni-1234567890abcdef0)

PROFILE:
    aws-profile        AWS CLI profile name (optional, uses default if not specified)

OPTIONS:
    -h, --help         Show this help message

EXAMPLES:
    # Query single instance
    $0 i-1234567890abcdef0

    # Query by IP address
    $0 172.31.x.x

    # Query with specific AWS profile
    $0 eni-1234567890abcdef0 prod-account

    # Query multiple resources at once
    $0 172.31.x.x,10.x.x.x,i-1234567890abcdef0

    # Query multiple with profile
    $0 i-1111111111abcdef0,172.31.x.x dev-account

OUTPUT:
    For each resource, displays:
    - Network interface information (ENI, IPs, subnet, VPC)
    - Attached instance information (if applicable)
    - Security group rules (inbound/outbound)
    - Route table routes
    - Network ACL rules (inbound/outbound)

EOF
    exit 0
}

# Check for help flag
if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    show_help
fi

if [ -z "$1" ]; then
    echo "Error: No input provided"
    echo ""
    echo "Usage: $0 <instance-id|eni-id|ip-address> [aws-profile]"
    echo "Run '$0 --help' for more information"
    exit 1
fi

INPUT=$1
PROFILE_ARG=""
if [ ! -z "$2" ] && [ "$2" != "-h" ] && [ "$2" != "--help" ]; then
    PROFILE_ARG="--profile $2"
fi

# Check if input contains commas (multiple queries)
if [[ $INPUT == *","* ]]; then
    # Split by comma into array
    IFS=',' read -ra INPUTS <<< "$INPUT"
    TOTAL=${#INPUTS[@]}
    FOUND=0
    FAILED=0
    
    echo "========================================================================"
    echo "MULTIPLE QUERY MODE: $TOTAL resources"
    echo "========================================================================"
    echo ""
    
    for i in "${!INPUTS[@]}"; do
        CURRENT_INPUT="${INPUTS[$i]}"
        # Trim whitespace
        CURRENT_INPUT=$(echo "$CURRENT_INPUT" | xargs)
        
        QUERY_NUM=$((i + 1))
        
        echo "========================================================================"
        echo "QUERY $QUERY_NUM of $TOTAL: $CURRENT_INPUT"
        echo "========================================================================"
        
        # Run the script once and capture output
        OUTPUT=$($0 "$CURRENT_INPUT" $2 2>&1)
        EXIT_CODE=$?
        
        if [ $EXIT_CODE -ne 0 ] || echo "$OUTPUT" | grep -q "ERROR:"; then
            FAILED=$((FAILED + 1))
            echo ""
            echo "✗ FAILED to retrieve information for: $CURRENT_INPUT"
            echo "$OUTPUT"
            echo ""
        else
            FOUND=$((FOUND + 1))
            echo "$OUTPUT"
        fi
        
        echo ""
        
    done
    
    echo "========================================================================"
    echo "SUMMARY"
    echo "========================================================================"
    echo "Total queries: $TOTAL"
    echo "  Found:   $FOUND"
    echo "  Failed:  $FAILED"
    echo "========================================================================"
    
    exit 0
fi

# Detect input type
if [[ $INPUT =~ ^i-[a-z0-9]+ ]]; then
    INPUT_TYPE="instance"
elif [[ $INPUT =~ ^eni-[a-z0-9]+ ]]; then
    INPUT_TYPE="eni"
elif [[ $INPUT =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    INPUT_TYPE="ip"
else
    echo "ERROR: Invalid input. Must be instance-id (i-xxx), eni-id (eni-xxx), or IP address"
    exit 1
fi

echo "=========================================="
echo "INPUT: $INPUT ($INPUT_TYPE)"
echo "=========================================="

# Variables to populate
INSTANCE_ID=""
ENI_ID=""
PRIVATE_IP=""
PUBLIC_IP=""
SUBNET_ID=""
VPC_ID=""
SG_IDS=""
INSTANCE_NAME=""
STATE=""
ENI_DESCRIPTION=""
ATTACHMENT_STATUS=""

# Query based on input type
if [ "$INPUT_TYPE" == "instance" ]; then
    INSTANCE_ID=$INPUT
    INSTANCE_DATA=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID $PROFILE_ARG 2>&1)
    
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to retrieve instance data"
        echo "$INSTANCE_DATA"
        exit 1
    fi
    
    PRIVATE_IP=$(echo "$INSTANCE_DATA" | jq -r '.Reservations[0].Instances[0].PrivateIpAddress // "N/A"')
    PUBLIC_IP=$(echo "$INSTANCE_DATA" | jq -r '.Reservations[0].Instances[0].PublicIpAddress // "N/A"')
    SUBNET_ID=$(echo "$INSTANCE_DATA" | jq -r '.Reservations[0].Instances[0].SubnetId // "N/A"')
    VPC_ID=$(echo "$INSTANCE_DATA" | jq -r '.Reservations[0].Instances[0].VpcId // "N/A"')
    SG_IDS=$(echo "$INSTANCE_DATA" | jq -r '.Reservations[0].Instances[0].SecurityGroups[].GroupId')
    INSTANCE_NAME=$(echo "$INSTANCE_DATA" | jq -r '.Reservations[0].Instances[0].Tags[]? | select(.Key=="Name") | .Value // "N/A"')
    STATE=$(echo "$INSTANCE_DATA" | jq -r '.Reservations[0].Instances[0].State.Name // "N/A"')
    ENI_ID=$(echo "$INSTANCE_DATA" | jq -r '.Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId // "N/A"')
    
elif [ "$INPUT_TYPE" == "eni" ]; then
    ENI_ID=$INPUT
    ENI_DATA=$(aws ec2 describe-network-interfaces --network-interface-ids $ENI_ID $PROFILE_ARG 2>&1)
    
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to retrieve ENI data"
        echo "$ENI_DATA"
        exit 1
    fi
    
    PRIVATE_IP=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].PrivateIpAddress // "N/A"')
    PUBLIC_IP=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].Association.PublicIp // "N/A"')
    SUBNET_ID=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].SubnetId // "N/A"')
    VPC_ID=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].VpcId // "N/A"')
    SG_IDS=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].Groups[].GroupId')
    ENI_DESCRIPTION=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].Description // "N/A"')
    ATTACHMENT_STATUS=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].Status // "N/A"')
    INSTANCE_ID=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].Attachment.InstanceId // "N/A"')
    
    # If attached to instance, get instance details
    if [ "$INSTANCE_ID" != "N/A" ] && [ "$INSTANCE_ID" != "null" ]; then
        INSTANCE_DATA=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID $PROFILE_ARG 2>&1)
        if [ $? -eq 0 ]; then
            INSTANCE_NAME=$(echo "$INSTANCE_DATA" | jq -r '.Reservations[0].Instances[0].Tags[]? | select(.Key=="Name") | .Value // "N/A"')
            STATE=$(echo "$INSTANCE_DATA" | jq -r '.Reservations[0].Instances[0].State.Name // "N/A"')
        fi
    fi
    
elif [ "$INPUT_TYPE" == "ip" ]; then
    IP_ADDRESS=$INPUT
    
    # Try to find ENI by private IP first
    ENI_DATA=$(aws ec2 describe-network-interfaces --filters "Name=addresses.private-ip-address,Values=$IP_ADDRESS" $PROFILE_ARG 2>&1)
    
    # If not found, try public IP
    if [ $? -ne 0 ] || [ "$(echo "$ENI_DATA" | jq '.NetworkInterfaces | length')" -eq 0 ]; then
        ENI_DATA=$(aws ec2 describe-network-interfaces --filters "Name=association.public-ip,Values=$IP_ADDRESS" $PROFILE_ARG 2>&1)
    fi
    
    if [ $? -ne 0 ] || [ "$(echo "$ENI_DATA" | jq '.NetworkInterfaces | length')" -eq 0 ]; then
        echo "ERROR: No ENI found with IP address $IP_ADDRESS"
        exit 1
    fi
    
    ENI_ID=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].NetworkInterfaceId // "N/A"')
    PRIVATE_IP=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].PrivateIpAddress // "N/A"')
    PUBLIC_IP=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].Association.PublicIp // "N/A"')
    SUBNET_ID=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].SubnetId // "N/A"')
    VPC_ID=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].VpcId // "N/A"')
    SG_IDS=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].Groups[].GroupId')
    ENI_DESCRIPTION=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].Description // "N/A"')
    ATTACHMENT_STATUS=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].Status // "N/A"')
    INSTANCE_ID=$(echo "$ENI_DATA" | jq -r '.NetworkInterfaces[0].Attachment.InstanceId // "N/A"')
    
    # If attached to instance, get instance details
    if [ "$INSTANCE_ID" != "N/A" ] && [ "$INSTANCE_ID" != "null" ]; then
        INSTANCE_DATA=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID $PROFILE_ARG 2>&1)
        if [ $? -eq 0 ]; then
            INSTANCE_NAME=$(echo "$INSTANCE_DATA" | jq -r '.Reservations[0].Instances[0].Tags[]? | select(.Key=="Name") | .Value // "N/A"')
            STATE=$(echo "$INSTANCE_DATA" | jq -r '.Reservations[0].Instances[0].State.Name // "N/A"')
        fi
    fi
fi

# Fetch VPC and Subnet CIDR blocks
SUBNET_CIDR="N/A"
VPC_CIDRS="N/A"
DNS_HOSTNAMES="N/A"
DNS_SUPPORT="N/A"

if [ "$SUBNET_ID" != "N/A" ] && [ "$SUBNET_ID" != "" ]; then
    SUBNET_DATA=$(aws ec2 describe-subnets --subnet-ids $SUBNET_ID $PROFILE_ARG 2>&1)
    if [ $? -eq 0 ]; then
        SUBNET_CIDR=$(echo "$SUBNET_DATA" | jq -r '.Subnets[0].CidrBlock // "N/A"')
    fi
fi

if [ "$VPC_ID" != "N/A" ] && [ "$VPC_ID" != "" ]; then
    VPC_DATA=$(aws ec2 describe-vpcs --vpc-ids $VPC_ID $PROFILE_ARG 2>&1)
    if [ $? -eq 0 ]; then
        # VPCs can have multiple CIDR blocks, get them all and join with comma
        VPC_CIDRS=$(echo "$VPC_DATA" | jq -r '[.Vpcs[0].CidrBlockAssociationSet[].CidrBlock] | join(",")')
        if [ -z "$VPC_CIDRS" ] || [ "$VPC_CIDRS" == "null" ] || [ "$VPC_CIDRS" == "" ]; then
            VPC_CIDRS="N/A"
        fi
    fi
    
    # Get DNS attributes - these require separate API calls
    DNS_HOSTNAME_DATA=$(aws ec2 describe-vpc-attribute --vpc-id $VPC_ID --attribute enableDnsHostnames $PROFILE_ARG 2>&1)
    if [ $? -eq 0 ]; then
        DNS_HOSTNAMES=$(echo "$DNS_HOSTNAME_DATA" | jq -r '.EnableDnsHostnames.Value // false')
    fi
    
    DNS_SUPPORT_DATA=$(aws ec2 describe-vpc-attribute --vpc-id $VPC_ID --attribute enableDnsSupport $PROFILE_ARG 2>&1)
    if [ $? -eq 0 ]; then
        DNS_SUPPORT=$(echo "$DNS_SUPPORT_DATA" | jq -r '.EnableDnsSupport.Value // false')
    fi
fi

# Display collected information
echo ""
echo "NETWORK INTERFACE INFO:"
if [ "$ENI_ID" != "N/A" ] && [ "$ENI_ID" != "" ]; then
    echo "  ENI ID:     $ENI_ID"
fi
if [ "$ENI_DESCRIPTION" != "N/A" ] && [ "$ENI_DESCRIPTION" != "" ] && [ "$ENI_DESCRIPTION" != "null" ]; then
    echo "  ENI Desc:   $ENI_DESCRIPTION"
fi
if [ "$ATTACHMENT_STATUS" != "N/A" ] && [ "$ATTACHMENT_STATUS" != "" ]; then
    echo "  ENI Status: $ATTACHMENT_STATUS"
fi
echo "  Private IP: $PRIVATE_IP"
echo "  Public IP:  $PUBLIC_IP"
echo "  Subnet:     $SUBNET_ID ($SUBNET_CIDR)"
echo "  VPC:        $VPC_ID ($VPC_CIDRS)"
if [ "$DNS_HOSTNAMES" != "N/A" ] && [ "$DNS_SUPPORT" != "N/A" ]; then
    echo "    DNS Hostnames: $DNS_HOSTNAMES | DNS Support: $DNS_SUPPORT"
fi

if [ "$INSTANCE_ID" != "N/A" ] && [ "$INSTANCE_ID" != "" ] && [ "$INSTANCE_ID" != "null" ]; then
    echo ""
    echo "ATTACHED INSTANCE INFO:"
    echo "  Instance:   $INSTANCE_ID"
    if [ "$INSTANCE_NAME" != "N/A" ] && [ "$INSTANCE_NAME" != "" ]; then
        echo "  Name:       $INSTANCE_NAME"
    fi
    if [ "$STATE" != "N/A" ] && [ "$STATE" != "" ]; then
        echo "  State:      $STATE"
    fi
fi
echo ""

# Security Groups
echo "=========================================="
echo "SECURITY GROUPS"
echo "=========================================="

if [ -z "$SG_IDS" ]; then
    echo "No security groups found"
else
    for SG_ID_RAW in $SG_IDS; do
        # Trim any whitespace or newlines
        SG_ID=$(echo "$SG_ID_RAW" | xargs)
        
        SG_DATA=$(aws ec2 describe-security-groups --group-ids "$SG_ID" $PROFILE_ARG 2>&1)
        
        if [ $? -ne 0 ]; then
            echo "ERROR: Failed to retrieve security group $SG_ID"
            echo "DEBUG: AWS returned: $SG_DATA"
            continue
        fi
        
        SG_NAME=$(echo "$SG_DATA" | jq -r '.SecurityGroups[0].GroupName')
        
        echo ""
        echo "Security Group: $SG_NAME ($SG_ID)"
        echo "------------------------------------------"
        
        # Inbound Rules
        echo "INBOUND RULES:"
        echo "$SG_DATA" | jq -r '.SecurityGroups[0].IpPermissions[] as $rule |
            # Build protocol/port string once
            (if $rule.IpProtocol == "-1" then "ALL Traffic"
             else $rule.IpProtocol + 
                  (if $rule.FromPort then " Port " + ($rule.FromPort|tostring) + 
                      (if $rule.FromPort != $rule.ToPort then "-" + ($rule.ToPort|tostring) else "" end)
                   else "" end)
             end) as $proto |
            
            # Output one line per IP range
            (if ($rule.IpRanges | length) > 0 then
                ($rule.IpRanges[] | "  " + $proto + " from " + .CidrIp)
             else empty end),
            
            # Output one line per Security Group
            (if ($rule.UserIdGroupPairs | length) > 0 then
                ($rule.UserIdGroupPairs[] | "  " + $proto + " from SG:" + .GroupId)
             else empty end),
            
            # Output one line per IPv6 range
            (if ($rule.Ipv6Ranges | length) > 0 then
                ($rule.Ipv6Ranges[] | "  " + $proto + " from " + .CidrIpv6)
             else empty end),
            
            # Output one line per Prefix List
            (if ($rule.PrefixListIds | length) > 0 then
                ($rule.PrefixListIds[] | "  " + $proto + " from PL:" + .PrefixListId)
             else empty end),
            
            # Safety check: if rule has no sources at all
            (if (($rule.IpRanges | length) == 0 and
                 ($rule.UserIdGroupPairs | length) == 0 and
                 ($rule.Ipv6Ranges | length) == 0 and
                 ($rule.PrefixListIds | length) == 0)
             then
                 "  " + $proto + " from <none>"
             else empty end)'
        
        # Outbound Rules
        echo ""
        echo "OUTBOUND RULES:"
        echo "$SG_DATA" | jq -r '.SecurityGroups[0].IpPermissionsEgress[] as $rule |
            # Build protocol/port string once
            (if $rule.IpProtocol == "-1" then "ALL Traffic"
             else $rule.IpProtocol + 
                  (if $rule.FromPort then " Port " + ($rule.FromPort|tostring) + 
                      (if $rule.FromPort != $rule.ToPort then "-" + ($rule.ToPort|tostring) else "" end)
                   else "" end)
             end) as $proto |
            
            # Output one line per IP range
            (if ($rule.IpRanges | length) > 0 then
                ($rule.IpRanges[] | "  " + $proto + " to " + .CidrIp)
             else empty end),
            
            # Output one line per Security Group
            (if ($rule.UserIdGroupPairs | length) > 0 then
                ($rule.UserIdGroupPairs[] | "  " + $proto + " to SG:" + .GroupId)
             else empty end),
            
            # Output one line per IPv6 range
            (if ($rule.Ipv6Ranges | length) > 0 then
                ($rule.Ipv6Ranges[] | "  " + $proto + " to " + .CidrIpv6)
             else empty end),
            
            # Output one line per Prefix List
            (if ($rule.PrefixListIds | length) > 0 then
                ($rule.PrefixListIds[] | "  " + $proto + " to PL:" + .PrefixListId)
             else empty end),
            
            # Safety check: if rule has no destinations at all
            (if (($rule.IpRanges | length) == 0 and
                 ($rule.UserIdGroupPairs | length) == 0 and
                 ($rule.Ipv6Ranges | length) == 0 and
                 ($rule.PrefixListIds | length) == 0)
             then
                 "  " + $proto + " to <none>"
             else empty end)'
    done
fi

# Route Table
echo ""
echo "=========================================="
echo "ROUTE TABLE"
echo "=========================================="

if [ "$SUBNET_ID" != "N/A" ] && [ "$SUBNET_ID" != "" ]; then
    # Get route table associated with subnet
    RT_DATA=$(aws ec2 describe-route-tables --filters "Name=association.subnet-id,Values=$SUBNET_ID" $PROFILE_ARG 2>&1)
    
    if [ $? -eq 0 ] && [ "$(echo "$RT_DATA" | jq '.RouteTables | length')" -gt 0 ]; then
        RT_ID=$(echo "$RT_DATA" | jq -r '.RouteTables[0].RouteTableId')
        echo ""
        echo "Route Table: $RT_ID"
        echo "------------------------------------------"
        echo "ROUTES:"
        echo "$RT_DATA" | jq -r '.RouteTables[0].Routes[] | 
            "  " + (if .DestinationCidrBlock then .DestinationCidrBlock 
             elif .DestinationIpv6CidrBlock then .DestinationIpv6CidrBlock
             elif .DestinationPrefixListId then .DestinationPrefixListId 
             else "unknown" end) + " -> " +
            (if .GatewayId then .GatewayId
             elif .NatGatewayId then .NatGatewayId
             elif .NetworkInterfaceId then .NetworkInterfaceId
             elif .VpcPeeringConnectionId then .VpcPeeringConnectionId
             elif .TransitGatewayId then .TransitGatewayId
             else "local" end) +
            " [" + .State + "]"'
    else
        # Try main route table for VPC
        if [ "$VPC_ID" != "N/A" ] && [ "$VPC_ID" != "" ]; then
            RT_DATA=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID" "Name=association.main,Values=true" $PROFILE_ARG 2>&1)
            
            if [ $? -eq 0 ]; then
                RT_ID=$(echo "$RT_DATA" | jq -r '.RouteTables[0].RouteTableId')
                echo ""
                echo "Route Table: $RT_ID (VPC Main)"
                echo "------------------------------------------"
                echo "ROUTES:"
                echo "$RT_DATA" | jq -r '.RouteTables[0].Routes[] | 
                    "  " + (if .DestinationCidrBlock then .DestinationCidrBlock 
                     elif .DestinationIpv6CidrBlock then .DestinationIpv6CidrBlock
                     elif .DestinationPrefixListId then .DestinationPrefixListId 
                     else "unknown" end) + " -> " +
                    (if .GatewayId then .GatewayId
                     elif .NatGatewayId then .NatGatewayId
                     elif .NetworkInterfaceId then .NetworkInterfaceId
                     elif .VpcPeeringConnectionId then .VpcPeeringConnectionId
                     elif .TransitGatewayId then .TransitGatewayId
                     else "local" end) +
                    " [" + .State + "]"'
            fi
        fi
    fi
else
    echo "No subnet found - cannot retrieve route table"
fi

# Network ACLs
echo ""
echo "=========================================="
echo "NETWORK ACLs"
echo "=========================================="

if [ "$SUBNET_ID" != "N/A" ] && [ "$SUBNET_ID" != "" ]; then
    NACL_DATA=$(aws ec2 describe-network-acls --filters "Name=association.subnet-id,Values=$SUBNET_ID" $PROFILE_ARG 2>&1)
    
    if [ $? -eq 0 ] && [ "$(echo "$NACL_DATA" | jq '.NetworkAcls | length')" -gt 0 ]; then
        NACL_ID=$(echo "$NACL_DATA" | jq -r '.NetworkAcls[0].NetworkAclId')
        echo ""
        echo "Network ACL: $NACL_ID"
        echo "------------------------------------------"
        
        # Inbound Rules
        echo "INBOUND RULES:"
        echo "$NACL_DATA" | jq -r '.NetworkAcls[0].Entries[] | 
            select(.Egress == false) | 
            "  Rule #" + (.RuleNumber|tostring) + " [" + .RuleAction + "] " +
            (if .Protocol == "-1" then "ALL"
             elif .Protocol == "6" then "TCP"
             elif .Protocol == "17" then "UDP"
             elif .Protocol == "1" then "ICMP"
             else ("Protocol " + .Protocol) end) +
            (if .PortRange then " Port " + (.PortRange.From|tostring) + 
                (if .PortRange.From != .PortRange.To then "-" + (.PortRange.To|tostring) else "" end)
             else "" end) +
            " from " + (if .CidrBlock then .CidrBlock elif .Ipv6CidrBlock then .Ipv6CidrBlock else "unknown" end)' | sort -t'#' -k2 -n
        
        # Outbound Rules
        echo ""
        echo "OUTBOUND RULES:"
        echo "$NACL_DATA" | jq -r '.NetworkAcls[0].Entries[] | 
            select(.Egress == true) | 
            "  Rule #" + (.RuleNumber|tostring) + " [" + .RuleAction + "] " +
            (if .Protocol == "-1" then "ALL"
             elif .Protocol == "6" then "TCP"
             elif .Protocol == "17" then "UDP"
             elif .Protocol == "1" then "ICMP"
             else ("Protocol " + .Protocol) end) +
            (if .PortRange then " Port " + (.PortRange.From|tostring) + 
                (if .PortRange.From != .PortRange.To then "-" + (.PortRange.To|tostring) else "" end)
             else "" end) +
            " to " + (if .CidrBlock then .CidrBlock elif .Ipv6CidrBlock then .Ipv6CidrBlock else "unknown" end)' | sort -t'#' -k2 -n
    else
        echo "No Network ACL found for subnet"
    fi
else
    echo "No subnet found - cannot retrieve Network ACL"
fi

echo ""
echo "=========================================="
