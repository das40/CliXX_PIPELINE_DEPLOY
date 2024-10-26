#!/usr/bin/env python3
import boto3, botocore, base64, time

# Assume Role to interact with AWS resources
session_client = boto3.client('sts')
assumed_role_data = session_client.assume_role(
    RoleArn='arn:aws:iam::619071313311:role/Engineer',
    RoleSessionName='clixx_session'
)
session_creds = assumed_role_data['Credentials']

# Create boto3 clients with assumed role credentials
ec2_client = boto3.client('ec2', region_name="us-east-1", 
                          aws_access_key_id=session_creds['AccessKeyId'], 
                          aws_secret_access_key=session_creds['SecretAccessKey'], 
                          aws_session_token=session_creds['SessionToken'])

ec2_resource = boto3.resource('ec2', region_name="us-east-1",
                              aws_access_key_id=session_creds['AccessKeyId'],
                              aws_secret_access_key=session_creds['SecretAccessKey'],
                              aws_session_token=session_creds['SessionToken'])

elbv2_client = boto3.client('elbv2', region_name="us-east-1", 
                            aws_access_key_id=session_creds['AccessKeyId'], 
                            aws_secret_access_key=session_creds['SecretAccessKey'], 
                            aws_session_token=session_creds['SessionToken'])

rds_client = boto3.client('rds', region_name="us-east-1", 
                          aws_access_key_id=session_creds['AccessKeyId'], 
                          aws_secret_access_key=session_creds['SecretAccessKey'], 
                          aws_session_token=session_creds['SessionToken'])

efs_client = boto3.client('efs', region_name="us-east-1", 
                          aws_access_key_id=session_creds['AccessKeyId'], 
                          aws_secret_access_key=session_creds['SecretAccessKey'], 
                          aws_session_token=session_creds['SessionToken'])

route53_client = boto3.client('route53', 
                              aws_access_key_id=session_creds['AccessKeyId'], 
                              aws_secret_access_key=session_creds['SecretAccessKey'], 
                              aws_session_token=session_creds['SessionToken'])

autoscaling_client = boto3.client('autoscaling', region_name="us-east-1", 
                                  aws_access_key_id=session_creds['AccessKeyId'], 
                                  aws_secret_access_key=session_creds['SecretAccessKey'], 
                                  aws_session_token=session_creds['SessionToken'])

###########################################################################
# Variables
# clixx_vpc_cidr_block = "10.10.0.0/16"
# clixx_pub_subnet_1_block = "10.10.1.0/24"
# clixx_pub_subnet_2_block = "10.10.2.0/24"
# clixx_priv_subnet_1_block = "10.10.3.0/24"
# clixx_priv_subnet_2_block = "10.10.4.0/24"
# clixx_db_identifier = "ClixxAppDB"
# clixx_db_snapshot_ref = "arn:aws:rds:us-east-1:619071313311:snapshot:wordpressdbclixx-snapshot"
# clixx_db_class = "db.m6gd.large"
# clixx_db_admin_user = "clixxadmin"
# clixx_db_secret_key = "ClixxPass123"
# clixx_ami_id = "ami-0a7c251754ac5da7f5"
# clixx_instance_size = "t2.medium"
# clixx_key_name = "clixx_devops_kp"
# clixx_cert_arn = "arn:aws:acm:us-east-1:619071313311:certificate/ed0a7048-b2f1-4ca7-835d-06d5cc51f805"
# clixx_host_zone_id = "Z032607324NJ585T59J7F"
# clixx_dns_record = "dev.clixx-dasola.com"
# aws_region = "us-east-1"



aws_region = "us-east-1"  # Terraform variable AWS_REGION

# Key Pair paths
clixx_key_name = "clixx_devops_kp"  # AWS key pair name used on EC2
clixx_key_path_private = "clixx_key"  # Path from Terraform variable PATH_TO_PRIVATE_KEY
clixx_key_path_public = "/Users/oyeioladasolajoshua/desktop/apps/TERRAFORM/STACK_EC2-TF/clixx_key.pub"  # PATH_TO_PUBLIC_KEY

## EC2 and Load Balancer Configuration
instance_type = "t2.micro"  # Terraform variable clixx_instance_size
ami_id = "ami-08f3d892de259504d"  # Terraform variable clixx_ami_id

# RDS Configuration
DB_IDENTIFIER = "ClixxAppDB"  # RDS instance name
snapshot_arn = "arn:aws:rds:us-east-1:619071313311:snapshot:wordpressdbclixx-snapshot"  # Terraform variable clixx_db_snapshot_ref
DB_CLASS = "db.m6gd.large"
DB_USER = "wordpressuser"  # Terraform variable clixx_db_admin_user
DB_NAME = "wordpressdb"  # Terraform variable clixx_db_name
DB_USER_PASSWORD = "W3lcome123"  # Terraform variable clixx_db_secret_key
DB_HOST = ""  # Dynamically set to the RDS endpoint in Terraform as clixx_db_host

# EFS Configuration
efs_id = ""  
efs_performance_mode = "generalPurpose"  # Terraform variable clixx_efs_performance_mode
efs_encrypted = True  # Terraform variable clixx_efs_encrypted
MOUNT_POINT = "/var/www/html"  # Terraform variable clixx_efs_mount_point

# Route 53 and Load Balancer Configuration
certificate_arn = "arn:aws:acm:us-east-1:619071313311:certificate/ed0a7048-b2f1-4ca7-835d-06d5cc51f805"
hosted_zone_id = "Z0881876FFUR3OKRNM20"
DNS = "dev.clixx-dasola.com"  # Terraform variable clixx_dns_record
LB_DNS = "clixx-dasola.com"  # Terraform variable clixx_lb_dns




# --- VPC ---
vpcs = ec2_client.describe_vpcs(Filters=[{'Name': 'cidr', 'Values': [clixx_vpc_cidr_block]}])
if not vpcs['Vpcs']:
    clixx_vpc = ec2_resource.create_vpc(CidrBlock=clixx_vpc_cidr_block)
    ec2_client.create_tags(Resources=[clixx_vpc.id], Tags=[{'Key': 'Name', 'Value': 'CLixxVPC'}])
    ec2_client.modify_vpc_attribute(VpcId=clixx_vpc.id, EnableDnsSupport={'Value': True})
    ec2_client.modify_vpc_attribute(VpcId=clixx_vpc.id, EnableDnsHostnames={'Value': True})
    print(f"VPC created: {clixx_vpc.id} with Name tag 'CLixxVPC'")
else:
    print(f"VPC already exists with CIDR block {clixx_vpc_cidr_block}")
vpc_id = vpcs['Vpcs'][0]['VpcId'] if vpcs['Vpcs'] else clixx_vpc.id

# --- Subnets ---
subnets_1 = ec2_client.describe_subnets(Filters=[{'Name': 'cidr', 'Values': [clixx_pub_subnet_1_block]}])
if not subnets_1['Subnets']:
    subnet_1 = ec2_client.create_subnet(CidrBlock=clixx_pub_subnet_1_block, VpcId=vpc_id, AvailabilityZone=aws_region + "a")
    ec2_client.create_tags(Resources=[subnet_1['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': "CLixxPubSubnet1"}])
    print(f"Public Subnet 1 created: {subnet_1['Subnet']['SubnetId']} with Name tag 'CLixxPubSubnet1'")
else:
    print(f"Public Subnet 1 already exists with CIDR block {clixx_pub_subnet_1_block}")
subnet_1_id = subnets_1['Subnets'][0]['SubnetId'] if subnets_1['Subnets'] else subnet_1['Subnet']['SubnetId']

subnets_2 = ec2_client.describe_subnets(Filters=[{'Name': 'cidr', 'Values': [clixx_pub_subnet_2_block]}])
if not subnets_2['Subnets']:
    subnet_2 = ec2_client.create_subnet(CidrBlock=clixx_pub_subnet_2_block, VpcId=vpc_id, AvailabilityZone=aws_region + "b")
    ec2_client.create_tags(Resources=[subnet_2['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': "CLixxPubSubnet2"}])
    print(f"Public Subnet 2 created: {subnet_2['Subnet']['SubnetId']} with Name tag 'CLixxPubSubnet2'")
else:
    print(f"Public Subnet 2 already exists with CIDR block {clixx_pub_subnet_2_block}")
subnet_2_id = subnets_2['Subnets'][0]['SubnetId'] if subnets_2['Subnets'] else subnet_2['Subnet']['SubnetId']

private_subnets_1 = ec2_client.describe_subnets(Filters=[{'Name': 'cidr', 'Values': [clixx_priv_subnet_1_block]}])
if not private_subnets_1['Subnets']:
    private_subnet_1 = ec2_client.create_subnet(CidrBlock=clixx_priv_subnet_1_block, VpcId=vpc_id, AvailabilityZone=aws_region + "a")
    ec2_client.create_tags(Resources=[private_subnet_1['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': "CLixxPrivSubnet1"}])
    print(f"Private Subnet 1 created: {private_subnet_1['Subnet']['SubnetId']} with Name tag 'CLixxPrivSubnet1'")
else:
    print(f"Private Subnet 1 already exists with CIDR block {clixx_priv_subnet_1_block}")
private_subnet_1_id = private_subnets_1['Subnets'][0]['SubnetId'] if private_subnets_1['Subnets'] else private_subnet_1['Subnet']['SubnetId']

private_subnets_2 = ec2_client.describe_subnets(Filters=[{'Name': 'cidr', 'Values': [clixx_priv_subnet_2_block]}])
if not private_subnets_2['Subnets']:
    private_subnet_2 = ec2_client.create_subnet(CidrBlock=clixx_priv_subnet_2_block, VpcId=vpc_id, AvailabilityZone=aws_region + "b")
    ec2_client.create_tags(Resources=[private_subnet_2['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': "CLixxPrivSubnet2"}])
    print(f"Private Subnet 2 created: {private_subnet_2['Subnet']['SubnetId']} with Name tag 'CLixxPrivSubnet2'")
else:
    print(f"Private Subnet 2 already exists with CIDR block {clixx_priv_subnet_2_block}")
private_subnet_2_id = private_subnets_2['Subnets'][0]['SubnetId'] if private_subnets_2['Subnets'] else private_subnet_2['Subnet']['SubnetId']

# --- Internet Gateway ---
igw_list = list(ec2_resource.internet_gateways.filter(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]))
if not igw_list:
    clixx_igw = ec2_resource.create_internet_gateway()
    ec2_client.attach_internet_gateway(VpcId=vpc_id, InternetGatewayId=clixx_igw.id)
    ec2_client.create_tags(Resources=[clixx_igw.id], Tags=[{'Key': 'Name', 'Value': 'CLixxIGW'}])
    print(f"Internet Gateway created: {clixx_igw.id} with Name tag 'CLixxIGW'")
else:
    clixx_igw = igw_list[0]
    print(f"Internet Gateway already exists with ID {clixx_igw.id}")

# --- Route Tables ---
pub_route_table_list = list(ec2_resource.route_tables.filter(Filters=[{'Name': 'association.main', 'Values': ['false']}]))

if not pub_route_table_list:
    clixx_pub_route_table = ec2_resource.create_route_table(VpcId=vpc_id)
    ec2_client.create_tags(Resources=[clixx_pub_route_table.id], Tags=[{'Key': 'Name', 'Value': 'CLixxPubRT'}])
    print(f"Public Route Table created: {clixx_pub_route_table.id} with Name tag 'CLixxPubRT'")
else:
    clixx_pub_route_table = pub_route_table_list[0]
    print(f"Public Route Table already exists with ID {clixx_pub_route_table.id}")

priv_route_table_list = list(ec2_resource.route_tables.filter(Filters=[{'Name': 'association.main', 'Values': ['false']}]))
if not priv_route_table_list:
    clixx_priv_route_table = ec2_resource.create_route_table(VpcId=vpc_id)
    ec2_client.create_tags(Resources=[clixx_priv_route_table.id], Tags=[{'Key': 'Name', 'Value': 'CLixxPrivRT'}])
    print(f"Private Route Table created: {clixx_priv_route_table.id} with Name tag 'CLixxPrivRT'")
else:
    clixx_priv_route_table = priv_route_table_list[0]
    print(f"Private Route Table already exists with ID {clixx_priv_route_table.id}")

# --- Route for Internet Access for Public Subnets ---
routes = [route for route in clixx_pub_route_table.routes if route.destination_cidr_block == '0.0.0.0/0']
if not routes:
    clixx_pub_route_table.create_route(
        DestinationCidrBlock='0.0.0.0/0',
        GatewayId=clixx_igw.id
    )
    print("Public route created for Internet access")
else:
    print("Public route for Internet access already exists")

# --- Associate Subnets with Route Tables ---
pub_associations = [assoc for assoc in clixx_pub_route_table.associations if assoc.subnet_id in [subnet_1_id, subnet_2_id]]
if not pub_associations:
    clixx_pub_route_table.associate_with_subnet(SubnetId=subnet_1_id) 
    clixx_pub_route_table.associate_with_subnet(SubnetId=subnet_2_id)
    print("Public subnets associated with Public Route Table")
else:
    print("Public subnets already associated with Public Route Table")

priv_associations = [assoc for assoc in clixx_priv_route_table.associations if assoc.subnet_id in [private_subnet_1_id, private_subnet_2_id]]
if not priv_associations:
    clixx_priv_route_table.associate_with_subnet(SubnetId=private_subnet_1_id)
    clixx_priv_route_table.associate_with_subnet(SubnetId=private_subnet_2_id)
    print("Private subnets associated with Private Route Table")
else:
    print("Private subnets already associated with Private Route Table")
print("Route tables created and associated with subnets.")

# --- Security Group ---
# Check for existing public security group
existing_public_sg = list(ec2_resource.security_groups.filter(Filters=[{'Name': 'group-name', 'Values': ['ClixxPublicSG']}]))
if not existing_public_sg:
    clixx_public_sg = ec2_resource.create_security_group(
        GroupName='ClixxPublicSG',
        Description='Public Security Group for App Servers',
        VpcId=vpc_id
    )
    clixx_public_sg.create_tags(Tags=[{'Key': 'Name', 'Value': 'ClixxPublicSG'}])
    
    # Authorize ingress rules for the public security group
    ec2_client.authorize_security_group_ingress(
        GroupId=clixx_public_sg.id,
        IpPermissions=[
            {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},  # SSH
            {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},  # HTTP
            {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},  # HTTPS
        ]
    )
    print(f"Public Security Group created: {clixx_public_sg.id}")
else:
    clixx_public_sg = existing_public_sg[0]
    print(f"Public Security Group already exists with ID: {clixx_public_sg.id}")

# Check for existing private security group
existing_private_sg = list(ec2_resource.security_groups.filter(Filters=[{'Name': 'group-name', 'Values': ['ClixxPrivateSG']}]))
if not existing_private_sg:
    clixx_private_sg = ec2_resource.create_security_group(
        GroupName='ClixxPrivateSG',
        Description='Private Security Group for RDS and EFS',
        VpcId=vpc_id
    )
    clixx_private_sg.create_tags(Tags=[{'Key': 'Name', 'Value': 'ClixxPrivateSG'}])

    # Authorize ingress rules for the private security group
    ec2_client.authorize_security_group_ingress(
        GroupId=clixx_private_sg.id,
        IpPermissions=[
            {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '10.10.0.0/16'}]},  # MySQL (RDS)
            {'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049, 'IpRanges': [{'CidrIp': '10.10.0.0/16'}]},  # NFS (EFS)
        ]
    )
    print(f"Private Security Group created: {clixx_private_sg.id}")
else:
    clixx_private_sg = existing_private_sg[0]
    print(f"Private Security Group already exists with ID: {clixx_private_sg.id}")

print(f"Security Groups created: Public SG (ID: {clixx_public_sg.id}), Private SG (ID: {clixx_private_sg.id})")

# --- RDS Instance ---
# Create or handle existing DB Subnet Group
clixx_db_subnet_group_name = 'ClixxDBSubnetGroup'
db_subnet_groups = rds_client.describe_db_subnet_groups()
db_subnet_group_exists = False

for subnet_group in db_subnet_groups['DBSubnetGroups']:
    if subnet_group['DBSubnetGroupName'] == clixx_db_subnet_group_name:
        db_subnet_group_exists = True
        print(f"DB Subnet Group '{clixx_db_subnet_group_name}' already exists.")
        break

if not db_subnet_group_exists:
    rds_client.create_db_subnet_group(
        DBSubnetGroupName=clixx_db_subnet_group_name,
        SubnetIds=[private_subnet_1_id, private_subnet_2_id],
        DBSubnetGroupDescription='Clixx Database Subnet Group',
        Tags=[{'Key': 'Name', 'Value': 'ClixxDBSubnetGroup'}]
    )
    print(f"DB Subnet Group '{clixx_db_subnet_group_name}' created successfully.")

# Check if the RDS instance exists
db_instances = rds_client.describe_db_instances()
clixx_db_instance_exists = any(db['DBInstanceIdentifier'] == clixx_db_identifier for db in db_instances['DBInstances'])

if clixx_db_instance_exists:
    print(f"DB Instance '{clixx_db_identifier}' already exists.")
else:
    # Restore the DB instance from snapshot if it doesn't exist
    print(f"DB Instance '{clixx_db_identifier}' not found. Restoring from snapshot...")
    rds_client.restore_db_instance_from_db_snapshot(
        DBInstanceIdentifier=clixx_db_identifier,
        DBSnapshotIdentifier=clixx_db_snapshot_ref,
        DBInstanceClass=clixx_db_class,
        VpcSecurityGroupIds=[clixx_private_sg.id],
        DBSubnetGroupName=clixx_db_subnet_group_name,
        PubliclyAccessible=False,
        Tags=[{'Key': 'Name', 'Value': 'ClixxDBInstance'}]
    )
    print(f"Restore operation initiated for DB instance '{clixx_db_identifier}'.")

# --- EFS File System ---
# Check if EFS exists by creation token
efs_token = 'Clixx-EFS'
efs_response = efs_client.describe_file_systems(CreationToken=efs_token)

if efs_response['FileSystems']:
    file_system_id = efs_response['FileSystems'][0]['FileSystemId']
    print(f"EFS already exists with FileSystemId: {file_system_id}")
else:
    # Create EFS if it doesn't exist
    efs_response = efs_client.create_file_system(
        CreationToken=efs_token,
        PerformanceMode='generalPurpose',
        Tags=[{'Key': 'Name', 'Value': 'ClixxEFS'}]
    )
    file_system_id = efs_response['FileSystemId']
    print(f"EFS created with FileSystemId: {file_system_id}")

# Wait until the EFS is available
while True:
    efs_info = efs_client.describe_file_systems(FileSystemId=file_system_id)
    lifecycle_state = efs_info['FileSystems'][0]['LifeCycleState']
    if lifecycle_state == 'available':
        print(f"EFS '{efs_token}' is now available with FileSystemId: {file_system_id}")
        break
    else:
        print(f"EFS '{efs_token}' is in '{lifecycle_state}' state. Waiting to become available...")
        time.sleep(10)

# Create mount targets for EFS in private subnets
private_subnet_ids = [private_subnet_1_id, private_subnet_2_id]
for private_subnet_id in private_subnet_ids:
    # Check if mount target already exists for the subnet
    mount_targets = efs_client.describe_mount_targets(FileSystemId=file_system_id)['MountTargets']
    existing_mount_targets = [mt['SubnetId'] for mt in mount_targets]

    if private_subnet_id not in existing_mount_targets:
        efs_client.create_mount_target(
            FileSystemId=file_system_id,
            SubnetId=private_subnet_id,
            SecurityGroups=[clixx_private_sg.id]
        )
        print(f"Mount target created in Private Subnet: {private_subnet_id}")
    else:
        print(f"Mount target already exists in Private Subnet: {private_subnet_id}")

# --- Create Target Group ---
all_target_groups = elbv2_client.describe_target_groups()['TargetGroups']
target_group_arn = None

for tg in all_target_groups:
    if tg['TargetGroupName'] == 'ClixxTargetGroup':
        target_group_arn = tg['TargetGroupArn']
        print(f"Target Group already exists with ARN: {target_group_arn}")
        break

if target_group_arn is None:
    target_group = elbv2_client.create_target_group(
        Name='ClixxTargetGroup',
        Protocol='HTTP',
        Port=80,
        VpcId=vpc_id,
        TargetType='instance',
        HealthCheckProtocol='HTTP',
        HealthCheckPath='/',
        HealthCheckIntervalSeconds=120,
        HealthCheckTimeoutSeconds=30,
        HealthyThresholdCount=5,
        UnhealthyThresholdCount=4,
        Matcher={'HttpCode': '200-399'}
    )
    target_group_arn = target_group['TargetGroups'][0]['TargetGroupArn']
    print(f"Target Group created with ARN: {target_group_arn}")

# --- Create Load Balancer ---
all_load_balancers = elbv2_client.describe_load_balancers()['LoadBalancers']
load_balancer_arn = None

for lb in all_load_balancers:
    if lb['LoadBalancerName'] == 'ClixxLoadBalancer':
        load_balancer_arn = lb['LoadBalancerArn']
        print(f"Load Balancer already exists with ARN: {load_balancer_arn}")
        break

if load_balancer_arn is None:
    load_balancer = elbv2_client.create_load_balancer(
        Name='ClixxLoadBalancer',
        Subnets=[subnet_1_id, subnet_2_id],
        SecurityGroups=[clixx_public_sg.id],
        Scheme='internet-facing',
        IpAddressType='ipv4',
        Tags=[{'Key': 'Name', 'Value': 'ClixxLoadBalancer'}, {'Key': 'Environment', 'Value': 'dev'}]
    )
    load_balancer_arn = load_balancer['LoadBalancers'][0]['LoadBalancerArn']
    print(f"Load Balancer created with ARN: {load_balancer_arn}")

# Create Listener for Load Balancer (HTTP & HTTPS)
listeners = elbv2_client.describe_listeners(LoadBalancerArn=load_balancer_arn)['Listeners']
http_listener_exists = any(listener['Protocol'] == 'HTTP' for listener in listeners)
https_listener_exists = any(listener['Protocol'] == 'HTTPS' for listener in listeners)

if not http_listener_exists:
    elbv2_client.create_listener(
        LoadBalancerArn=load_balancer_arn,
        Protocol='HTTP',
        Port=80,
        DefaultActions=[{'Type': 'forward', 'TargetGroupArn': target_group_arn}]
    )
    print(f"HTTP Listener created for Load Balancer: {load_balancer_arn}")

if not https_listener_exists:
    elbv2_client.create_listener(
        LoadBalancerArn=load_balancer_arn,
        Protocol='HTTPS',
        Port=443,
        SslPolicy='ELBSecurityPolicy-2016-08',
        Certificates=[{'CertificateArn': clixx_cert_arn}],
        DefaultActions=[{'Type': 'forward', 'TargetGroupArn': target_group_arn}]
    )
    print(f"HTTPS Listener created for Load Balancer: {load_balancer_arn}")

# --- Create Route 53 record for Load Balancer ---
record_sets = route53_client.list_resource_record_sets(HostedZoneId=clixx_host_zone_id)['ResourceRecordSets']
record_exists = any(record['Name'] == clixx_dns_record for record in record_sets)

if not record_exists:
    route53_client.change_resource_record_sets(
        HostedZoneId=clixx_host_zone_id,
        ChangeBatch={
            'Changes': [{
                'Action': 'CREATE',
                'ResourceRecordSet': {
                    'Name': clixx_dns_record,
                    'Type': 'A',
                    'AliasTarget': {
                        'HostedZoneId': load_balancer['LoadBalancers'][0]['CanonicalHostedZoneId'],
                        'DNSName': load_balancer['LoadBalancers'][0]['DNSName'],
                        'EvaluateTargetHealth': False
                    }
                }
            }]
        }
    )
    print(f"Route 53 record created for {clixx_dns_record}")
else:
    print(f"Route 53 record already exists for {clixx_dns_record}")


"""user_data_script=#!/bin/bash -x
# Basic logging
exec > >(tee /var/log/userdata.log) 2>&1

echo "Connecting to DB: ${DB_HOST}"

    # Database Configuration
    DB_USER="${DB_USER}"
    DB_USER_PASSWORD="${DB_USER_PASSWORD}"
    DB_HOST="${DB_HOST}"
    DB_NAME="${DB_NAME}"
    DNS="${DNS}"
    EFS_ID="${efs_id}"  # Passed from Terraform using $$ for variable interpolation
    REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
    MOUNT_POINT="/var/www/html"
    LB_DNS="${LB_DNS}"

# Update packages and install dependencies
sudo yum update -y
sudo yum install -y git
sudo amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
sudo yum install -y httpd mariadb-server nfs-utils

# Start and enable Apache
sudo systemctl start httpd
sudo systemctl enable httpd

# Configure permissions
sudo usermod -a -G apache ec2-user
sudo chown -R ec2-user:apache /var/www
sudo chmod 2775 /var/www
find /var/www -type d -exec sudo chmod 2775 {} \;
find /var/www -type f -exec sudo chmod 0664 {} \;

# Mount EFS
AVAILABILITY_ZONE=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)

# Extract region by removing the last character (the zone letter)
#REGION=$AVAILABILITY_ZONE:0:-1
REGION=$(echo "$AVAILABILITY_ZONE" | sed 's/[a-z]$//')


# Create mount point directory if it doesn't exist
sudo mkdir -p "$MOUNT_POINT"
sudo chown ec2-user:ec2-user "$MOUNT_POINT"

# Add the EFS entry to /etc/fstab for automatic mounting
echo "$EFS_ID.efs.$REGION.amazonaws.com:/ $MOUNT_POINT nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,_netdev 0 0" | sudo tee -a /etc/fstab

# Sleep to allow network interfaces to initialize
sleep 120

# Mount the EFS
sudo mount -a

# Check if EFS mount was successful
if mount | grep "$MOUNT_POINT" > /dev/null; then
    echo "EFS successfully mounted"
else
    echo "EFS mount failed"
    
fi

# Clone your repository and set up WordPress configuration
cd /var/www/html
if ! git clone https://github.com/stackitgit/CliXX_Retail_Repository.git; then
    echo "Git clone failed"

fi
cp -r CliXX_Retail_Repository/* /var/www/html

# Setup wp-config.php
if [ -f "wp-config-sample.php" ]; then
    cp wp-config-sample.php wp-config.php
else
    echo "wp-config-sample.php does not exist!" >> /var/log/userdata.log
    exit 1  # Exit if wp-config-sample.php doesn't exist
fi

# Replace placeholders in wp-config.php with actual values
sed -i "s/database_name_here/${DB_NAME}/; s/username_here/${DB_USER}/; s/password_here/${DB_USER_PASSWORD}/; s/localhost/${DB_HOST}/" wp-config.php

# Check if HTTPS handling already exists
if ! grep -q "HTTP_X_FORWARDED_PROTO" wp-config.php; then
    # Add HTTPS handling to wp-config.php
    echo "if (isset(\$_SERVER['HTTP_X_FORWARDED_PROTO']) && \$_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
        \$_SERVER['HTTPS'] = 'on';
    }" >> wp-config.php || echo "Failed to append HTTPS handling to wp-config.php" >> /var/log/userdata.log
else
    echo "HTTPS handling already exists in wp-config.php" >> /var/log/userdata.log
fi

# Update Apache configuration to allow WordPress permalinks
sudo sed -i '151s/None/All/' /etc/httpd/conf/httpd.conf

# Adjust file and directory ownership and permissions
sudo chown -R apache /var/www
sudo chgrp -R apache /var/www
sudo chmod 2775 /var/www
find /var/www -type d -exec sudo chmod 2775 {} \;
find /var/www -type f -exec sudo chmod 0664 {} \;

# Check if DNS is already in the wp_options table
output_variable=$(mysql -u ${DB_USER} -p${DB_USER_PASSWORD} -h ${DB_HOST} ${DB_NAME} -sse "SELECT option_value FROM wp_options WHERE option_value LIKE '%${DNS}%' LIMIT 1;")

if [[ "$output_variable" == *"$DNS"* ]]; then
    echo "DNS Address is already in the table"
else
    echo "DNS Address is not in the table, updating..."
    
    # Ensure the database exists before performing the update
    mysql -u ${DB_USER} -p${DB_USER_PASSWORD} -h ${DB_HOST} -e "CREATE DATABASE IF NOT EXISTS ${DB_NAME};"
    
    # Update the wp_options table with the new DNS value
    mysql -u ${DB_USER} -p${DB_USER_PASSWORD} -h ${DB_HOST} ${DB_NAME} -e "UPDATE wp_options SET option_value = '${DNS}' WHERE option_value LIKE '%${DNS}%';"
fi

# Restart and enable Apache
sudo systemctl restart httpd

# Update RDS with Load Balancer DNS
UPDATE_SITEURL="UPDATE wp_options SET option_value='https://${LB_DNS}' WHERE option_name='siteurl';"
UPDATE_HOME="UPDATE wp_options SET option_value='https://${LB_DNS}' WHERE option_name='home';"

# Execute the update queries
if mysql -h ${DB_HOST} -u ${DB_USER} -p${DB_USER_PASSWORD} -D ${DB_NAME} -e "${UPDATE_SITEURL}" && \
   mysql -h ${DB_HOST} -u ${DB_USER} -p${DB_USER_PASSWORD} -D ${DB_NAME} -e "${UPDATE_HOME}"; then
    echo "MySQL update successful"
else
    echo "MySQL update failed"
    exit 1
fi

# Set TCP keepalive settings
sudo /sbin/sysctl -w net.ipv4.tcp_keepalive_time=200 net.ipv4.tcp_keepalive_intvl=200 net.ipv4.tcp_keepalive_probes=5

# WordPress Installation on EFS
cd "$MOUNT_POINT"
sudo wget https://wordpress.org/latest.tar.gz
sudo tar -xzf latest.tar.gz
sudo mv wordpress/* "$MOUNT_POINT"
sudo rm -rf wordpress latest.tar.gz

# Set up WordPress configuration
sudo cp wp-config-sample.php wp-config.php
sudo sed -i "s/database_name_here/$DB_NAME/; s/username_here/$DB_USER/; s/password_here/$DB_USER_PASSWORD/; s/localhost/$DB_HOST/" wp-config.php

# Adjust permissions for WordPress
sudo chown -R apache:apache "$MOUNT_POINT"
sudo find "$MOUNT_POINT" -type d -exec chmod 755 {} \;
sudo find "$MOUNT_POINT" -type f -exec chmod 644 {} \;

# Reload Apache
sudo systemctl restart httpd

# Log completion
echo "WordPress installation and configuration completed."
""""

# Encode the user data to Base64
clixx_user_data_base64 = base64.b64encode(user_data_script.encode('utf-8')).decode('utf-8')

# --- Create Launch Template ---
# List all launch templates and check for 'ClixxLaunchTemplate'
all_lt_response = ec2_client.describe_launch_templates()
launch_template_names = [lt['LaunchTemplateName'] for lt in all_lt_response['LaunchTemplates']]

if 'ClixxLaunchTemplate' in launch_template_names:
    # Get the ID of the existing launch template
    clixx_launch_template_id = next(
        lt['LaunchTemplateId'] for lt in all_lt_response['LaunchTemplates'] if lt['LaunchTemplateName'] == 'ClixxLaunchTemplate'
    )
    print(f"Launch Template already exists with ID: {clixx_launch_template_id}")
else:
    # Create a new launch template since it doesn't exist
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName='ClixxLaunchTemplate',
        VersionDescription='Version 1',
        LaunchTemplateData={
            'ImageId': clixx_ami_id,
            'InstanceType': clixx_instance_size,
            'KeyName': clixx_key_name,
            'UserData': clixx_user_data_base64,
            'IamInstanceProfile': {
                'Name': 'ClixxEFSOperations'
            },
            'NetworkInterfaces': [{
                'AssociatePublicIpAddress': True,
                'DeviceIndex': 0,
                'SubnetId': subnet_1_id,
                'Groups': [clixx_public_sg.id]
            }]
        }
    )
    clixx_launch_template_id = launch_template['LaunchTemplate']['LaunchTemplateId']
    print(f"Launch Template created with ID: {clixx_launch_template_id}")

# --- Create Auto Scaling Group ---
# List all Auto Scaling Groups and check for 'ClixxAutoScalingGroup'
all_asg_response = autoscaling_client.describe_auto_scaling_groups()
asg_names = [asg['AutoScalingGroupName'] for asg in all_asg_response['AutoScalingGroups']]

if 'ClixxAutoScalingGroup' in asg_names:
    print("Auto Scaling Group already exists.")
else:
    # Create a new Auto Scaling Group since it doesn't exist
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName='ClixxAutoScalingGroup',
        LaunchTemplate={
            'LaunchTemplateId': clixx_launch_template_id,
            'Version': '1'
        },
        MinSize=1,
        MaxSize=3,
        DesiredCapacity=1,
        VPCZoneIdentifier=subnet_1_id,
        TargetGroupARNs=[target_group_arn],
        Tags=[
            {
                'Key': 'Name',
                'Value': 'ClixxAutoScalingGroup',
                'PropagateAtLaunch': True
            }
        ]
    )
    print("Auto Scaling Group created successfully.")
