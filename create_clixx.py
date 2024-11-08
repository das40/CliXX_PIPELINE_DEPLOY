
import boto3
import logging
import time, base64
from botocore.exceptions import ClientError

# Set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Assume Role to interact with AWS resources
clixx_sts_client = boto3.client('sts')
clixx_assumed_role_object = clixx_sts_client.assume_role(
    RoleArn='arn:aws:iam::619071313311:role/Engineer',
    RoleSessionName='mysession'
)
clixx_credentials = clixx_assumed_role_object['Credentials']

# Create clients with assumed role credentials
clixx_ec2_client = boto3.client('ec2', region_name='us-east-1',
                                aws_access_key_id=clixx_credentials['AccessKeyId'],
                                aws_secret_access_key=clixx_credentials['SecretAccessKey'],
                                aws_session_token=clixx_credentials['SessionToken'])
clixx_ec2_resource = boto3.resource('ec2', region_name='us-east-1',
                                     aws_access_key_id=clixx_credentials['AccessKeyId'],
                                     aws_secret_access_key=clixx_credentials['SecretAccessKey'],
                                     aws_session_token=clixx_credentials['SessionToken'])
clixx_elbv2_client = boto3.client('elbv2', region_name='us-east-1',
                                  aws_access_key_id=clixx_credentials['AccessKeyId'],
                                  aws_secret_access_key=clixx_credentials['SecretAccessKey'],
                                  aws_session_token=clixx_credentials['SessionToken'])
clixx_rds_client = boto3.client('rds', region_name='us-east-1',
                                aws_access_key_id=clixx_credentials['AccessKeyId'],
                                aws_secret_access_key=clixx_credentials['SecretAccessKey'],
                                aws_session_token=clixx_credentials['SessionToken'])
clixx_efs_client = boto3.client('efs', region_name='us-east-1',
                                aws_access_key_id=clixx_credentials['AccessKeyId'],
                                aws_secret_access_key=clixx_credentials['SecretAccessKey'],
                                aws_session_token=clixx_credentials['SessionToken'])
clixx_route53_client = boto3.client('route53',
                                    aws_access_key_id=clixx_credentials['AccessKeyId'],
                                    aws_secret_access_key=clixx_credentials['SecretAccessKey'],
                                    aws_session_token=clixx_credentials['SessionToken'])
clixx_autoscaling_client = boto3.client('autoscaling', region_name='us-east-1',
                                        aws_access_key_id=clixx_credentials['AccessKeyId'],
                                        aws_secret_access_key=clixx_credentials['SecretAccessKey'],
                                        aws_session_token=clixx_credentials['SessionToken'])

# Define CIDR ranges for VPC and subnets
clixx_vpc_cidr_block = '10.0.0.0/16'
clixx_public_subnets_cidrs = ['10.0.1.0/24', '10.0.2.0/24']
clixx_app_private_subnets_cidrs = ['10.0.3.0/24', '10.0.4.0/24']
clixx_db_private_subnets_cidrs = ['10.0.5.0/24', '10.0.6.0/24']
clixx_oracle_private_subnet_cidr = '10.0.7.0/24'
clixx_java_app_db_subnets_cidrs = ['10.0.8.0/25', '10.0.9.0/25']
clixx_java_app_server_subnets_cidrs = ['10.0.10.0/25', '10.0.11.0/25']
clixx_region = 'us-east-1'
clixx_availability_zones = [f'{clixx_region}a', f'{clixx_region}b']

clixx_db_snapshot_identifier = "arn:aws:rds:us-east-1:619071313311:snapshot:wordpressdbclixx-snapshot"
clixx_db_instance_class = "db.m6gd.large"
clixx_db_username = "wordpressuser"
clixx_db_password = "W3lcome123"
clixx_ami_id = "ami-00f251754ac5da7f0"
clixx_instance_type = "t2.micro"
clixx_key_pair_name = "bastionkey.pem"
clixx_certificate_arn = "arn:aws:acm:us-east-1:619071313311:certificate/ed0a7048-b2f1-4ca7-835d-06d5cc51f805"
#clixx_hosted_zone_id = "Z0881876FFUR3OKRNM20"
clixx_record_name = "dev.clixx-dasola.com"

# Create VPC (if not already created)
clixx_vpcs = clixx_ec2_client.describe_vpcs(Filters=[{'Name': 'cidr', 'Values': [clixx_vpc_cidr_block]}])
if not clixx_vpcs['Vpcs']:
    clixx_vpc = clixx_ec2_resource.create_vpc(CidrBlock=clixx_vpc_cidr_block)
    clixx_ec2_client.create_tags(Resources=[clixx_vpc.id], Tags=[{'Key': 'Name', 'Value': 'CLIXXSTACKVPC'}])
    clixx_ec2_client.modify_vpc_attribute(VpcId=clixx_vpc.id, EnableDnsSupport={'Value': True})
    clixx_ec2_client.modify_vpc_attribute(VpcId=clixx_vpc.id, EnableDnsHostnames={'Value': True})
    logger.info(f"VPC created: {clixx_vpc.id}")
    clixx_vpc_id = clixx_vpc.id
else:
    clixx_vpc_id = clixx_vpcs['Vpcs'][0]['VpcId']
    logger.info(f"VPC already exists: {clixx_vpc_id}")

# Function to create a subnet and apply tags
def create_subnet(clixx_vpc_id, cidr_block, az, name_tag):
    response = clixx_ec2_client.create_subnet(
        VpcId=clixx_vpc_id,
        CidrBlock=cidr_block,
        AvailabilityZone=az
    )
    subnet_id = response['Subnet']['SubnetId']
    clixx_ec2_client.create_tags(Resources=[subnet_id], Tags=[{'Key': 'Name', 'Value': name_tag}])
    logger.info(f"Subnet {name_tag} created: {subnet_id}")
    return subnet_id

# Create public and private subnets
clixx_public_subnet_ids = [create_subnet(clixx_vpc_id, cidr, clixx_availability_zones[i % 2], f'CLIXX-PublicSubnet-{i+1}') for i, cidr in enumerate(clixx_public_subnets_cidrs)]
clixx_app_private_subnet_ids = [create_subnet(clixx_vpc_id, cidr, clixx_availability_zones[i % 2], f'CLIXX-AppPrivateSubnet-{i+1}') for i, cidr in enumerate(clixx_app_private_subnets_cidrs)]
clixx_db_private_subnet_ids = [create_subnet(clixx_vpc_id, cidr, clixx_availability_zones[i % 2], f'CLIXX-DBPrivateSubnet-{i+1}') for i, cidr in enumerate(clixx_db_private_subnets_cidrs)]
clixx_oracle_private_subnet_id = create_subnet(clixx_vpc_id, clixx_oracle_private_subnet_cidr, clixx_availability_zones[0], 'CLIXX-OraclePrivateSubnet')
clixx_java_app_db_subnet_ids = [create_subnet(clixx_vpc_id, cidr, clixx_availability_zones[i % 2], f'CLIXX-JavaAppDBSubnet-{i+1}') for i, cidr in enumerate(clixx_java_app_db_subnets_cidrs)]
clixx_java_app_server_subnet_ids = [create_subnet(clixx_vpc_id, cidr, clixx_availability_zones[i % 2], f'CLIXX-JavaAppServerSubnet-{i+1}') for i, cidr in enumerate(clixx_java_app_server_subnets_cidrs)]

# Create Internet Gateway
clixx_igw_response = clixx_ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [clixx_vpc_id]}])
if not clixx_igw_response['InternetGateways']:
    clixx_igw = clixx_ec2_resource.create_internet_gateway()
    clixx_ec2_client.attach_internet_gateway(VpcId=clixx_vpc_id, InternetGatewayId=clixx_igw.id)
    clixx_ec2_client.create_tags(Resources=[clixx_igw.id], Tags=[{'Key': 'Name', 'Value': 'CLIXXSTACKIGW'}])
    logger.info(f"Internet Gateway created: {clixx_igw.id}")
    clixx_igw_id = clixx_igw.id
else:
    clixx_igw_id = clixx_igw_response['InternetGateways'][0]['InternetGatewayId']
    logger.info(f"Internet Gateway already exists: {clixx_igw_id}")

# NAT Gateways for private subnets
clixx_nat_gateway_ids = []
for subnet_id in clixx_public_subnet_ids:
    eip = clixx_ec2_client.allocate_address(Domain='vpc')
    nat_gw_response = clixx_ec2_client.create_nat_gateway(
        SubnetId=subnet_id,
        AllocationId=eip['AllocationId']
    )
    nat_gw_id = nat_gw_response['NatGateway']['NatGatewayId']
    clixx_nat_gateway_ids.append(nat_gw_id)
    logger.info(f"NAT Gateway created: {nat_gw_id}")
    # Wait for NAT Gateway to become available
    while True:
        nat_gw_status = clixx_ec2_client.describe_nat_gateways(NatGatewayIds=[nat_gw_id])
        state = nat_gw_status['NatGateways'][0]['State']
        if state == 'available':
            logger.info(f"NAT Gateway {nat_gw_id} is now available.")
            break
        else:
            time.sleep(10)

# Create Route Tables and associate with subnets
clixx_pub_route_table = clixx_ec2_resource.create_route_table(VpcId=clixx_vpc_id)
clixx_ec2_client.create_tags(Resources=[clixx_pub_route_table.id], Tags=[{'Key': 'Name', 'Value': 'CLIXX-PublicRT'}])
clixx_pub_route_table.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=clixx_igw_id)
for subnet_id in clixx_public_subnet_ids:
    clixx_pub_route_table.associate_with_subnet(SubnetId=subnet_id)

# Private Route Tables for application and database subnets with NAT Gateways
for i, nat_gw_id in enumerate(clixx_nat_gateway_ids):
    clixx_priv_route_table = clixx_ec2_resource.create_route_table(VpcId=clixx_vpc_id)
    clixx_ec2_client.create_tags(Resources=[clixx_priv_route_table.id], Tags=[{'Key': 'Name', 'Value': f'CLIXX-PrivateRT-AZ{i+1}'}])
    clixx_priv_route_table.create_route(DestinationCidrBlock='0.0.0.0/0', NatGatewayId=nat_gw_id)
    private_subnet_ids = clixx_app_private_subnet_ids if i == 0 else clixx_db_private_subnet_ids
    for subnet_id in private_subnet_ids:
        clixx_priv_route_table.associate_with_subnet(SubnetId=subnet_id)


# Function to create a security group
def create_security_group(name, description, vpc_id, ingress_rules=None):
    sg = clixx_ec2_client.create_security_group(
        GroupName=name,
        Description=description,
        VpcId=vpc_id
    )
    clixx_ec2_client.create_tags(Resources=[sg['GroupId']], Tags=[{'Key': 'Name', 'Value': name}])
    logger.info(f"Security group '{name}' created with ID: {sg['GroupId']}")
    if ingress_rules:
        clixx_ec2_client.authorize_security_group_ingress(
            GroupId=sg['GroupId'],
            IpPermissions=ingress_rules
        )
    return sg['GroupId']

# Security groups
bastion_sg_id = create_security_group('CLIXX-BastionSG', 'Bastion server SG', clixx_vpc_id, [{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}])
load_balancer_sg_id = create_security_group('CLIXX-LoadBalancerSG', 'Load Balancer SG', clixx_vpc_id, [{'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}, {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}])
mysql_db_sg_id = create_security_group('CLIXX-MySQLDBSG', 'MySQL DB SG', clixx_vpc_id, [{'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]}])
#oracle_db_sg_id = create_security_group('CLIXX-OracleDBSG', 'Oracle DB SG', clixx_vpc_id, [{'IpProtocol': 'tcp', 'FromPort': 1521, 'ToPort': 1521, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]}])


# Create DB Subnet Group if it does not exist
try:
    clixx_rds_client.create_db_subnet_group(
        DBSubnetGroupName='CLIXX-DBSubnetGroup',
        DBSubnetGroupDescription='Subnet group for CLIXX database instances',
        SubnetIds=clixx_db_private_subnet_ids,  # Use your private subnets for DB
        Tags=[{'Key': 'Name', 'Value': 'CLIXX-DBSubnetGroup'}]
    )
    logger.info("DB Subnet Group created: CLIXX-DBSubnetGroup")
except ClientError as e:
    if e.response['Error']['Code'] == 'DBSubnetGroupAlreadyExistsFault':
        logger.info("DB Subnet Group already exists: CLIXX-DBSubnetGroup")
    else:
        logger.error(f"Failed to create DB Subnet Group: {e}")



# --- Create RDS Instances ---

# MySQL RDS Instance (for application database)
try:
    clixx_mysql_rds_response = clixx_rds_client.create_db_instance(
        DBInstanceIdentifier='CLIXX-MySQLDB',
        DBInstanceClass='db.m6gd.large',
        Engine='mysql',
        MasterUsername='wordpressuser',
        MasterUserPassword='W3lcome123',
        AllocatedStorage=100,
        VpcSecurityGroupIds=[mysql_db_sg_id],
        DBSubnetGroupName='CLIXX-DBSubnetGroup',
        MultiAZ=True,  # Ensure high availability
        Tags=[{'Key': 'Name', 'Value': 'CLIXX-MySQLDB'}],
        PubliclyAccessible=False
    )
    logger.info("MySQL RDS instance created for application database.")
except ClientError as e:
    logger.error(f"Failed to create MySQL RDS instance: {e}")

# Define the function to update RDS security group
def update_rds_security_group(clixx_ec2_client, rds_sg_id, clixx_app_sg_id):
    try:
        clixx_ec2_client.authorize_security_group_ingress(
            GroupId=rds_sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 3306,
                    'ToPort': 3306,
                    'UserIdGroupPairs': [{'GroupId': clixx_app_sg_id}]
                }
            ]
        )
        logger.info(f"RDS Security Group {rds_sg_id} updated to allow access from CLIXX SG {clixx_app_sg_id}.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidPermission.Duplicate':
            logger.info("Ingress rule already exists.")
        else:
            logger.error(f"Failed to update RDS security group: {e}")

# Update the RDS security group to allow access from CLIXX application instances
update_rds_security_group(clixx_ec2_client, mysql_db_sg_id, bastion_sg_id)  # Adjust bastion_sg_id to actual app SG if different


# --- Deploy Bastion Hosts in Both Public Subnets ---
bastion_hosts = []
try:
    for i, subnet_id in enumerate(clixx_public_subnet_ids):
        bastion_instance = clixx_ec2_resource.create_instances(
            ImageId='ami-00f251754ac5da7f0',  # Replace with a suitable Linux AMI ID for your region
            InstanceType='t2.micro',          # Adjust instance type as necessary
            KeyName='bastionkey.pem',             # Use your existing key pair or create a new one
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[
                {
                    'SubnetId': subnet_id,       # Place in each public subnet
                    'DeviceIndex': 0,
                    'AssociatePublicIpAddress': True,
                    'Groups': [bastion_sg_id]
                }
            ],
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [{'Key': 'Name', 'Value': f'CLIXX-BastionHost-AZ{i+1}'}]
                }
            ]
        )
        bastion_hosts.append(bastion_instance[0].id)
        logger.info(f"Bastion Host deployed in AZ{i+1} with Instance ID: {bastion_instance[0].id}")
except ClientError as e:
    logger.error(f"Failed to deploy Bastion Hosts: {e}")

# --- Create EFS for shared storage ---
try:
    clixx_efs_response = clixx_efs_client.create_file_system(
        CreationToken='CLIXX-EFS',
        PerformanceMode='generalPurpose',
        Tags=[{'Key': 'Name', 'Value': 'CLIXX-EFS'}]
    )
    clixx_file_system_id = clixx_efs_response['FileSystemId']
    logger.info(f"EFS created with FileSystemId: {clixx_file_system_id}")

    # Wait for EFS to become available
    while True:
        efs_status = clixx_efs_client.describe_file_systems(FileSystemId=clixx_file_system_id)
        if efs_status['FileSystems'][0]['LifeCycleState'] == 'available':
            logger.info("EFS is now available.")
            break
        time.sleep(120)
except ClientError as e:
    logger.error(f"Failed to create EFS: {e}")
    
    
# Assuming 'clixx_file_system_id' is your EFS ID and 'mysql_db_sg_id' (or another) is used as the security group.
efs_security_group_id = mysql_db_sg_id  # Adjust as necessary

def create_efs_mount_targets(efs_id, subnet_ids, security_group_id):
    for subnet_id in subnet_ids:
        try:
            mount_target = clixx_efs_client.create_mount_target(
                FileSystemId=efs_id,
                SubnetId=subnet_id,
                SecurityGroups=[security_group_id]
            )
            logger.info(f"Created EFS mount target for subnet {subnet_id} with ID {mount_target['MountTargetId']}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'MountTargetConflict':
                logger.info(f"Mount target already exists in subnet {subnet_id}")
            else:
                logger.error(f"Error creating mount target for subnet {subnet_id}: {e}")

# Call the function to create mount targets in each private subnet where CLIXX instances are hosted
create_efs_mount_targets(clixx_file_system_id, clixx_app_private_subnet_ids, efs_security_group_id)

   

# --- Create Application Load Balancer (ALB) ---
try:
    clixx_lb_response = clixx_elbv2_client.create_load_balancer(
        Name='CLIXX-LoadBalancer',
        Subnets=clixx_public_subnet_ids,
        SecurityGroups=[load_balancer_sg_id],
        Scheme='internet-facing',
        Type='application',
        IpAddressType='ipv4',
        Tags=[{'Key': 'Name', 'Value': 'CLIXX-LoadBalancer'}]
    )
    clixx_lb_arn = clixx_lb_response['LoadBalancers'][0]['LoadBalancerArn']
    logger.info(f"Load Balancer created with ARN: {clixx_lb_arn}")
except ClientError as e:
    logger.error(f"Failed to create Load Balancer: {e}")

# --- Create Target Group ---
try:
    clixx_target_group_response = clixx_elbv2_client.create_target_group(
        Name='CLIXX-TG',
        Protocol='HTTP',
        Port=80,
        VpcId=clixx_vpc_id,
        HealthCheckProtocol='HTTP',
        HealthCheckPath='/',
        TargetType='instance',
        Tags=[{'Key': 'Name', 'Value': 'CLIXX-TG'}]
    )
    clixx_target_group_arn = clixx_target_group_response['TargetGroups'][0]['TargetGroupArn']
    logger.info(f"Target Group created with ARN: {clixx_target_group_arn}")
except ClientError as e:
    logger.error(f"Failed to create Target Group: {e}")

# --- Create HTTP Listener for Load Balancer ---
try:
    clixx_http_listener_response = clixx_elbv2_client.create_listener(
        LoadBalancerArn=clixx_lb_arn,
        Protocol='HTTP',
        Port=80,
        DefaultActions=[{
            'Type': 'forward',
            'TargetGroupArn': clixx_target_group_arn
        }]
    )
    logger.info(f"HTTP Listener created for Load Balancer with ARN: {clixx_http_listener_response['Listeners'][0]['ListenerArn']}")
except ClientError as e:
    logger.error(f"Failed to create HTTP listener for Load Balancer: {e}")
    
    
    
 # --- Create HTTPS Listener for Load Balancer ---
try:
    clixx_https_listener_response = clixx_elbv2_client.create_listener(
        LoadBalancerArn=clixx_lb_arn,
        Protocol='HTTPS',
        Port=443,
        SslPolicy='ELBSecurityPolicy-2016-08',  # You can customize the SSL policy as needed
        Certificates=[{'CertificateArn': clixx_certificate_arn}],
        DefaultActions=[{
            'Type': 'forward',
            'TargetGroupArn': clixx_target_group_arn
        }]
    )
    logger.info(f"HTTPS Listener created for Load Balancer with ARN: {clixx_https_listener_response['Listeners'][0]['ListenerArn']}")
except ClientError as e:
    logger.error(f"Failed to create HTTPS listener for Load Balancer: {e}")
    raise   

# --- Create Launch Template for Application Instances ---
try:
    clixx_user_data_script = f'''#!/bin/bash -x
# Basic logging
exec > >(tee /var/log/userdata.log) 2>&1

# Set variables
DB_USER="wordpressuser"
DB_USER_PASSWORD="W3lcome123"
DB_HOST="wordpressdbclixx.cdk4eccemey1.us-east-1.rds.amazonaws.com"  # Update with actual DB host
DB_NAME="wordpressdb"
efs_name="CLiXX-EFS"
clixx_file_system_id="{clixx_file_system_id}"
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
MOUNT_POINT="/var/www/html"
RECORD_NAME="{clixx_record_name}"  # Define RECORD_NAME here

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
find /var/www -type d -exec sudo chmod 2775 {{}} \;
find /var/www -type f -exec sudo chmod 0664 {{}} \;

# Mount EFS
AVAILABILITY_ZONE=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
REGION=$(echo "$AVAILABILITY_ZONE" | sed 's/[a-z]$//')

# Create mount point directory if it doesn't exist
sudo mkdir -p "$MOUNT_POINT"
sudo chown ec2-user:ec2-user "$MOUNT_POINT"

# Add the EFS entry to /etc/fstab for automatic mounting
echo "$clixx_file_system_id.efs.$REGION.amazonaws.com:/ $MOUNT_POINT nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,_netdev 0 0" | sudo tee -a /etc/fstab

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
sed -i "s/database_name_here/${{DB_NAME}}/; s/username_here/${{DB_USER}}/; s/password_here/${{DB_USER_PASSWORD}}/; s/localhost/${{DB_HOST}}/" wp-config.php

# Add HTTPS enforcement
sudo sed -i "81i if (isset(\$_SERVER['HTTP_X_FORWARDED_PROTO']) && \$_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {{ \$_SERVER['HTTPS'] = 'on'; }}" wp-config.php

# Set WordPress options using RECORD_NAME
if [ -n "$RECORD_NAME" ]; then
    mysql -u $DB_USER -p$DB_USER_PASSWORD -h $DB_HOST -D $DB_NAME -e "
        UPDATE wp_options SET option_value='https://${{RECORD_NAME}}' WHERE option_name='home';
        UPDATE wp_options SET option_value='https://${{RECORD_NAME}}' WHERE option_name='siteurl';
        UPDATE wp_options SET option_value='https://${{RECORD_NAME}}' WHERE option_name='ping_sites';
        UPDATE wp_options SET option_value='https://${{RECORD_NAME}}' WHERE option_name='open_shop_header_retina_logo';
    "
    echo "WordPress options updated with RECORD_NAME: $RECORD_NAME"
else
    echo "RECORD_NAME variable is empty or not set, skipping WordPress options update."
fi

# Update Apache configuration to allow WordPress permalinks
sudo sed -i '151s/None/All/' /etc/httpd/conf/httpd.conf

# Adjust file and directory ownership and permissions
sudo chown -R apache /var/www
sudo chgrp -R apache /var/www
sudo chmod 2775 /var/www
find /var/www -type d -exec sudo chmod 2775 {{}} \;
find /var/www -type f -exec sudo chmod 0664 {{}} \;

# Restart and enable Apache
sudo systemctl restart httpd

# # WordPress Installation on EFS
# cd "$MOUNT_POINT"
# sudo wget https://wordpress.org/latest.tar.gz
# sudo tar -xzf latest.tar.gz
# sudo mv wordpress/* "$MOUNT_POINT"
# sudo rm -rf wordpress latest.tar.gz

# Set up WordPress configuration
sudo sed -i "s/database_name_here/$DB_NAME/; s/username_here/$DB_USER/; s/password_here/$DB_USER_PASSWORD/; s/localhost/$DB_HOST/" wp-config.php

# Adjust permissions for WordPress
sudo chown -R apache:apache "$MOUNT_POINT"
sudo find "$MOUNT_POINT" -type d -exec chmod 755 {{}} \;
sudo find "$MOUNT_POINT" -type f -exec chmod 644 {{}} \;

# Reload Apache
sudo systemctl restart httpd

# Log completion
echo "WordPress installation and configuration completed."
'''



    
    
    
    clixx_user_data_base64 = base64.b64encode(clixx_user_data_script.encode('utf-8')).decode('utf-8')

    clixx_launch_template_response = clixx_ec2_client.create_launch_template(
        LaunchTemplateName='CLIXX-LT',
        VersionDescription='Version 1',
        LaunchTemplateData={
            'ImageId': 'ami-00f251754ac5da7f0',  # Replace with your actual AMI ID
            'InstanceType': 't2.micro',
            'KeyName': 'bastionkey.pem',
            'UserData': clixx_user_data_base64,
            'NetworkInterfaces': [{
                'AssociatePublicIpAddress': False,
                'DeviceIndex': 0,
                'SubnetId': clixx_app_private_subnet_ids[0],
                'Groups': [mysql_db_sg_id]
            }]
        }
    )
    clixx_launch_template_id = clixx_launch_template_response['LaunchTemplate']['LaunchTemplateId']
    logger.info(f"Launch Template created with ID: {clixx_launch_template_id}")
except ClientError as e:
    logger.error(f"Failed to create Launch Template: {e}")

# --- Create Auto Scaling Group ---
try:
    clixx_autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName='CLIXX-ASG',
        LaunchTemplate={
            'LaunchTemplateId': clixx_launch_template_id,
            'Version': '1'
        },
        MinSize=1,
        MaxSize=3,
        DesiredCapacity=1,
        VPCZoneIdentifier=",".join(clixx_app_private_subnet_ids),
        TargetGroupARNs=[clixx_target_group_arn],
        Tags=[{
            'Key': 'Name',
            'Value': 'CLIXX',
            'PropagateAtLaunch': True
        }]
    )
    logger.info("Auto Scaling Group created successfully.")
except ClientError as e:
    logger.error(f"Failed to create Auto Scaling Group: {e}")

# --- Create Route 53 record for the load balancer ---
try:
    clixx_route53_response = clixx_route53_client.change_resource_record_sets(
        HostedZoneId='Z0881876FFUR3OKRNM20',  # Replace with your Hosted Zone ID
        ChangeBatch={
            'Comment': 'Create record for the CLIXX Load Balancer',
            'Changes': [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': 'dev.clixx-dasola.com',  # Replace with your desired record name
                        'Type': 'A',
                        'AliasTarget': {
                            'HostedZoneId': clixx_lb_response['LoadBalancers'][0]['CanonicalHostedZoneId'],
                            'DNSName': clixx_lb_response['LoadBalancers'][0]['DNSName'],
                            'EvaluateTargetHealth': False
                        }
                    }
                }
            ]
        }
    )
    logger.info("Route 53 record created successfully.")
except ClientError as e:
    logger.error(f"Failed to create Route 53 record: {e}")

# --- Complete the setup ---
logger.info("AWS infrastructure setup for CLIXX application completed successfully.")
