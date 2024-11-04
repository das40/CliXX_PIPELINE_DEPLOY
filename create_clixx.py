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

clixx_db_snapshot_identifier = "arn:aws:rds:us-east-1:619071313311:snapshot:wordpressdbclixx-snapshot"
clixx_db_instance_class = "db.m6gd.large"
clixx_db_username = "wordpressuser"
clixx_db_password = "W3lcome123"
clixx_ami_id = "ami-00f251754ac5da7f0"
clixx_instance_type = "t2.micro"
clixx_key_pair_name = "bastionkey.pem"
clixx_certificate_arn = "arn:aws:acm:us-east-1:619071313311:certificate/ed0a7048-b2f1-4ca7-835d-06d5cc51f805"
clixx_hosted_zone_id = "Z0881876FFUR3OKRNM20"
clixx_record_name = "dev.clixx-dasola.com"


# Function to create subnets and log status
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

# Variables for VPC and subnets
clixx_vpc_cidr_block = '10.0.0.0/16'
clixx_public_subnets_cidrs = ['10.0.1.0/24', '10.0.2.0/24']
clixx_private_subnets_cidrs_az1 = ['10.0.3.0/24', '10.0.4.0/24', '10.0.5.0/24', '10.0.6.0/24', '10.0.7.0/24']
clixx_private_subnets_cidrs_az2 = ['10.0.8.0/24', '10.0.9.0/24', '10.0.10.0/24', '10.0.11.0/24', '10.0.12.0/24']
clixx_region = 'us-east-1'
clixx_availability_zones = [f'{clixx_region}a', f'{clixx_region}b']

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

# Create public subnets
clixx_public_subnet_ids = []
for i, cidr in enumerate(clixx_public_subnets_cidrs):
    subnet_id = create_subnet(clixx_vpc_id, cidr, clixx_availability_zones[i], f'CLIXX-PublicSubnet-{i+1}')
    clixx_public_subnet_ids.append(subnet_id)

# Create private subnets for AZ1
clixx_private_subnet_ids_az1 = []
for i, cidr in enumerate(clixx_private_subnets_cidrs_az1):
    subnet_id = create_subnet(clixx_vpc_id, cidr, clixx_availability_zones[0], f'CLIXX-PrivateSubnet-AZ1-{i+1}')
    clixx_private_subnet_ids_az1.append(subnet_id)

# Create private subnets for AZ2
clixx_private_subnet_ids_az2 = []
for i, cidr in enumerate(clixx_private_subnets_cidrs_az2):
    subnet_id = create_subnet(clixx_vpc_id, cidr, clixx_availability_zones[1], f'CLIXX-PrivateSubnet-AZ2-{i+1}')
    clixx_private_subnet_ids_az2.append(subnet_id)

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

# Create an empty list to store NAT Gateway IDs
clixx_nat_gateway_ids = []

# Create NAT Gateways (one per public subnet)
for subnet_id in clixx_public_subnet_ids:
    eip = clixx_ec2_client.allocate_address(Domain='vpc')
    nat_gw_response = clixx_ec2_client.create_nat_gateway(
        SubnetId=subnet_id,
        AllocationId=eip['AllocationId']
    )
    nat_gw_id = nat_gw_response['NatGateway']['NatGatewayId']
    clixx_nat_gateway_ids.append(nat_gw_id)
    logger.info(f"NAT Gateway created: {nat_gw_id}")
    
    # Wait for the NAT Gateway to become available
    while True:
        nat_gw_status = clixx_ec2_client.describe_nat_gateways(NatGatewayIds=[nat_gw_id])
        state = nat_gw_status['NatGateways'][0]['State']
        if state == 'available':
            logger.info(f"NAT Gateway {nat_gw_id} is now available.")
            break
        else:
            logger.info(f"NAT Gateway {nat_gw_id} is currently in state '{state}'. Waiting for it to become available...")
            time.sleep(10)

# Create Route Tables and associate with subnets
# Public route table
clixx_pub_route_table = clixx_ec2_resource.create_route_table(VpcId=clixx_vpc_id)
clixx_ec2_client.create_tags(Resources=[clixx_pub_route_table.id], Tags=[{'Key': 'Name', 'Value': 'CLIXX-PublicRT'}])
logger.info(f"Public Route Table created: {clixx_pub_route_table.id}")

# Add route for Internet access through the Internet Gateway
clixx_pub_route_table.create_route(
    DestinationCidrBlock='0.0.0.0/0',
    GatewayId=clixx_igw_id
)
logger.info("Route to Internet Gateway added to the public route table.")

# Associate public subnets with the public route table
for subnet_id in clixx_public_subnet_ids:
    clixx_pub_route_table.associate_with_subnet(SubnetId=subnet_id)
    logger.info(f"Subnet {subnet_id} associated with Public Route Table")

# Create private route tables (one for each AZ) and associate with private subnets
for i, nat_gw_id in enumerate(clixx_nat_gateway_ids):
    clixx_priv_route_table = clixx_ec2_resource.create_route_table(VpcId=clixx_vpc_id)
    clixx_ec2_client.create_tags(Resources=[clixx_priv_route_table.id], Tags=[{'Key': 'Name', 'Value': f'CLIXX-PrivateRT-AZ{i+1}'}])
    logger.info(f"Private Route Table created: {clixx_priv_route_table.id}")

    # Add route to NAT Gateway for outbound Internet access
    clixx_priv_route_table.create_route(
        DestinationCidrBlock='0.0.0.0/0',
        NatGatewayId=nat_gw_id
    )
    logger.info(f"Route to NAT Gateway {nat_gw_id} added to Private Route Table {clixx_priv_route_table.id}")

    # Associate private subnets with the private route table
    private_subnet_ids = clixx_private_subnet_ids_az1 if i == 0 else clixx_private_subnet_ids_az2
    for subnet_id in private_subnet_ids:
        clixx_priv_route_table.associate_with_subnet(SubnetId=subnet_id)
        logger.info(f"Subnet {subnet_id} associated with Private Route Table AZ{i+1}")

logger.info("Route tables and associations created successfully.")

# Function to create a security group
def create_security_group(name, description, vpc_id, ingress_rules=None):
    sg = clixx_ec2_client.create_security_group(
        GroupName=name,
        Description=description,
        VpcId=vpc_id
    )
    clixx_ec2_client.create_tags(Resources=[sg['GroupId']], Tags=[{'Key': 'Name', 'Value': name}])
    logger.info(f"Security group '{name}' created with ID: {sg['GroupId']}")
    
    # Add ingress rules if provided
    if ingress_rules:
        clixx_ec2_client.authorize_security_group_ingress(
            GroupId=sg['GroupId'],
            IpPermissions=ingress_rules
        )
        logger.info(f"Ingress rules applied to security group '{name}'")
    
    return sg['GroupId']

# Create public security group

public_sg_id = create_security_group(
    'CLIXX-PublicSG',
    'Public security group for application servers',
    clixx_vpc_id,
    ingress_rules=[
        {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
        {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
        {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)

# Create private security group
private_sg_id = create_security_group(
    'CLIXX-PrivateSG',
    'Private security group for database and EFS access',
    clixx_vpc_id,
    ingress_rules=[
        {'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},
        {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]}
    ]
)
clixx_private_sg_id = private_sg_id  # Assign to ensure clixx_private_sg_id is defined globally


# Create DB Subnet Group if it does not exist
clixx_DBSubnetGroupName = 'CLIXXSTACKDBSUBNETGROUP'
all_private_subnet_ids = clixx_private_subnet_ids_az1 + clixx_private_subnet_ids_az2  # Combine all private subnets

try:
    clixx_rds_client.describe_db_subnet_groups(DBSubnetGroupName=clixx_DBSubnetGroupName)
    logger.info(f"DB Subnet Group '{clixx_DBSubnetGroupName}' already exists.")
except clixx_rds_client.exceptions.DBSubnetGroupNotFoundFault:
    logger.info(f"Creating DB Subnet Group '{clixx_DBSubnetGroupName}'.")
    clixx_response = clixx_rds_client.create_db_subnet_group(
        DBSubnetGroupName=clixx_DBSubnetGroupName,
        SubnetIds=all_private_subnet_ids,
        DBSubnetGroupDescription='My stack DB subnet group',
        Tags=[{'Key': 'Name', 'Value': 'CLIXXSTACKDBSUBNETGROUP'}]
    )
    logger.info(f"DB Subnet Group '{clixx_DBSubnetGroupName}' created successfully.")

# --- Check if the RDS snapshot is available ---
# Define the DB instance identifier
clixx_db_instance_identifier = 'wordpressdbclixx'  # Replace with your actual DB instance name

try:
    snapshot_response = clixx_rds_client.describe_db_snapshots(DBSnapshotIdentifier=clixx_db_snapshot_identifier)
    snapshot_status = snapshot_response['DBSnapshots'][0]['Status']
    if snapshot_status != 'available':
        logger.info(f"Snapshot '{clixx_db_snapshot_identifier}' is in '{snapshot_status}' state. Waiting for it to become 'available'...")
        while snapshot_status != 'available':
            time.sleep(30)  # Wait 30 seconds before checking again
            snapshot_response = clixx_rds_client.describe_db_snapshots(DBSnapshotIdentifier=clixx_db_snapshot_identifier)
            snapshot_status = snapshot_response['DBSnapshots'][0]['Status']
            logger.info(f"Snapshot '{clixx_db_snapshot_identifier}' current state: '{snapshot_status}'")
        logger.info(f"Snapshot '{clixx_db_snapshot_identifier}' is now 'available'. Proceeding with the restore.")
    else:
        logger.info(f"Snapshot '{clixx_db_snapshot_identifier}' is 'available'. Proceeding with the restore.")
except ClientError as e:
    logger.error(f"Failed to describe snapshot '{clixx_db_snapshot_identifier}': {e}")
    raise

# --- Restore RDS Instance from Snapshot ---
clixx_db_instances = clixx_rds_client.describe_db_instances()
clixx_db_instance_identifiers = [db['DBInstanceIdentifier'] for db in clixx_db_instances['DBInstances']]

if clixx_db_instance_identifier in clixx_db_instance_identifiers:
    clixx_instances = clixx_rds_client.describe_db_instances(DBInstanceIdentifier=clixx_db_instance_identifier)
    logger.info(f"DB Instance '{clixx_db_instance_identifier}' already exists. Details: {clixx_instances}")
else:
    logger.info(f"DB Instance '{clixx_db_instance_identifier}' not found. Restoring from snapshot...")
    try:
        clixx_response = clixx_rds_client.restore_db_instance_from_db_snapshot(
            DBInstanceIdentifier=clixx_db_instance_identifier,
            DBSnapshotIdentifier=clixx_db_snapshot_identifier,
            DBInstanceClass=clixx_db_instance_class,
            VpcSecurityGroupIds=[clixx_private_sg_id],
            DBSubnetGroupName=clixx_DBSubnetGroupName,
            PubliclyAccessible=False,
            Tags=[{'Key': 'Name', 'Value': 'wordpressdbclixx'}]
        )
        logger.info(f"Restore operation initiated. Response: {clixx_response}")
    except ClientError as e:
        logger.error(f"Failed to restore DB Instance '{clixx_db_instance_identifier}': {e}")
        raise

# --- Create EFS file system ---
clixx_efs_response = clixx_efs_client.describe_file_systems(
    CreationToken='CLiXX-EFS'
)

# If EFS exists, proceed with the existing EFS
if clixx_efs_response['FileSystems']:
    clixx_file_system_id = clixx_efs_response['FileSystems'][0]['FileSystemId']
    logger.info(f"EFS already exists with FileSystemId: {clixx_file_system_id}")
else:
    # Create EFS if it doesn't exist
    clixx_efs_response = clixx_efs_client.create_file_system(
        CreationToken='CLiXX-EFS',
        PerformanceMode='generalPurpose',
        Tags=[{'Key': 'Name', 'Value': 'CLiXX-EFS'}]
    )
    clixx_file_system_id = clixx_efs_response['FileSystemId']
    logger.info(f"EFS created with FileSystemId: {clixx_file_system_id}")
    # Wait for EFS to become available
    while True:
        clixx_efs_info = clixx_efs_client.describe_file_systems(
            FileSystemId=clixx_file_system_id
        )
        lifecycle_state = clixx_efs_info['FileSystems'][0]['LifeCycleState']
        if lifecycle_state == 'available':
            logger.info(f"EFS CLiXX-EFS is now available with FileSystemId: {clixx_file_system_id}")
            break
        else:
            logger.info(f"EFS is in '{lifecycle_state}' state. Waiting for it to become available...")
            time.sleep(10)

# Add a tag to the EFS file system
clixx_efs_client.create_tags(FileSystemId=clixx_file_system_id, Tags=[{'Key': 'Name', 'Value': 'CLiXX-EFS'}])

# Create mount targets for private subnets
for subnet_id in clixx_private_subnet_ids_az1 + clixx_private_subnet_ids_az2:
    # Check if mount target already exists for the subnet
    clixx_mount_targets_response = clixx_efs_client.describe_mount_targets(
        FileSystemId=clixx_file_system_id
    )
    existing_mount_targets = [mt['SubnetId'] for mt in clixx_mount_targets_response['MountTargets']]
    if subnet_id not in existing_mount_targets:
        try:
            clixx_mount_target_response = clixx_efs_client.create_mount_target(
                FileSystemId=clixx_file_system_id,
                SubnetId=subnet_id,
                SecurityGroups=[clixx_private_sg_id]
            )
            logger.info(f"Mount target created in Private Subnet: {subnet_id}")
        except ClientError as e:
            logger.error(f"Failed to create mount target for subnet {subnet_id}: {e}")
    else:
        logger.info(f"Mount target already exists in Private Subnet: {subnet_id}")

# Apply lifecycle policy to EFS for automatic data transition
clixx_efs_client.put_lifecycle_configuration(
    FileSystemId=clixx_file_system_id,
    LifecyclePolicies=[
        {'TransitionToIA': 'AFTER_30_DAYS'},
        {'TransitionToPrimaryStorageClass': 'AFTER_1_ACCESS'}
    ]
)
logger.info("Lifecycle policy applied to EFS.")

# Deploy Bastion Host in Public Subnet
bastion_instance = clixx_ec2_resource.create_instances(
    ImageId='ami-00f251754ac5da7f0',  # Replace with the latest Linux AMI ID
    InstanceType='t2.micro',
    KeyName='bastionkey.pem',
    MinCount=1,
    MaxCount=1,
    NetworkInterfaces=[
        {
            'SubnetId': clixx_public_subnet_ids[0],
            'DeviceIndex': 0,
            'AssociatePublicIpAddress': True,
            'Groups': [public_sg_id]
        }
    ],
    TagSpecifications=[
        {
            'ResourceType': 'instance',
            'Tags': [{'Key': 'Name', 'Value': 'CLIXX-BastionHost'}]
        }
    ]
)
logger.info(f"Bastion host deployed: Instance ID {bastion_instance[0].id}")




# --- Create Target Group ---
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

# --- Create Application Load Balancer ---
clixx_lb_response = clixx_elbv2_client.create_load_balancer(
    Name='CLIXX-LoadBalancer',
    Subnets=clixx_public_subnet_ids,
    SecurityGroups=[clixx_public_sg_id],  # Ensure this is defined earlier
    Scheme='internet-facing',
    Type='application',
    IpAddressType='ipv4',
    Tags=[{'Key': 'Name', 'Value': 'CLIXX-LoadBalancer'}]
)
clixx_lb_arn = clixx_lb_response['LoadBalancers'][0]['LoadBalancerArn']
logger.info(f"Load Balancer created with ARN: {clixx_lb_arn}")

# Create Route 53 record for the load balancer
clixx_hosted_zone_id = 'Z0881876FFUR3OKRNM20'  # Replace with your hosted zone ID
clixx_record_name = 'dev.clixx-dasola.com'  # Replace with your desired record name

try:
    clixx_route53_response = clixx_route53_client.change_resource_record_sets(
        HostedZoneId=clixx_hosted_zone_id,
        ChangeBatch={
            'Comment': 'Create record for the CLiXX Load Balancer',
            'Changes': [
                {
                    'Action': 'CREATE',
                    'ResourceRecordSet': {
                        'Name': clixx_record_name,
                        'Type': 'A',
                        'AliasTarget': {
                            'HostedZoneId': clixx_load_balancer['LoadBalancers'][0]['CanonicalHostedZoneId'],
                            'DNSName': clixx_load_balancer['LoadBalancers'][0]['DNSName'],
                            'EvaluateTargetHealth': False
                        }
                    }
                }
            ]
        }
    )
    logger.info(f"Route 53 record created for {clixx_record_name}")
except ClientError as e:
    logger.error(f"Failed to create Route 53 record: {e}")

# Encode the user data to Base64
# Encode the user data to Base64
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

# --- Create Launch Template ---
# List all launch templates and check for 'CLiXX-LT'
# Assign the first public subnet ID to clixx_subnet_1_id
clixx_subnet_1_id = clixx_public_subnet_ids[0]

# Assign the public security group ID to clixx_public_sg_id
clixx_public_sg_id = public_sg_id

clixx_all_lt_response = clixx_ec2_client.describe_launch_templates()
clixx_launch_template_names = [lt['LaunchTemplateName'] for lt in clixx_all_lt_response['LaunchTemplates']]

if 'CLiXX-LT' in clixx_launch_template_names:
    # Get the ID of the existing launch template
    clixx_launch_template_id = next(lt['LaunchTemplateId'] for lt in clixx_all_lt_response['LaunchTemplates'] if lt['LaunchTemplateName'] == 'CLiXX-LT')
    logger.info(f"Launch Template already exists with ID: {clixx_launch_template_id}")
else:
    # Create a new launch template since it doesn't exist
    clixx_launch_template = clixx_ec2_client.create_launch_template(
        LaunchTemplateName='CLiXX-LT',
        VersionDescription='Version 1',
        LaunchTemplateData={
            'ImageId': clixx_ami_id,  
            'InstanceType': clixx_instance_type,  
            'KeyName': clixx_key_pair_name,  
            'UserData': clixx_user_data_base64,  
            'IamInstanceProfile': {
                'Name': 'EC2-Admin'  
            },
            'NetworkInterfaces': [{
                'AssociatePublicIpAddress': True,
                'DeviceIndex': 0,
                'SubnetId': clixx_subnet_1_id,
                'Groups': [clixx_public_sg.id]
            }]
        }
    )
    clixx_launch_template_id = clixx_launch_template['LaunchTemplate']['LaunchTemplateId']
    logger.info(f"Launch Template created with ID: {clixx_launch_template_id}")

# --- Create Auto Scaling Group ---
# List all Auto Scaling Groups and check for 'CLiXX-ASG'
clixx_all_asg_response = clixx_autoscaling_client.describe_auto_scaling_groups()
clixx_asg_names = [asg['AutoScalingGroupName'] for asg in clixx_all_asg_response['AutoScalingGroups']]
if 'CLiXX-ASG' in clixx_asg_names:
    logger.info("Auto Scaling Group already exists.")
else:
    # Create a new Auto Scaling Group since it doesn't exist
    clixx_autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName='CLiXX-ASG',
        LaunchTemplate={
            'LaunchTemplateId': clixx_launch_template_id, 
            'Version': '1'
        },
        MinSize=1,
        MaxSize=3,
        DesiredCapacity=1,
        VPCZoneIdentifier=clixx_subnet_1_id,
        TargetGroupARNs=[clixx_target_group_arn], 
        Tags=[
            {
                'Key': 'Name',
                'Value': 'CLiXX',
                'PropagateAtLaunch': True
            }
        ]
    )
    logger.info("Auto Scaling Group created successfully.")
