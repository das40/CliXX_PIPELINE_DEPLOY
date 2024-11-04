import boto3
import logging
import time, base64, time
from botocore.exceptions import ClientError

# Set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Assume role (already part of your existing code)
sts_client = boto3.client('sts')
assumed_role_object = sts_client.assume_role(
    RoleArn='arn:aws:iam::619071313311:role/Engineer',
    RoleSessionName='mysession'
)
credentials = assumed_role_object['Credentials']

# Create clients with assumed role credentials
ec2_client = boto3.client('ec2', region_name='us-east-1',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'])
ec2_resource = boto3.resource('ec2', region_name='us-east-1',
                               aws_access_key_id=credentials['AccessKeyId'],
                               aws_secret_access_key=credentials['SecretAccessKey'],
                               aws_session_token=credentials['SessionToken'])

# Function to create subnets and log status
def create_subnet(vpc_id, cidr_block, az, name_tag):
    response = ec2_client.create_subnet(
        VpcId=vpc_id,
        CidrBlock=cidr_block,
        AvailabilityZone=az
    )
    subnet_id = response['Subnet']['SubnetId']
    ec2_client.create_tags(Resources=[subnet_id], Tags=[{'Key': 'Name', 'Value': name_tag}])
    logger.info(f"Subnet {name_tag} created: {subnet_id}")
    return subnet_id

# Variables for VPC and subnets
vpc_cidr_block = '10.0.0.0/16'
public_subnets_cidrs = ['10.0.1.0/24', '10.0.2.0/24']
private_subnets_cidrs_az1 = ['10.0.3.0/24', '10.0.4.0/24', '10.0.5.0/24', '10.0.6.0/24', '10.0.7.0/24']
private_subnets_cidrs_az2 = ['10.0.8.0/24', '10.0.9.0/24', '10.0.10.0/24', '10.0.11.0/24', '10.0.12.0/24']
region = 'us-east-1'
availability_zones = [f'{region}a', f'{region}b']

# Create VPC (if not already created)
vpcs = ec2_client.describe_vpcs(Filters=[{'Name': 'cidr', 'Values': [vpc_cidr_block]}])
if not vpcs['Vpcs']:
    vpc = ec2_resource.create_vpc(CidrBlock=vpc_cidr_block)
    ec2_client.create_tags(Resources=[vpc.id], Tags=[{'Key': 'Name', 'Value': 'CLIXXSTACKVPC'}])
    ec2_client.modify_vpc_attribute(VpcId=vpc.id, EnableDnsSupport={'Value': True})
    ec2_client.modify_vpc_attribute(VpcId=vpc.id, EnableDnsHostnames={'Value': True})
    logger.info(f"VPC created: {vpc.id}")
    vpc_id = vpc.id
else:
    vpc_id = vpcs['Vpcs'][0]['VpcId']
    logger.info(f"VPC already exists: {vpc_id}")

# Create public subnets
public_subnet_ids = []
for i, cidr in enumerate(public_subnets_cidrs):
    subnet_id = create_subnet(vpc_id, cidr, availability_zones[i], f'CLIXX-PublicSubnet-{i+1}')
    public_subnet_ids.append(subnet_id)

# Create private subnets for AZ1
private_subnet_ids_az1 = []
for i, cidr in enumerate(private_subnets_cidrs_az1):
    subnet_id = create_subnet(vpc_id, cidr, availability_zones[0], f'CLIXX-PrivateSubnet-AZ1-{i+1}')
    private_subnet_ids_az1.append(subnet_id)

# Create private subnets for AZ2
private_subnet_ids_az2 = []
for i, cidr in enumerate(private_subnets_cidrs_az2):
    subnet_id = create_subnet(vpc_id, cidr, availability_zones[1], f'CLIXX-PrivateSubnet-AZ2-{i+1}')
    private_subnet_ids_az2.append(subnet_id)

# Create Internet Gateway
igw_response = ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
if not igw_response['InternetGateways']:
    igw = ec2_resource.create_internet_gateway()
    ec2_client.attach_internet_gateway(VpcId=vpc_id, InternetGatewayId=igw.id)
    ec2_client.create_tags(Resources=[igw.id], Tags=[{'Key': 'Name', 'Value': 'CLIXXSTACKIGW'}])
    logger.info(f"Internet Gateway created: {igw.id}")
    igw_id = igw.id
else:
    igw_id = igw_response['InternetGateways'][0]['InternetGatewayId']
    logger.info(f"Internet Gateway already exists: {igw_id}")

# Create NAT Gateways (one per public subnet)
nat_gateway_ids = []
for subnet_id in public_subnet_ids:
    eip = ec2_client.allocate_address(Domain='vpc')
    nat_gw_response = ec2_client.create_nat_gateway(
        SubnetId=subnet_id,
        AllocationId=eip['AllocationId']
    )
    nat_gw_id = nat_gw_response['NatGateway']['NatGatewayId']
    nat_gateway_ids.append(nat_gw_id)
    logger.info(f"NAT Gateway created: {nat_gw_id}")
    time.sleep(10)  # Wait for NAT Gateway to be provisioned

# Create Route Tables and associate with subnets
# Public route table
pub_route_table = ec2_resource.create_route_table(VpcId=vpc_id)
ec2_client.create_tags(Resources=[pub_route_table.id], Tags=[{'Key': 'Name', 'Value': 'CLIXX-PublicRT'}])
logger.info(f"Public Route Table created: {pub_route_table.id}")
pub_route_table.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=igw_id)

for subnet_id in public_subnet_ids:
    pub_route_table.associate_with_subnet(SubnetId=subnet_id)
    logger.info(f"Subnet {subnet_id} associated with Public Route Table")

# Private route tables (one for each AZ)
for i, nat_gw_id in enumerate(nat_gateway_ids):
    priv_route_table = ec2_resource.create_route_table(VpcId=vpc_id)
    ec2_client.create_tags(Resources=[priv_route_table.id], Tags=[{'Key': 'Name', 'Value': f'CLIXX-PrivateRT-AZ{i+1}'}])
    logger.info(f"Private Route Table created: {priv_route_table.id}")
    priv_route_table.create_route(DestinationCidrBlock='0.0.0.0/0', NatGatewayId=nat_gw_id)
    
    private_subnet_ids = private_subnet_ids_az1 if i == 0 else private_subnet_ids_az2
    for subnet_id in private_subnet_ids:
        priv_route_table.associate_with_subnet(SubnetId=subnet_id)
        logger.info(f"Subnet {subnet_id} associated with Private Route Table AZ{i+1}")

logger.info("VPC, subnets, route tables, and NAT Gateways created successfully.")


# --- Security Groups and Additional Components ---

# Function to create a security group
def create_security_group(name, description, vpc_id, ingress_rules=None):
    sg = ec2_client.create_security_group(
        GroupName=name,
        Description=description,
        VpcId=vpc_id
    )
    ec2_client.create_tags(Resources=[sg['GroupId']], Tags=[{'Key': 'Name', 'Value': name}])
    logger.info(f"Security group '{name}' created with ID: {sg['GroupId']}")
    
    # Add ingress rules if provided
    if ingress_rules:
        ec2_client.authorize_security_group_ingress(
            GroupId=sg['GroupId'],
            IpPermissions=ingress_rules
        )
        logger.info(f"Ingress rules applied to security group '{name}'")
    
    return sg['GroupId']

# Create public security group (e.g., for bastion and load balancer)
public_sg_id = create_security_group(
    'CLIXX-PublicSG',
    'Public security group for bastion and load balancer',
    vpc_id,
    ingress_rules=[
        {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},
            {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},
            {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
        ]
)

# Create private security group (e.g., for application and database servers)
private_sg_id = create_security_group(
    'CLIXX-PrivateSG',
    'Private security group for application and database servers',
    vpc_id,
    ingress_rules=[
        {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},
        {'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},
        {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]}
    ]
)

logger.info("Security groups created and configured.")
# --- RDS Subnet Group ---
clixx_DBSubnetGroupName = 'CLIXXSTACKDBSUBNETGROUP'
clixx_response = clixx_rds_client.describe_db_subnet_groups()
clixx_db_subnet_group_exists = False

for clixx_subnet_group in clixx_response['DBSubnetGroups']:
    if clixx_subnet_group['DBSubnetGroupName'] == clixx_DBSubnetGroupName:
        clixx_db_subnet_group_exists = True
        clixx_DBSubnetGroupName = clixx_subnet_group['DBSubnetGroupName']
        logger.info(f"DB Subnet Group '{clixx_DBSubnetGroupName}' already exists. Proceeding with the existing one.")
        break

if not clixx_db_subnet_group_exists:
    clixx_response = clixx_rds_client.create_db_subnet_group(
        DBSubnetGroupName=clixx_DBSubnetGroupName,
        SubnetIds=[clixx_private_subnet_1_id, clixx_private_subnet_2_id],
        DBSubnetGroupDescription='My stack DB subnet group',
        Tags=[{'Key': 'Name', 'Value': 'CLIXXSTACKDBSUBNETGROUP'}]
    )
    clixx_DBSubnetGroupName = clixx_response['DBSubnetGroup']['DBSubnetGroupName']
    logger.info(f"DB Subnet Group '{clixx_DBSubnetGroupName}' created successfully.")

# --- Check if the RDS snapshot is available ---
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

# --- Deploy Bastion Host in Public Subnet ---
bastion_instance = ec2_resource.create_instances(
    ImageId='ami-00f251754ac5da7f0',  # Replace with the latest Linux AMI ID
    InstanceType='t2.micro',
    KeyName='bastionkey.pem',
    MinCount=1,
    MaxCount=1,
    NetworkInterfaces=[
        {
            'SubnetId': public_subnet_ids[0],
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



# --- Create Load Balancer ---
elb_client = boto3.client('elbv2', region_name='us-east-1',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'])

lb_response = elb_client.create_load_balancer(
    Name='CLIXX-LoadBalancer',
    Subnets=public_subnet_ids,
    SecurityGroups=[public_sg_id],
    Scheme='internet-facing',
    Type='application',
    IpAddressType='ipv4',
    Tags=[
        {'Key': 'Name', 'Value': 'CLIXX-LoadBalancer'}
    ]
)
logger.info(f"Load Balancer created with ARN: {lb_response['LoadBalancers'][0]['LoadBalancerArn']}")

logger.info("Deployment of VPC, subnets, route tables, security groups, bastion host, and load balancer completed.")

# --- Security Groups and Additional Components ---

# Create EFS file system
efs_client = boto3.client('efs', region_name='us-east-1',
                         aws_access_key_id=credentials['AccessKeyId'],
                         aws_secret_access_key=credentials['SecretAccessKey'],
                         aws_session_token=credentials['SessionToken'])

efs_response = efs_client.create_file_system(
    CreationToken='CLIXX-EFS-Token',
    PerformanceMode='generalPurpose',
    Tags=[{'Key': 'Name', 'Value': 'CLIXX-EFS'}]
)
efs_id = efs_response['FileSystemId']
logger.info(f"EFS created with ID: {efs_id}")

# Wait for EFS to be in 'available' state
while True:
    clixx_efs_info = clixx_efs_client.describe_file_systems(FileSystemId=clixx_file_system_id)
    lifecycle_state = clixx_efs_info['FileSystems'][0]['LifeCycleState']
    if lifecycle_state == 'available':
        logger.info(f"EFS CLiXX-EFS is now available with FileSystemId: {clixx_file_system_id}")
        break
    else:
        logger.info(f"EFS is in '{lifecycle_state}' state. Waiting for it to become available...")
        time.sleep(10)


# Create mount targets for each private subnet
for subnet_id in private_subnet_ids_az1[:2]:  # Adjust the range or subnets as necessary
    try:
        efs_client.create_mount_target(
            FileSystemId=efs_id,
            SubnetId=subnet_id,
            SecurityGroups=[private_sg_id]
        )
        logger.info(f"Mount target created for EFS {efs_id} in subnet {subnet_id}")
    except ClientError as e:
        logger.error(f"Failed to create mount target for subnet {subnet_id}: {e}")

for subnet_id in private_subnet_ids_az2[:2]:  # Adjust the range or subnets as necessary
    try:
        efs_client.create_mount_target(
            FileSystemId=efs_id,
            SubnetId=subnet_id,
            SecurityGroups=[private_sg_id]
        )
        logger.info(f"Mount target created for EFS {efs_id} in subnet {subnet_id}")
    except ClientError as e:
        logger.error(f"Failed to create mount target for subnet {subnet_id}: {e}")

# Apply lifecycle policy to EFS for automatic data transition
efs_client.put_lifecycle_configuration(
    FileSystemId=efs_id,
    LifecyclePolicies=[
        {'TransitionToIA': 'AFTER_30_DAYS'},
        {'TransitionToPrimaryStorageClass': 'AFTER_1_ACCESS'}
    ]
)
logger.info("Lifecycle policy applied to EFS.")



# --- Create Route 53 Record ---
route53_response = route53_client.change_resource_record_sets(
    HostedZoneId=hosted_zone_id,
    ChangeBatch={
        'Comment': 'Create record for Load Balancer',
        'Changes': [
            {
                'Action': 'CREATE',
                'ResourceRecordSet': {
                    'Name': 'dev.clixx-dasola.com',
                    'Type': 'A',
                    'AliasTarget': {
                        'HostedZoneId': lb_response['LoadBalancers'][0]['CanonicalHostedZoneId'],
                        'DNSName': lb_response['LoadBalancers'][0]['DNSName'],
                        'EvaluateTargetHealth': False
                    }
                }
            }
        ]
    }
)
logger.info("Route 53 record created for dev.clixx-dasola.com")

# --- Create Target Group ---
tg_response = elb_client.create_target_group(
    Name='CLIXX-TG',
    Protocol='HTTP',
    Port=80,
    VpcId=vpc_id,
    HealthCheckProtocol='HTTP',
    HealthCheckPath='/',
    TargetType='instance',
    Tags=[{'Key': 'Name', 'Value': 'CLIXX-TG'}]
)
tg_arn = tg_response['TargetGroups'][0]['TargetGroupArn']
logger.info(f"Target Group created with ARN: {tg_arn}")


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
