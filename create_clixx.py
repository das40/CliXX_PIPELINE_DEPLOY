import boto3
from botocore.exceptions import ClientError

session = boto3.Session(
    aws_access_key_id=credentials['AccessKeyId'],
    aws_secret_access_key=credentials['SecretAccessKey'],
    aws_session_token=credentials['SessionToken'],
    region_name=AWS_REGION

# Initialize the boto3 clients
ec2_client = boto3.client('ec2')
rds_client = boto3.client('rds')
autoscaling_client = boto3.client('autoscaling')
elb_client = boto3.client('elbv2')
efs_client = boto3.client('efs')

AWS_REGION = 'us-east-1'
sts_client = boto3.client('sts')

# Assuming a role
assumed_role_object = sts_client.assume_role(RoleArn='arn:aws:iam::619071313311:role/Engineer', RoleSessionName='mysession')
credentials = assumed_role_object['Credentials']

# Step 1: Create a VPC
def create_vpc(cidr_block):
    response = ec2_client.create_vpc(CidrBlock=cidr_block, AmazonProvidedIpv6CidrBlock=False)
    vpc_id = response['Vpc']['VpcId']
    print(f"VPC created with VPC ID: {vpc_id}")
    return vpc_id

# Step 2: Create Private Subnet
def create_private_subnet(vpc_id, cidr_block, availability_zone):
    response = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=cidr_block, AvailabilityZone=availability_zone)
    subnet_id = response['Subnet']['SubnetId']
    print(f"Private subnet created with ID: {subnet_id}")
    return subnet_id

# Step 3: Create Security Group
def create_security_group(vpc_id, group_name, description):
    try:
        response = ec2_client.create_security_group(GroupName=group_name, Description=description, VpcId=vpc_id)
        security_group_id = response['GroupId']
        print(f'Security group {group_name} created with ID: {security_group_id}')
        return security_group_id
    except ClientError as e:
        print(f'Error creating security group: {e}')

# Step 4: Create an Internet Gateway and attach to VPC
def create_internet_gateway(vpc_id):
    igw_response = ec2_client.create_internet_gateway()
    igw_id = igw_response['InternetGateway']['InternetGatewayId']
    ec2_client.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    print(f"Internet Gateway {igw_id} attached to VPC {vpc_id}")
    return igw_id

# Step 5: Create a Route Table and associate with a private subnet
def create_route_table(vpc_id, igw_id, subnet_id):
    route_table_response = ec2_client.create_route_table(VpcId=vpc_id)
    rt_id = route_table_response['RouteTable']['RouteTableId']
    ec2_client.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ec2_client.associate_route_table(SubnetId=subnet_id, RouteTableId=rt_id)
    print(f"Route table {rt_id} created and associated with subnet {subnet_id}")
    return rt_id

def create_efs(file_system_name, vpc_id):
    response = efs_client.create_file_system(
        CreationToken=file_system_name,
        PerformanceMode='generalPurpose',
        Encrypted=True
    )
    
    # Retrieve the File System ID from the response
    efs_id = response['FileSystemId']
    print(f"EFS created with File System ID: {efs_id}")

    # Create mount targets for the EFS in the specified VPC
    subnet_ids = get_private_subnet_ids(vpc_id)
    for subnet_id in subnet_ids:
        mount_response = efs_client.create_mount_target(FileSystemId=efs_id, SubnetId=subnet_id)
        print(f"Mount target created for EFS in subnet {subnet_id}: {mount_response['MountTargetId']}")
    
    return efs_id



def get_private_subnet_ids(vpc_id):
    response = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'tag:Type', 'Values': ['private']}])
    return [subnet['SubnetId'] for subnet in response['Subnets']]

# Step 7: Create a Launch Template
def create_launch_template(template_name, instance_type, security_group_id):
    response = ec2_client.create_launch_template(
        LaunchTemplateName=template_name,
        LaunchTemplateData={
            'InstanceType': instance_type,
            'SecurityGroupIds': [security_group_id],
            'UserData': user_data_script
        }
    )
    launch_template_id = response['LaunchTemplate']['LaunchTemplateId']
    print(f"Launch Template {template_name} created with ID: {launch_template_id}")
    return launch_template_id

# Step 8: Create an RDS Instance (Restored from Snapshot)
def create_rds_instance(db_identifier, db_snapshot_arn, db_subnet_group_name, vpc_security_group_ids):
    try:
        response = rds_client.restore_db_instance_from_db_snapshot(
            DBInstanceIdentifier=db_identifier,
            DBSnapshotIdentifier=db_snapshot_arn,
            DBInstanceClass='db.t3.micro',
            DBSubnetGroupName=db_subnet_group_name,
            VpcSecurityGroupIds=vpc_security_group_ids,
            PubliclyAccessible=False,
            MultiAZ=False
        )
        print(f"RDS instance {db_identifier} restored from snapshot.")
        return response
    except ClientError as e:
        print(f"Error restoring RDS instance: {e.response['Error']['Message']}")

# Step 9: Create a Target Group
def create_target_group(vpc_id, target_group_name, protocol='HTTP', port=80):
    response = elb_client.create_target_group(
        Name=target_group_name,
        Protocol=protocol,
        Port=port,
        VpcId=vpc_id,
        HealthCheckProtocol=protocol,
        HealthCheckPort=str(port),
        HealthCheckPath='/index.php',
        HealthCheckIntervalSeconds=30,
        HealthCheckTimeoutSeconds=5,
        HealthyThresholdCount=5,
        UnhealthyThresholdCount=2,
        TargetType='instance'
    )
    tg_arn = response['TargetGroups'][0]['TargetGroupArn']
    print(f"Target Group {target_group_name} created with ARN: {tg_arn}")
    return tg_arn

# Step 10: Create an Application Load Balancer
def create_load_balancer(subnets, security_groups, lb_name):
    response = elb_client.create_load_balancer(
        Name=lb_name,
        Subnets=subnets,
        SecurityGroups=security_groups,
        Scheme='internet-facing',
        Type='application',
        IpAddressType='ipv4'
    )
    lb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
    print(f"Load Balancer {lb_name} created with ARN: {lb_arn}")
    return lb_arn

# Step 11: Create a Listener for the Load Balancer
def create_https_listener(lb_arn, target_group_arn, certificate_arn):
    response = elb_client.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol='HTTPS',
        Port=443,
        SslPolicy='ELBSecurityPolicy-2016-08',
        Certificates=[{'CertificateArn': certificate_arn}],
        DefaultActions=[{
            'Type': 'forward',
            'TargetGroupArn': target_group_arn
        }]
    )
    
    listener_arn = response['Listeners'][0]['ListenerArn']
    print(f"HTTPS Listener created for Load Balancer with ARN: {listener_arn}")
    return listener_arn

# Step 12: Create an Auto Scaling Group
def create_autoscaling_group(launch_template_id, autoscaling_group_name, subnet_ids, target_group_arn):
    response = autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName=autoscaling_group_name,
        LaunchTemplate={'LaunchTemplateId': launch_template_id},
        MinSize=2,
        MaxSize=5,
        DesiredCapacity=3,
        VPCZoneIdentifier=','.join(subnet_ids),
        HealthCheckType='EC2',
        HealthCheckGracePeriod=300,
        TargetGroupARNs=[target_group_arn]
    )
    print(f"Auto Scaling Group {autoscaling_group_name} created.")
    return response

# User Data Script
user_data_script = """#!/bin/bash -x
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

"""

# Main Execution
vpc_id = create_vpc('10.0.0.0/16')
private_subnet_id = create_private_subnet(vpc_id, '10.0.1.0/24', 'us-east-1a')
security_group_id = create_security_group(vpc_id, 'clixx-security-group', 'Security group for clixx application')
igw_id = create_internet_gateway(vpc_id)
route_table_id = create_route_table(vpc_id, igw_id, private_subnet_id)

# Creating EFS
efs_id = create_efs('clixx-efs', vpc_id)

# Creating RDS instance
rds_instance_id = create_rds_instance('clixx-db-instance', 'arn:aws:rds:us-east-1:123456789012:snapshot:mydbsnapshot', 'clixx-db-subnet-group', [security_group_id])

# Creating Launch Template
launch_template_id = create_launch_template('clixx-launch-template', 't2.micro', security_group_id)

# Creating Load Balancer and related components
target_group_arn = create_target_group(vpc_id, 'clixx-target-group')
load_balancer_arn = create_load_balancer([private_subnet_id], [security_group_id], 'clixx-load-balancer')
listener_arn = create_https_listener(load_balancer_arn, target_group_arn, 'arn:aws:acm:us-east-1:123456789012:certificate/my-certificate')

# Creating Auto Scaling Group
create_autoscaling_group(launch_template_id, 'clixx-autoscaling-group', [private_subnet_id], target_group_arn)
