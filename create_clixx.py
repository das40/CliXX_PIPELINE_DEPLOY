import boto3
from botocore.exceptions import ClientError

# Initialize the boto3 clients
ec2_client = boto3.client('ec2')
rds_client = boto3.client('rds')
autoscaling_client = boto3.client('autoscaling')
elb_client = boto3.client('elbv2')

# Step 2: Create a VPC
def create_vpc(cidr_block):
    response = ec2_client.create_vpc(
        CidrBlock=cidr_block,
        AmazonProvidedIpv6CidrBlock=False
    )
    vpc_id = response['Vpc']['VpcId']
    print(f"VPC created with VPC ID: {vpc_id}")
    return vpc_id

# Step 3: Create Subnets
def create_subnet(vpc_id, cidr_block, availability_zone, public_ip=False):
    response = ec2_client.create_subnet(
        VpcId=vpc_id,
        CidrBlock=cidr_block,
        AvailabilityZone=availability_zone
    )
    
    subnet_id = response['Subnet']['SubnetId']
    
    if public_ip:
        ec2_client.modify_subnet_attribute(
            SubnetId=subnet_id,
            MapPublicIpOnLaunch={'Value': True}
        )
    
    return subnet_id

# Step 4: Create Security Group
def create_security_group(vpc_id, group_name, description):
    try:
        response = ec2_client.create_security_group(GroupName=group_name, Description=description, VpcId=vpc_id)
        security_group_id = response['GroupId']
        print(f'Security group {group_name} created with ID: {security_group_id}')
        
        # Check existing egress rules
        existing_rules = ec2_client.describe_security_groups(GroupIds=[security_group_id])['SecurityGroups'][0]['IpPermissionsEgress']
        
        # If there are no egress rules or the specific rule doesn't exist, add it
        if not any(rule['IpProtocol'] == '-1' and any(ip['CidrIp'] == '0.0.0.0/0' for ip in rule['IpRanges']) for rule in existing_rules):
            ec2_client.authorize_security_group_egress(
                GroupId=security_group_id,
                IpPermissions=[{
                    'IpProtocol': '-1',  # All traffic
                    'FromPort': 0,
                    'ToPort': 65535,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )
            print(f'Egress rule added to security group {group_name}.')
        else:
            print(f'Egress rule already exists for security group {group_name}.')
        
        return security_group_id

    except ClientError as e:
        print(f'Error creating security group: {e}')

# Step 5: Create an Internet Gateway and attach to VPC
def create_internet_gateway(vpc_id):
    igw_response = ec2_client.create_internet_gateway()
    igw_id = igw_response['InternetGateway']['InternetGatewayId']
    
    ec2_client.attach_internet_gateway(
        InternetGatewayId=igw_id,
        VpcId=vpc_id
    )
    print(f"Internet Gateway {igw_id} attached to VPC {vpc_id}")
    return igw_id

# Step 6: Create a Route Table and associate with a subnet
def create_route_table(vpc_id, igw_id, subnet_id):
    route_table_response = ec2_client.create_route_table(VpcId=vpc_id)
    rt_id = route_table_response['RouteTable']['RouteTableId']
    
    # Create route for all traffic to go to the Internet Gateway
    ec2_client.create_route(
        RouteTableId=rt_id,
        DestinationCidrBlock="0.0.0.0/0",
        GatewayId=igw_id
    )
    
    # Associate the route table with the subnet
    ec2_client.associate_route_table(
        SubnetId=subnet_id,
        RouteTableId=rt_id
    )
    
    print(f"Route table {rt_id} created and associated with subnet {subnet_id}")
    return rt_id

# Step 7: Create an RDS Instance (Restored from Snapshot)
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

# Step 8: Create a Target Group
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

# Step 9: Create an Application Load Balancer
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

# Step 10: Create a Listener for the Load Balancer
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

# Step 11: Create an Auto Scaling Group
def create_autoscaling_group(launch_config_name, autoscaling_group_name, subnets, target_group_arn):
    response = autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName=autoscaling_group_name,
        LaunchConfigurationName=launch_config_name,
        MinSize=2,
        MaxSize=5,
        DesiredCapacity=3,
        VPCZoneIdentifier=','.join(subnets),
        HealthCheckType='EC2',
        HealthCheckGracePeriod=300,
        TargetGroupARNs=[target_group_arn]
    )
    print(f"Auto Scaling Group {autoscaling_group_name} created.")
    return response

# User Data Script
user_data_script = """#!/bin/bash -x

# Logging setup
exec > >(tee /var/log/userdata.log) 2>&1

# Variables
DB_USER='wordpressuser'
DB_NAME='wordpressdb'
DB_USER_PASSWORD='W3lcome123'
DB_HOST='wordpressdbclixx.cdk4eccemey1.us-east-1.rds.amazonaws.com'
DNS='clixx-dasola.com'
FILE_SYSTEM_ID=fs-02db2efacffee0059
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
MOUNT_POINT=/var/www/html
LB_DNS='dev.clixx-dasola.com'

# Update the system and install required packages
sudo yum update -y
sudo yum install git -y
sudo amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
sudo yum install -y httpd mariadb-server

# Mount EFS
mkdir -p ${MOUNT_POINT}
chown ec2-user:ec2-user ${MOUNT_POINT}
echo "${FILE_SYSTEM_ID}.efs.${REGION}.amazonaws.com:/ ${MOUNT_POINT} nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,_netdev 0 0" >> /etc/fstab
mount -a -t nfs4
chmod -R 755 ${MOUNT_POINT}

# Start and enable Apache and MariaDB services
sudo systemctl start httpd
sudo systemctl enable httpd
sudo systemctl start mariadb
sudo systemctl enable mariadb

# Add ec2-user to Apache group and modify permissions for /var/www
sudo usermod -a -G apache ec2-user
sudo chown -R ec2-user:apache ${MOUNT_POINT}
sudo chmod -R 775 ${MOUNT_POINT}

# Download and configure WordPress
cd ${MOUNT_POINT}
wget https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz
cp -r wordpress/* ${MOUNT_POINT}
rm -rf wordpress latest.tar.gz

# Create a wp-config.php file
cat > ${MOUNT_POINT}/wp-config.php <<EOL
define('DB_NAME', '${DB_NAME}');
define('DB_USER', '${DB_USER}');
define('DB_PASSWORD', '${DB_USER_PASSWORD}');
define('DB_HOST', '${DB_HOST}');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');
define('AUTH_KEY', 'put your unique phrase here');
define('SECURE_AUTH_KEY', 'put your unique phrase here');
define('LOGGED_IN_KEY', 'put your unique phrase here');
define('NONCE_KEY', 'put your unique phrase here');
define('AUTH_SALT', 'put your unique phrase here');
define('SECURE_AUTH_SALT', 'put your unique phrase here');
define('LOGGED_IN_SALT', 'put your unique phrase here');
define('NONCE_SALT', 'put your unique phrase here');
$table_prefix  = 'wp_';
define('WP_DEBUG', false);
if ( !defined('ABSPATH') ) {
    define('ABSPATH', __DIR__ . '/');
}
require_once(ABSPATH . 'wp-settings.php');
EOL

# Create the database and user
mysql -u root -e "CREATE DATABASE ${DB_NAME};"
mysql -u root -e "CREATE USER '${DB_USER}'@'%' IDENTIFIED BY '${DB_USER_PASSWORD}';"
mysql -u root -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'%';"
mysql -u root -e "FLUSH PRIVILEGES;"

# Restart Apache to apply changes
sudo systemctl restart httpd
"""

# Running the functions in sequence
if __name__ == "__main__":
    vpc_id = create_vpc('10.0.0.0/16')
    subnet_id = create_subnet(vpc_id, '10.0.1.0/24', 'us-east-1a', public_ip=True)
    security_group_id = create_security_group(vpc_id, 'my_security_group', 'Security group for web application')
    internet_gateway_id = create_internet_gateway(vpc_id)
    route_table_id = create_route_table(vpc_id, internet_gateway_id, subnet_id)
    
    db_identifier = 'mydb'
    db_snapshot_arn = 'arn:aws:rds:us-east-1:619071313311:snapshot:wordpressdbclixx-snapshot'
    db_subnet_group_name = 'mydb-subnet-group'
    rds_response = create_rds_instance(db_identifier, db_snapshot_arn, db_subnet_group_name, [security_group_id])
    
    target_group_name = 'my-target-group'
    target_group_arn = create_target_group(vpc_id, target_group_name)
    
    load_balancer_name = 'my-load-balancer'
    load_balancer_arn = create_load_balancer([subnet_id], [security_group_id], load_balancer_name)
    
    certificate_arn = 'arn:aws:acm:us-east-1:619071313311:certificate/ed0a7048-b2f1-4ca7-835d-06d5cc51f805'
    listener_arn = create_https_listener(load_balancer_arn, target_group_arn, certificate_arn)

    launch_config_name = 'my-launch-configuration'
    autoscaling_group_name = 'my-autoscaling-group'
    create_autoscaling_group(launch_config_name, autoscaling_group_name, [subnet_id], target_group_arn)
