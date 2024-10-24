import boto3

# Initialize the boto3 clients
ec2_client = boto3.client('ec2')
rds_client = boto3.client('rds')
autoscaling_client = boto3.client('autoscaling')
elb_client = boto3.client('elbv2')

# Step 1: Create a Key Pair
def create_key_pair(key_name, public_key_path):
    with open(public_key_path, 'r') as key_file:
        public_key = key_file.read()
    
    response = ec2_client.import_key_pair(
        KeyName=key_name,
        PublicKeyMaterial=public_key.encode('utf-8')
    )
    print(f"Key Pair {key_name} created.")
    return response

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
        # Enable public IP on launch for this subnet
        ec2_client.modify_subnet_attribute(
            SubnetId=subnet_id,
            MapPublicIpOnLaunch={'Value': True}
        )
    
    return subnet_id

# Step 4: Create Security Group
def create_security_group(vpc_id, group_name, description):
    response = ec2_client.create_security_group(
        GroupName=group_name,
        Description=description,
        VpcId=vpc_id
    )
    
    sg_id = response['GroupId']
    
    # Allow all outbound traffic (egress)
    ec2_client.authorize_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[
            {
                'IpProtocol': '-1',
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )
    
    return sg_id

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
        Certificates=[{
            'CertificateArn': certificate_arn
        }],
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

# Start and enable Apache
sudo systemctl start httpd
sudo systemctl enable httpd
sudo systemctl start mariadb
sudo systemctl enable mariadb

# Add ec2-user to Apache group and modify permissions for /var/www
sudo usermod -a -G apache ec2-user
sudo chown -R ec2-user:apache /var/www
sudo chmod 2775 /var/www && find /var/www -type d -exec sudo chmod 2775 {} \;
find /var/www -type f -exec sudo chmod 0664 {} \;

# Clone your repository and set up WordPress configuration
cd /var/www/html
git clone https://github.com/stackitgit/CliXX_Retail_Repository.git
cp -r CliXX_Retail_Repository/* .
rm -rf CliXX_Retail_Repository
cp wp-config-sample.php wp-config.php

# Setup WordPress config
sed -i "s/database_name_here/${DB_NAME}/" wp-config.php
sed -i "s/username_here/${DB_USER}/" wp-config.php
sed -i "s/password_here/${DB_USER_PASSWORD}/" wp-config.php
sed -i "s/localhost/${DB_HOST}/" wp-config.php

# Enable and start services
sudo systemctl start httpd
sudo systemctl enable httpd

# Output the Load Balancer DNS
echo "Your application is ready at: http://${LB_DNS}"

# Enable HTTPS on Apache
sudo yum install -y mod_ssl
sudo systemctl restart httpd
"""

# Main execution block
if __name__ == "__main__":
    key_pair_name = 'my-key-pair'
    public_key_path = 'path/to/your/public/key.pub'  # Update this path
    vpc_cidr_block = '10.0.0.0/16'
    subnet_cidr_block = '10.0.1.0/24'
    availability_zone = 'us-east-1a'
    
    # Create Key Pair
    create_key_pair(key_pair_name, public_key_path)

    # Create VPC
    vpc_id = create_vpc(vpc_cidr_block)

    # Create Subnet
    subnet_id = create_subnet(vpc_id, subnet_cidr_block, availability_zone, public_ip=True)

    # Create Security Group
    security_group_id = create_security_group(vpc_id, "wordpress-sg", "Security group for WordPress instances")

    # Create Internet Gateway
    igw_id = create_internet_gateway(vpc_id)

    # Create Route Table
    route_table_id = create_route_table(vpc_id, igw_id, subnet_id)

    # Create RDS Instance
    db_identifier = 'wordpressdb'
    db_snapshot_arn = 'arn:aws:rds:us-east-1:619071313311:snapshot:wordpressdbclixx-snapshot'  # Update with your snapshot ARN
    db_subnet_group_name = 'wordpress-db-subnet-group'
    vpc_security_group_ids = [security_group_id]
    
    create_rds_instance(db_identifier, db_snapshot_arn, db_subnet_group_name, vpc_security_group_ids)

    # Create Target Group
    target_group_name = 'wordpress-target-group'
    target_group_arn = create_target_group(vpc_id, target_group_name)

    # Create Load Balancer
    lb_name = 'wordpress-load-balancer'
    lb_arn = create_load_balancer([subnet_id], [security_group_id], lb_name)

    # Create HTTPS Listener
    certificate_arn = 'arn:aws:acm:us-east-1:619071313311:certificate/ed0a7048-b2f1-4ca7-835d-06d5cc51f805'  # Update with your certificate ARN
    create_https_listener(lb_arn, target_group_arn, certificate_arn)

    # Create Launch Configuration (optional)
    launch_config_name = 'wordpress-launch-configuration'
    # Define other launch configuration details

    # Create Auto Scaling Group
    autoscaling_group_name = 'wordpress-auto-scaling-group'
    create_autoscaling_group(launch_config_name, autoscaling_group_name, [subnet_id], target_group_arn)

    print("All resources created successfully.")
