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
    ec2_client = boto3.client('ec2')
    
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
    ec2_client = boto3.client('ec2')

    # Create the security group
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
        HealthCheckPath='/inex.php',
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
        Protocol='HTTPS',            # HTTPS protocol
        Port=443,                    # Port 443 for HTTPS
        SslPolicy='ELBSecurityPolicy-2016-08',  # SSL Policy
        Certificates=[{
            'CertificateArn': "arn:aws:acm:us-east-1:619071313311:certificate/ed0a7048-b2f1-4ca7-835d-06d5cc51f805"  # ACM certificate
    
        }],
        DefaultActions=[{
            'Type': 'forward',
            'TargetGroupArn': target_group_arn  # Forwarding traffic to the target group
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
cp -r CliXX_Retail_Repository/* /var/www/html

# Setup wp-config.php
if [ -f "wp-config-sample.php" ]; then
    cp wp-config-sample.php wp-config.php
else
    echo "wp-config-sample.php does not exist!"
    exit 1
fi

# Replace placeholders in wp-config.php with actual values
sed -i "s/database_name_here/${DB_NAME}/g" wp-config.php
sed -i "s/username_here/${DB_USER}/g" wp-config.php
sed -i "s/password_here/${DB_USER_PASSWORD}/g" wp-config.php
sed -i "s/localhost/${DB_HOST}/g" wp-config.php

# Update Apache configuration to allow WordPress permalinks
sudo sed -i '151s/None/All/' /etc/httpd/conf/httpd.conf

# Adjust file and directory ownership and permissions
sudo chown -R apache /var/www
sudo chgrp -R apache /var/www
sudo chmod 2775 /var/www
find /var/www -type d -exec sudo chmod 2775 {} \;
find /var/www -type f -exec sudo chmod 0664 {} \;

# Check if DNS is already in the wp_options table (matching your actual setup)
output_variable=$(mysql -u ${DB_USER} -p${DB_USER_PASSWORD} -h ${DB_HOST} -D ${DB_NAME} -sse "select option_value from wp_options where option_value like '%${DNS}%';")

if [[ "${output_variable}" == "${DNS}" ]]; then
    echo "DNS Address is already in the table"
else
    echo "DNS Address is not in the table, updating..."
    mysql -u ${DB_USER} -p${DB_USER_PASSWORD} -h ${DB_HOST} -D ${DB_NAME} -e "UPDATE wp_options SET option_value ='${DNS}' WHERE option_value LIKE '%${DNS}%';"
fi

# Restart and enable Apache
sudo systemctl restart httpd

# Update RDS with Load Balancer DNS
UPDATE_SITEURL="UPDATE wp_options SET option_value='https://${LB_DNS}' WHERE option_name='siteurl';"
UPDATE_HOME="UPDATE wp_options SET option_value='https://${LB_DNS}' WHERE option_name='home';"

# Execute the update queries
mysql -h ${DB_HOST} -u ${DB_USER} -p${DB_USER_PASSWORD} -D ${DB_NAME} -e "${UPDATE_SITEURL}"
mysql -h ${DB_HOST} -u ${DB_USER} -p${DB_USER_PASSWORD} -D ${DB_NAME} -e "${UPDATE_HOME}"

# Check if MySQL query was successful
if (( $? == 0 )); then
    echo "MySQL update successful"
else
    echo "MySQL update failed"
    exit 1
fi

# Set TCP keepalive settings
sudo /sbin/sysctl -w net.ipv4.tcp_keepalive_time=200 net.ipv4.tcp_keepalive_intvl=200 net.ipv4.tcp_keepalive_probes=5
"""
# Step 12: Create Launch Configuration
def create_launch_configuration(lc_name, ami_id, instance_type, key_pair, sg_ids, user_data_script):
    response = autoscaling_client.create_launch_configuration(
        LaunchConfigurationName=lc_name,
        ImageId=ami_id,
        InstanceType=instance_type,
        KeyName=key_pair,
        SecurityGroups=sg_ids,
        UserData=user_data_script
    )
    print(f"Launch Configuration {lc_name} created.")
    return response

# Main function to orchestrate the resource creation
def main():
    # Key pair and VPC setup
    key_pair_name = "keypair_alpha"
    public_key_path = "path/to/public_key.pem"
    vpc_cidr = "10.0.0.0/16"
    vpc_id = create_vpc(vpc_cidr)

    # Create public and private subnets
    public_subnet_id = create_subnet(vpc_id, "10.0.0.0/24", "us-east-1a", public_ip=True)
    private_subnet_id = create_subnet(vpc_id, "10.0.1.0/24", "us-east-1a")

    # Create security groups
    public_sg_id = create_security_group(vpc_id, "sg_public_alpha", "Public SG", 
        [{'protocol': 'tcp', 'from_port': 22, 'to_port': 22, 'cidr_block': '0.0.0.0/0'}],
        [{'protocol': '-1', 'from_port': 0, 'to_port': 0, 'cidr_block': '0.0.0.0/0'}])

    # Create Internet Gateway and Route Table
    igw_id = create_internet_gateway(vpc_id)
    route_table_id = create_route_table(vpc_id, igw_id, public_subnet_id)

    # Example RDS Instance creation (using a snapshot)
    db_subnet_group = "rds-subnet-group"
    db_snapshot_arn = "arn:aws:rds:us-east-1:619071313311:snapshot:wordpressdbclixx-snapshot"
    create_rds_instance("db_instance_alpha", db_snapshot_arn, db_subnet_group, [public_sg_id])

    # Create Target Group and Load Balancer
    target_group_arn = create_target_group(vpc_id, "tg_alpha")
    lb_arn = create_load_balancer([public_subnet_id], [public_sg_id], "lb_alpha")
    create_listener(lb_arn, target_group_arn)

    # Auto Scaling Group creation
    lc_name = "lc_alpha"
    ami_id = "ami-08f3d892de259504d"
    instance_type = "t2.micro"
    user_data_script = "#!/bin/bash\necho Hello World"
    create_launch_configuration(lc_name, ami_id, instance_type, key_pair_name, [public_sg_id], user_data_script)
    create_autoscaling_group(lc_name, "asg_alpha", [public_subnet_id], target_group_arn)

if __name__ == "__main__":
    main()
