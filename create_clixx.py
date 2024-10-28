#!/usr/bin/env python3
import boto3, botocore, base64, time

# Assume Role to interact with AWS resources
sts_client = boto3.client('sts')
assumed_role_object = sts_client.assume_role(
    RoleArn='arn:aws:iam::619071313311:role/Engineer',
    RoleSessionName='mysession'
)
credentials = assumed_role_object['Credentials']

# Create boto3 clients with assumed role credentials
ec2_client = boto3.client('ec2', region_name="us-east-1", 
                          aws_access_key_id=credentials['AccessKeyId'], 
                          aws_secret_access_key=credentials['SecretAccessKey'], 
                          aws_session_token=credentials['SessionToken'])

ec2_resource = boto3.resource('ec2', region_name="us-east-1",
                            aws_access_key_id=credentials['AccessKeyId'],
                            aws_secret_access_key=credentials['SecretAccessKey'],
                            aws_session_token=credentials['SessionToken'])

elbv2_client = boto3.client('elbv2', region_name="us-east-1", 
                            aws_access_key_id=credentials['AccessKeyId'], 
                            aws_secret_access_key=credentials['SecretAccessKey'], 
                            aws_session_token=credentials['SessionToken'])

rds_client = boto3.client('rds', region_name="us-east-1", 
                          aws_access_key_id=credentials['AccessKeyId'], 
                          aws_secret_access_key=credentials['SecretAccessKey'], 
                          aws_session_token=credentials['SessionToken'])

efs_client = boto3.client('efs', region_name="us-east-1", 
                          aws_access_key_id=credentials['AccessKeyId'], 
                          aws_secret_access_key=credentials['SecretAccessKey'], 
                          aws_session_token=credentials['SessionToken'])

route53_client = boto3.client('route53', 
                              aws_access_key_id=credentials['AccessKeyId'], 
                              aws_secret_access_key=credentials['SecretAccessKey'], 
                              aws_session_token=credentials['SessionToken'])

autoscaling_client = boto3.client('autoscaling', region_name="us-east-1", 
                                  aws_access_key_id=credentials['AccessKeyId'], 
                                  aws_secret_access_key=credentials['SecretAccessKey'], 
                                  aws_session_token=credentials['SessionToken'])

###########################################################################
# Variables
vpc_cidr_block = "10.0.0.0/16"
public_subnet_cidr_block_1 = "10.0.1.0/24"
public_subnet_cidr_block_2 = "10.0.2.0/24"
private_subnet_cidr_block_1 = "10.0.3.0/24"
private_subnet_cidr_block_2 = "10.0.4.0/24"
db_instance_identifier = "Wordpressdbclixx"
db_snapshot_identifier = "arn:aws:rds:us-east-1:619071313311:snapshot:wordpressdbclixx-snapshot"
db_instance_class = "db.m6gd.large"
db_username = "wordpressuser"
db_password = "W3lcome123"
ami_id = "ami-00f251754ac5da7f0"
instance_type = "t2.micro"
key_pair_name = "stack_devops_kp"
certificate_arn = "arn:aws:acm:us-east-1:619071313311:certificate/ed0a7048-b2f1-4ca7-835d-06d5cc51f805"
hosted_zone_id = "Z022607324NJ585R59I5F"
record_name = "dev.clixx-dasola.com"
aws_region = "us-east-1"

# --- VPC ---
vpcs = ec2_client.describe_vpcs(Filters=[{'Name': 'cidr', 'Values': [vpc_cidr_block]}])
if not vpcs['Vpcs']:
    vpc = ec2_resource.create_vpc(CidrBlock=vpc_cidr_block)
    ec2_client.create_tags(Resources=[vpc.id], Tags=[{'Key': 'Name', 'Value': 'TESTSTACKVPC'}])
    ec2_client.modify_vpc_attribute(VpcId=vpc.id, EnableDnsSupport={'Value': True})
    ec2_client.modify_vpc_attribute(VpcId=vpc.id, EnableDnsHostnames={'Value': True})
    print(f"VPC created: {vpc.id} with Name tag 'TESTSTACKVPC'")
else:
    print(f"VPC already exists with CIDR block {vpc_cidr_block}")
vpc_id = vpcs['Vpcs'][0]['VpcId'] if vpcs['Vpcs'] else vpc.id

# --- Subnets ---
subnets_1 = ec2_client.describe_subnets(Filters=[{'Name': 'cidr', 'Values': [public_subnet_cidr_block_1]}])
if not subnets_1['Subnets']:
    subnet_1 = ec2_client.create_subnet(CidrBlock=public_subnet_cidr_block_1, VpcId=vpc_id, AvailabilityZone=aws_region + "a")
    ec2_client.create_tags(Resources=[subnet_1['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': "TESTSTACKPUBSUB"}])
    print(f"Public Subnet 1 created: {subnet_1['Subnet']['SubnetId']} with Name tag 'TESTSTACKPUBSUB'")
else:
    print(f"Public Subnet 1 already exists with CIDR block {public_subnet_cidr_block_1}")
subnet_1_id = subnets_1['Subnets'][0]['SubnetId'] if subnets_1['Subnets'] else subnet_1['Subnet']['SubnetId']

subnets_2 = ec2_client.describe_subnets(Filters=[{'Name': 'cidr', 'Values': [public_subnet_cidr_block_2]}])
if not subnets_2['Subnets']:
    subnet_2 = ec2_client.create_subnet(CidrBlock=public_subnet_cidr_block_2, VpcId=vpc_id, AvailabilityZone=aws_region + "b")
    ec2_client.create_tags(Resources=[subnet_2['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': "TESTSTACKPUBSUB2"}])
    print(f"Public Subnet 2 created: {subnet_2['Subnet']['SubnetId']} with Name tag 'TESTSTACKPUBSUB2'")
else:
    print(f"Public Subnet 2 already exists with CIDR block {public_subnet_cidr_block_2}")
subnet_2_id = subnets_2['Subnets'][0]['SubnetId'] if subnets_2['Subnets'] else subnet_2['Subnet']['SubnetId']

private_subnets_1 = ec2_client.describe_subnets(Filters=[{'Name': 'cidr', 'Values': [private_subnet_cidr_block_1]}])
if not private_subnets_1['Subnets']:
    private_subnet_1 = ec2_client.create_subnet(CidrBlock=private_subnet_cidr_block_1, VpcId=vpc_id, AvailabilityZone=aws_region + "a")
    ec2_client.create_tags(Resources=[private_subnet_1['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': "TESTSTACKPRIVSUB1"}])
    print(f"Private Subnet 1 created: {private_subnet_1['Subnet']['SubnetId']} with Name tag 'TESTSTACKPRIVSUB1'")
else:
    print(f"Private Subnet 1 already exists with CIDR block {private_subnet_cidr_block_1}")
private_subnet_1_id = private_subnets_1['Subnets'][0]['SubnetId'] if private_subnets_1['Subnets'] else private_subnet_1['Subnet']['SubnetId']

private_subnets_2 = ec2_client.describe_subnets(Filters=[{'Name': 'cidr', 'Values': [private_subnet_cidr_block_2]}])
if not private_subnets_2['Subnets']:
    private_subnet_2 = ec2_client.create_subnet(CidrBlock=private_subnet_cidr_block_2, VpcId=vpc_id, AvailabilityZone=aws_region + "b")
    ec2_client.create_tags(Resources=[private_subnet_2['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': "TESTSTACKPRIVSUB2"}])
    print(f"Private Subnet 2 created: {private_subnet_2['Subnet']['SubnetId']} with Name tag 'TESTSTACKPRIVSUB2'")
else:
    print(f"Private Subnet 2 already exists with CIDR block {private_subnet_cidr_block_2}")
private_subnet_2_id = private_subnets_2['Subnets'][0]['SubnetId'] if private_subnets_2['Subnets'] else private_subnet_2['Subnet']['SubnetId']

# --- Internet Gateway ---
igw_list = list(ec2_resource.internet_gateways.filter(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]))
if not igw_list:
    igw = ec2_resource.create_internet_gateway()
    ec2_client.attach_internet_gateway(VpcId=vpc_id, InternetGatewayId=igw.id)
    ec2_client.create_tags(Resources=[igw.id], Tags=[{'Key': 'Name', 'Value': 'TESTSTACKIGW'}])
    print(f"Internet Gateway created: {igw.id} with Name tag 'TESTSTACKIGW'")
else:
    igw = igw_list[0]
    print(f"Internet Gateway already exists with ID {igw.id}")

# --- Route Tables ---
pub_route_table_list = list(ec2_resource.route_tables.filter(Filters=[{'Name': 'association.main', 'Values': ['false']}]))
if not pub_route_table_list:
    pub_route_table = ec2_resource.create_route_table(VpcId=vpc_id)
    ec2_client.create_tags(Resources=[pub_route_table.id], Tags=[{'Key': 'Name', 'Value': 'TESTSTACKPUBRT'}])
    print(f"Public Route Table created: {pub_route_table.id} with Name tag 'TESTSTACKPUBRT'")
else:
    pub_route_table = pub_route_table_list[0]
    print(f"Public Route Table already exists with ID {pub_route_table.id}")

priv_route_table_list = list(ec2_resource.route_tables.filter(Filters=[{'Name': 'association.main', 'Values': ['false']}]))
if not priv_route_table_list:
    priv_route_table = ec2_resource.create_route_table(VpcId=vpc_id)
    ec2_client.create_tags(Resources=[priv_route_table.id], Tags=[{'Key': 'Name', 'Value': 'TESTSTACKPRIVRT'}])
    print(f"Private Route Table created: {priv_route_table.id} with Name tag 'TESTSTACKPRIVRT'")
else:
    priv_route_table = priv_route_table_list[0]
    print(f"Private Route Table already exists with ID {priv_route_table.id}")

# --- Route for Internet Access for Public Subnets ---
# Retrieve routes directly from the pub_route_table and filter them
routes = [route for route in pub_route_table.routes if route.destination_cidr_block == '0.0.0.0/0']
if not routes:
    pub_route_table.create_route(
        DestinationCidrBlock='0.0.0.0/0',
        GatewayId=igw.id
    )
    print("Public route created for Internet access")
else:
    print("Public route for Internet access already exists")

# --- Associate Subnets with Route Tables ---
# Check if the public subnets are associated with the public route table
pub_associations = [assoc for assoc in pub_route_table.associations if assoc.subnet_id in [subnet_1_id, subnet_2_id]]
if not pub_associations:
    pub_route_table.associate_with_subnet(SubnetId=subnet_1_id) 
    pub_route_table.associate_with_subnet(SubnetId=subnet_2_id)
    print("Public subnets associated with Public Route Table")
else:
    print("Public subnets already associated with Public Route Table")

# Check if the private subnets are associated with the private route table
priv_associations = [assoc for assoc in priv_route_table.associations if assoc.subnet_id in [private_subnet_1_id, private_subnet_2_id]]
if not priv_associations:
    priv_route_table.associate_with_subnet(SubnetId=private_subnet_1_id)
    priv_route_table.associate_with_subnet(SubnetId=private_subnet_2_id)
    print("Private subnets associated with Private Route Table")
else:
    print("Private subnets already associated with Private Route Table")
print("Route tables created and associated with subnets.")

# --- Security Group ---
# Check for existing public security group
existing_public_sg = list(ec2_resource.security_groups.filter(Filters=[{'Name': 'group-name', 'Values': ['TESTSTACKSG']}]))
if not existing_public_sg:
    public_sg = ec2_resource.create_security_group(
        GroupName='TESTSTACKSG',
        Description='Public Security Group for App Servers',
        VpcId=vpc.id
    )
    public_sg.create_tags(Tags=[{'Key': 'Name', 'Value': 'TESTSTACKSG'}])

    
    # Using ec2_client to authorize ingress rules
    ec2_client.authorize_security_group_ingress(
        GroupId=public_sg.id,
        IpPermissions=[
            {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},  # SSH
            {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},  # HTTP
            {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},  # HTTPS
            {'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},  # NFS (EFS)
            {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},  # MySQL (RDS)
        ]
    )
    print(f"Public Security Group created: {public_sg.id}")
else:
    public_sg = existing_public_sg[0]
    print(f"Public Security Group already exists with ID: {public_sg.id}")

# Check for existing private security group
existing_private_sg = list(ec2_resource.security_groups.filter(Filters=[{'Name': 'group-name', 'Values': ['TESTSTACKSGPRIV']}]))
if not existing_private_sg:
    private_sg = ec2_resource.create_security_group(
        GroupName='TESTSTACKSGPRIV',
        Description='Private Security Group for RDS and EFS',
        VpcId=vpc.id
    )
    private_sg.create_tags(Tags=[{'Key': 'Name', 'Value': 'TESTSTACKSGPRIV'}])

    # Using ec2_client to authorize ingress rules
    ec2_client.authorize_security_group_ingress(
        GroupId=private_sg.id,
        IpPermissions=[
            {'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},  # NFS (EFS)
            {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},  # MySQL (RDS)
        ]
    )
    print(f"Private Security Group created: {private_sg.id}")
else:
    private_sg = existing_private_sg[0]
    print(f"Private Security Group already exists with ID: {private_sg.id}")
print(f"Security groups created: Public SG (ID: {public_sg.id}), Private SG (ID: {private_sg.id})")

# --- RDS Instance ---
# Create or handle existing DB Subnet Group
DBSubnetGroupName = 'TESTSTACKDBSUBNETGROUP'
# Attempt to describe the DB Subnet Group
response = rds_client.describe_db_subnet_groups()
# Flag to check if the subnet group exists
db_subnet_group_exists = False
# Loop through all subnet groups to find a match
for subnet_group in response['DBSubnetGroups']:
    if subnet_group['DBSubnetGroupName'] == DBSubnetGroupName:
        db_subnet_group_exists = True
        DBSubnetGroupName = subnet_group['DBSubnetGroupName']
        print(f"DB Subnet Group '{DBSubnetGroupName}' already exists. Proceeding with the existing one.")
        break

# Create DB Subnet Group if it does not exist
# if not db_subnet_group_exists:
#     response = rds_client.create_db_subnet_group(
#         DBSubnetGroupName=DBSubnetGroupName,
#         SubnetIds=[private_subnet_1_id, private_subnet_2_id],
#         DBSubnetGroupDescription='My stack DB subnet group',
#         Tags=[{'Key': 'Name', 'Value': 'TESTSTACKDBSUBNETGROUP'}]
#     )
#     DBSubnetGroupName = response['DBSubnetGroup']['DBSubnetGroupName']
#     print(f"DB Subnet Group '{DBSubnetGroupName}' created successfully.")
# Define the DB subnet group name
DBSubnetGroupName = 'TESTSTACKDBSUBNETGROUP'

# Check if the DB Subnet Group exists
try:
    response = rds_client.describe_db_subnet_groups(DBSubnetGroupName=DBSubnetGroupName)
    print(f"DB Subnet Group '{DBSubnetGroupName}' already exists. Proceeding with the existing one.")
except botocore.exceptions.ClientError as e:
    # If the subnet group doesn't exist, a ClientError will be raised
    if e.response['Error']['Code'] == 'DBSubnetGroupNotFoundFault':
        # Create the DB Subnet Group
        try:
            response = rds_client.create_db_subnet_group(
                DBSubnetGroupName=DBSubnetGroupName,
                SubnetIds=[private_subnet_1_id, private_subnet_2_id],
                DBSubnetGroupDescription='My stack DB subnet group',
                Tags=[{'Key': 'Name', 'Value': DBSubnetGroupName}]
            )
            print(f"DB Subnet Group '{DBSubnetGroupName}' created successfully.")
        except botocore.exceptions.ClientError as create_error:
            print(f"Error creating DB Subnet Group: {create_error}")
            exit(1)
    else:
        # If it's a different error, raise it
        raise e


# List all DB instances and check if the desired instance exists
# Check if the DB instance already exists
db_instances = rds_client.describe_db_instances()
db_instance_identifiers = [db['DBInstanceIdentifier'] for db in db_instances['DBInstances']]
if db_instance_identifier in db_instance_identifiers:
    # If the instance exists, print the details and skip restore
    instances = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)
    print(f"DB Instance '{db_instance_identifier}' already exists. Details: {instances}")
else:
    # Restore the DB instance from snapshot if it doesn't exist
    print(f"DB Instance '{db_instance_identifier}' not found. Restoring from snapshot...")
    # Attempt to restore the DB from the snapshot
    response = rds_client.restore_db_instance_from_db_snapshot(
        DBInstanceIdentifier=db_instance_identifier,
        DBSnapshotIdentifier=db_snapshot_identifier,
        DBInstanceClass=db_instance_class,
        VpcSecurityGroupIds=[private_sg.id],  # Ensure this is a valid security group ID
        DBSubnetGroupName=DBSubnetGroupName,
        PubliclyAccessible=False,
        Tags=[{'Key': 'Name', 'Value': 'wordpressdbclixx'}]
    )
    print(f"Restore operation initiated. Response: {response}")

# --- Create EFS file system ---
# Check if EFS with creation token exists
efs_response = efs_client.describe_file_systems(
    CreationToken='CLiXX-EFS'
)

# If EFS exists, proceed with the existing EFS
if efs_response['FileSystems']:
    file_system_id = efs_response['FileSystems'][0]['FileSystemId']
    print(f"EFS already exists with FileSystemId: {file_system_id}")
else:
    # Create EFS if it doesn't exist
    efs_response = efs_client.create_file_system(
        CreationToken='CLiXX-EFS',
        PerformanceMode='generalPurpose'
    )
    file_system_id = efs_response['FileSystemId']
    print(f"EFS created with FileSystemId: {file_system_id}")

# Wait until the EFS file system is in 'available' state
while True:
    efs_info = efs_client.describe_file_systems(
        FileSystemId=file_system_id
    )
    lifecycle_state = efs_info['FileSystems'][0]['LifeCycleState']
    if lifecycle_state == 'available':
        print(f"EFS CLiXX-EFS is now available with FileSystemId: {file_system_id}")
        break
    else:
        print(f"EFS is in '{lifecycle_state}' state. Waiting for it to become available...")
        time.sleep(10)

# Add a tag to the EFS file system
efs_client.create_tags(FileSystemId=file_system_id, Tags=[{'Key': 'Name', 'Value': 'CLiXX-EFS'}])

# After ensuring the file system is available, create the mount targets in the private subnets
private_subnet_ids = [private_subnet_1_id, private_subnet_2_id]
for private_subnet_id in private_subnet_ids:
    # Check if mount target already exists for the subnet
    mount_targets_response = efs_client.describe_mount_targets(
        FileSystemId=file_system_id
    )
    # Extract the list of subnet IDs for existing mount targets
    existing_mount_targets = [mt['SubnetId'] for mt in mount_targets_response['MountTargets']]
    # If the current subnet does not have a mount target, create one
    if private_subnet_id not in existing_mount_targets:
        mount_target_response = efs_client.create_mount_target(
            FileSystemId=file_system_id,
            SubnetId=private_subnet_id,
            SecurityGroups=[private_sg.id]
        )
        print(f"Mount target created in Private Subnet: {private_subnet_id}")
    else:
        print(f"Mount target already exists in Private Subnet: {private_subnet_id}")

# Attach Lifecycle Policy (optional)
efs_client.put_lifecycle_configuration(
    FileSystemId=file_system_id,
    LifecyclePolicies=[
        {
            'TransitionToIA': 'AFTER_30_DAYS'
        },
        {
            'TransitionToPrimaryStorageClass': 'AFTER_1_ACCESS'
        }
    ]
)
print(f"Lifecycle policy applied to EFS CLiXX-EFS")

# --- Create Target Group ---
# List all target groups and filter for 'CLiXX-TG'
all_tg_response = elbv2_client.describe_target_groups()
target_groups = all_tg_response['TargetGroups']
# Check if 'CLiXX-TG' exists in the list of target groups
target_group_arn = None
for tg in target_groups:
    if tg['TargetGroupName'] == 'CLiXX-TG':
        target_group_arn = tg['TargetGroupArn']
        print(f"Target Group already exists with ARN: {target_group_arn}")
        break
if target_group_arn is None:
    # Target group does not exist, create a new one
    print("Target Group 'CLiXX-TG' not found. Creating a new target group.")
    target_group = elbv2_client.create_target_group(
        Name='CLiXX-TG',
        Protocol='HTTP',
        Port=80,
        VpcId=vpc.id,
        TargetType='instance',
        HealthCheckProtocol='HTTP',
        HealthCheckPort='traffic-port',
        HealthCheckPath='/',
        HealthCheckIntervalSeconds=120,  
        HealthCheckTimeoutSeconds=30,    
        HealthyThresholdCount=5,         
        UnhealthyThresholdCount=4,       
        Matcher={
            'HttpCode': '200-399'        
        }
    )
    target_group_arn = target_group['TargetGroups'][0]['TargetGroupArn']
    print(f"Target Group created with ARN: {target_group_arn}")

# --- Create Application Load Balancer ---
# List all load balancers
all_lb_response = elbv2_client.describe_load_balancers()
load_balancers = all_lb_response['LoadBalancers']
# Check if 'CLiXX-LB' exists in the list of load balancers
load_balancer_arn = None
for lb in load_balancers:
    if lb['LoadBalancerName'] == 'CLiXX-LB':
        load_balancer_arn = lb['LoadBalancerArn']
        print(f"Load Balancer already exists with ARN: {load_balancer_arn}")
        break
if load_balancer_arn is None:
    # Load balancer does not exist, create a new one
    print("Load Balancer 'CLiXX-LB' not found. Creating a new load balancer.")
    load_balancer = elbv2_client.create_load_balancer(
        Name='CLiXX-LB',
        Subnets=[subnet_1_id, subnet_2_id],
        SecurityGroups=[public_sg.id],
        Scheme='internet-facing',
        IpAddressType='ipv4',
        Tags=[
            {
                'Key': 'Name',
                'Value': 'CLiXX-LB'
            },
            {
                'Key': 'Environment',
                'Value': 'dev'
            }
        ]
    )
    load_balancer_arn = load_balancer['LoadBalancers'][0]['LoadBalancerArn']
    print(f"Load Balancer created with ARN: {load_balancer_arn}")

#Create Listener for the Load Balancer (HTTP & HTTPS)
# Retrieve listeners for the load balancer
http_listener_response = elbv2_client.describe_listeners(LoadBalancerArn=load_balancer_arn)
existing_listeners = http_listener_response['Listeners']

# Check if HTTP listener exists
http_listener_exists = any(listener['Protocol'] == 'HTTP' for listener in existing_listeners)
if not http_listener_exists:
    elbv2_client.create_listener(
        LoadBalancerArn=load_balancer_arn,
        Protocol='HTTP',
        Port=80,
        DefaultActions=[{'Type': 'forward', 'TargetGroupArn': target_group_arn}]
    )
    print(f"HTTP Listener created for Load Balancer: {load_balancer_arn}")
else:
    print("HTTP Listener already exists.")

# Check if HTTPS listener exists
https_listener_exists = any(listener['Protocol'] == 'HTTPS' for listener in existing_listeners)
if not https_listener_exists:
    elbv2_client.create_listener(
        LoadBalancerArn=load_balancer_arn,
        Protocol='HTTPS',
        Port=443,
        SslPolicy='ELBSecurityPolicy-2016-08',
        Certificates=[{
            'CertificateArn': certificate_arn
        }],
        DefaultActions=[{'Type': 'forward', 'TargetGroupArn': target_group_arn}]
    )
    print(f"HTTPS Listener created for Load Balancer: {load_balancer_arn}")
else:
    print("HTTPS Listener already exists.")

# --- Create Route 53 record for the load balancer ---
route53_response = route53_client.list_resource_record_sets(
    HostedZoneId=hosted_zone_id
)
# Check if the record already exists using a broader approach
record_exists = any(record['Name'] == record_name for record in route53_response['ResourceRecordSets'])
if not record_exists:
    route53_client.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch={
            'Comment': 'Create a record for the CLiXX Load Balancer',
            'Changes': [{
                'Action': 'CREATE',
                'ResourceRecordSet': {
                    'Name': record_name,
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
    print(f"Route 53 record created for {record_name}")
else:
    print(f"Route 53 record already exists for {record_name}")

# Define user_data_script with dynamic variables
efs_name = "CLiXX-EFS"
mount_point = "/var/www/html"
user_data_script = f'''#!/bin/bash
# Switch to root user
sudo su -

# Update packages and install necessary utilities
yum update -y
yum install -y nfs-utils aws-cli

# Fetch the session token and region information for metadata
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
AVAILABILITY_ZONE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/placement/availability-zone")
REGION=${{AVAILABILITY_ZONE:0:-1}}

# Ensure DNS resolution and DNS hostnames are enabled (for VPC)
echo "nameserver 169.254.169.253" >> /etc/resolv.conf

# Use the passed in file_system_id
file_system_id="{file_system_id}"
if [ -z "$file_system_id" ]; then
    echo "Error: FileSystemId not provided"
    exit 1
fi

# Install the NFS utilities for mounting EFS
yum install -y nfs-utils

# Wait until the EFS file system is available
while true; do
    status=$(aws efs describe-file-systems --file-system-id $file_system_id --query "FileSystems[0].LifeCycleState" --output text --region $REGION)
    if [ "$status" == "available" ]; then
        echo "EFS FileSystem is available."
        break
    else
        echo "Waiting for EFS FileSystem to become available. Retrying in 10 seconds..."
    fi
    sleep 10
done

# Ensure the mount target exists in the same availability zone as the EC2 instance
while true; do
    mount_target=$(aws efs describe-mount-targets --file-system-id $file_system_id --region $REGION --query 'MountTargets[?AvailabilityZoneName==`'$AVAILABILITY_ZONE'`].MountTargetId' --output text)
    if [ -n "$mount_target" ]; then
        echo "Mount target found in availability zone $AVAILABILITY_ZONE."
        break
    else
        echo "Waiting for mount target in availability zone $AVAILABILITY_ZONE. Retrying in 10 seconds..."
    fi
    sleep 10
done

# Restart network service to ensure DNS resolution
sudo service network restart

# Create mount point and set permissions
MOUNT_POINT={mount_point}
mkdir -p $MOUNT_POINT
chown ec2-user:ec2-user $MOUNT_POINT

# Add EFS to fstab and attempt to mount
echo "${{file_system_id}}.efs.${{REGION}}.amazonaws.com:/ $MOUNT_POINT nfs4 defaults,_netdev 0 0" >> /etc/fstab

sleep 180
# Attempt to mount, retrying if it fails
attempt=0
max_attempts=5
while (( attempt < max_attempts )); do
    mount -a -t nfs4 && echo "EFS mounted successfully." && break
    echo "Mount failed, retrying after network restart..."
    sudo service network restart
    sleep 10
    attempt=$((attempt + 1))
done

# Check if mount was successful
if ! mount | grep -q $MOUNT_POINT; then
    echo "Error: EFS mount failed after $max_attempts attempts. Continuing with the rest of the script."
else
    echo "EFS successfully mounted at $MOUNT_POINT."
fi

chmod -R 755 $MOUNT_POINT

# Switch back to ec2-user
sudo su - ec2-user

# Proceed with the rest of the CLiXX setup
# Variables for WordPress Setup
CLiXX_GIT_REPO_URL="https://github.com/stackitgit/CliXX_Retail_Repository.git"
WordPress_DB_NAME="wordpressdb"
WordPress_DB_USER="wordpressuser"
WordPress_DB_PASS="W3lcome123"
WordPress_DB_HOST="wordpressdbclixx.cj0yi4ywm61r.us-east-1.rds.amazonaws.com"
RECORD_NAME="{record_name}"
WP_CONFIG_PATH="/var/www/html/wp-config.php"

# Install the needed packages and enable the services
sudo yum update -y
sudo yum install git -y
sudo amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
sudo yum install -y httpd mariadb-server
sudo systemctl start httpd
sudo systemctl enable httpd
sudo systemctl is-enabled httpd

# Add ec2-user to Apache group and grant permissions to /var/www
sudo usermod -a -G apache ec2-user
sudo chown -R ec2-user:apache /var/www
sudo chmod 2775 /var/www && find /var/www -type d -exec sudo chmod 2775 {{}} \;
find /var/www -type f -exec sudo chmod 0664 {{}} \;

# Check if wp-config.php exists before cloning the repository
if [ ! -f "/var/www/html/wp-config.php" ]; 
then
    echo "Cloning CliXX Retail repository..."
    git clone $CLiXX_GIT_REPO_URL /var/www/html
else
    echo "WordPress already installed, skipping clone..."
fi

# Configure the wp-config.php file
sudo cp /var/www/html/wp-config-sample.php /var/www/html/wp-config.php
sudo sed -i "s/database_name_here/$WordPress_DB_NAME/" $WP_CONFIG_PATH
sudo sed -i "s/username_here/$WordPress_DB_USER/" $WP_CONFIG_PATH
sudo sed -i "s/password_here/$WordPress_DB_PASS/" $WP_CONFIG_PATH
sudo sed -i "s/localhost/$WordPress_DB_HOST/" $WP_CONFIG_PATH

# Add HTTPS enforcement to wp-config.php
sudo sed -i "81i if (isset(\$_SERVER['HTTP_X_FORWARDED_PROTO']) && \$_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {{ \$_SERVER['HTTPS'] = 'on'; }}" $WP_CONFIG_PATH

# Allow WordPress to use Permalinks
sudo sed -i '151s/None/All/' /etc/httpd/conf/httpd.conf

# Grant file ownership of /var/www to apache user
sudo chown -R apache /var/www
sudo chgrp -R apache /var/www
sudo chmod 2775 /var/www
find /var/www -type d -exec sudo chmod 2775 {{}} \;
sudo find /var/www -type f -exec sudo chmod 0664 {{}} \;

# Restart Apache
sudo systemctl restart httpd
sudo service httpd restart
sudo systemctl enable httpd

# Wait for the database to be up
until mysqladmin ping -h $WordPress_DB_HOST -u $WordPress_DB_USER -p$WordPress_DB_PASS --silent; do
    echo "Waiting for database to be available..."
    sleep 10
done

# Check and update WordPress options
existing_value=$(mysql -u ${{WordPress_DB_USER}} -p${{WordPress_DB_PASS}} -h ${{WordPress_DB_HOST}} -D ${{WordPress_DB_NAME}} -sse "SELECT COUNT(*) FROM wp_options WHERE (option_name = 'home' OR option_name = 'siteurl' OR option_name = 'ping_sites' OR option_name = 'open_shop_header_retina_logo') AND option_value = '${{RECORD_NAME}}';")

if [ "$existing_value" -eq 4 ]; 
then
    echo "All relevant options are already set to ${{RECORD_NAME}}. No update needed."
else
    echo "Updating the options with the new record name value."
    mysql -u ${{WordPress_DB_USER}} -p${{WordPress_DB_PASS}} -h ${{WordPress_DB_HOST}} -D ${{WordPress_DB_NAME}} <<EOF
    UPDATE wp_options SET option_value = "https://${{RECORD_NAME}}" WHERE option_name = "home";
    UPDATE wp_options SET option_value = "https://${{RECORD_NAME}}" WHERE option_name = "siteurl";
    UPDATE wp_options SET option_value = "https://${{RECORD_NAME}}" WHERE option_name = "ping_sites";
    UPDATE wp_options SET option_value = "https://${{RECORD_NAME}}" WHERE option_name = "open_shop_header_retina_logo";
EOF
    echo "Update queries executed successfully."
fi

'''

# Encode the user data to Base64
user_data_base64 = base64.b64encode(user_data_script.encode('utf-8')).decode('utf-8')
# --- Create Launch Template ---
#List all launch templates and check for 'CLiXX-LT'
all_lt_response = ec2_client.describe_launch_templates()
launch_template_names = [lt['LaunchTemplateName'] for lt in all_lt_response['LaunchTemplates']]

if 'CLiXX-LT' in launch_template_names:
    # Get the ID of the existing launch template
    launch_template_id = next(lt['LaunchTemplateId'] for lt in all_lt_response['LaunchTemplates'] if lt['LaunchTemplateName'] == 'CLiXX-LT')
    print(f"Launch Template already exists with ID: {launch_template_id}")
else:
    # Create a new launch template since it doesn't exist
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName='CLiXX-LT',
        VersionDescription='Version 1',
        LaunchTemplateData={
            'ImageId': ami_id,  
            'InstanceType': instance_type,  
            'KeyName': key_pair_name,  
            #'SecurityGroupIds': [public_sg.id],  
            'UserData': user_data_base64,  
            'IamInstanceProfile': {
                'Name': 'EFS_operations'  
            },
            'NetworkInterfaces': [{
                'AssociatePublicIpAddress': True,
                'DeviceIndex': 0,
                'SubnetId': subnet_1_id,
                'Groups': [public_sg.id]
            }]
        }
    )
    launch_template_id = launch_template['LaunchTemplate']['LaunchTemplateId']
    print(f"Launch Template created with ID: {launch_template_id}")

# --- Create Auto Scaling Group ---
# List all Auto Scaling Groups and check for 'CLiXX-ASG'
all_asg_response = autoscaling_client.describe_auto_scaling_groups()
asg_names = [asg['AutoScalingGroupName'] for asg in all_asg_response['AutoScalingGroups']]
if 'CLiXX-ASG' in asg_names:
    print("Auto Scaling Group already exists.")
else:
    # Create a new Auto Scaling Group since it doesn't exist
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName='CLiXX-ASG',
        LaunchTemplate={
            'LaunchTemplateId': launch_template_id, 
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
                'Value': 'CLiXX',
                'PropagateAtLaunch': True
            }
        ]
    )
    print("Auto Scaling Group created successfully.")
