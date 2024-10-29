#!/usr/bin/env python3
import boto3, botocore, base64, time

# Assume Role to interact with AWS resources
clixx_sts_client = boto3.client('sts')
clixx_assumed_role_object = clixx_sts_client.assume_role(
    RoleArn='arn:aws:iam::619071313311:role/Engineer',
    RoleSessionName='mysession'
)
clixx_credentials = clixx_assumed_role_object['Credentials']

# Create boto3 clients with assumed role credentials
clixx_ec2_client = boto3.client('ec2', region_name="us-east-1", 
                                aws_access_key_id=clixx_credentials['AccessKeyId'], 
                                aws_secret_access_key=clixx_credentials['SecretAccessKey'], 
                                aws_session_token=clixx_credentials['SessionToken'])

clixx_ec2_resource = boto3.resource('ec2', region_name="us-east-1",
                                    aws_access_key_id=clixx_credentials['AccessKeyId'],
                                    aws_secret_access_key=clixx_credentials['SecretAccessKey'],
                                    aws_session_token=clixx_credentials['SessionToken'])

clixx_elbv2_client = boto3.client('elbv2', region_name="us-east-1", 
                                  aws_access_key_id=clixx_credentials['AccessKeyId'], 
                                  aws_secret_access_key=clixx_credentials['SecretAccessKey'], 
                                  aws_session_token=clixx_credentials['SessionToken'])

clixx_rds_client = boto3.client('rds', region_name="us-east-1", 
                                aws_access_key_id=clixx_credentials['AccessKeyId'], 
                                aws_secret_access_key=clixx_credentials['SecretAccessKey'], 
                                aws_session_token=clixx_credentials['SessionToken'])

clixx_efs_client = boto3.client('efs', region_name="us-east-1", 
                                aws_access_key_id=clixx_credentials['AccessKeyId'], 
                                aws_secret_access_key=clixx_credentials['SecretAccessKey'], 
                                aws_session_token=clixx_credentials['SessionToken'])

clixx_route53_client = boto3.client('route53', 
                                    aws_access_key_id=clixx_credentials['AccessKeyId'], 
                                    aws_secret_access_key=clixx_credentials['SecretAccessKey'], 
                                    aws_session_token=clixx_credentials['SessionToken'])

clixx_autoscaling_client = boto3.client('autoscaling', region_name="us-east-1", 
                                        aws_access_key_id=clixx_credentials['AccessKeyId'], 
                                        aws_secret_access_key=clixx_credentials['SecretAccessKey'], 
                                        aws_session_token=clixx_credentials['SessionToken'])


# Variables
clixx_vpc_cidr_block = "10.0.0.0/16"
clixx_public_subnet_cidr_block_1 = "10.0.1.0/24"
clixx_public_subnet_cidr_block_2 = "10.0.2.0/24"
clixx_private_subnet_cidr_block_1 = "10.0.3.0/24"
clixx_private_subnet_cidr_block_2 = "10.0.4.0/24"
clixx_db_instance_identifier = "Wordpressdbclixx"
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
clixx_aws_region = "us-east-1"

# --- VPC ---
clixx_vpcs = clixx_ec2_client.describe_vpcs(Filters=[{'Name': 'cidr', 'Values': [clixx_vpc_cidr_block]}])
if not clixx_vpcs['Vpcs']:
    clixx_vpc = clixx_ec2_resource.create_vpc(CidrBlock=clixx_vpc_cidr_block)
    clixx_ec2_client.create_tags(Resources=[clixx_vpc.id], Tags=[{'Key': 'Name', 'Value': 'CLIXXSTACKVPC'}])
    clixx_ec2_client.modify_vpc_attribute(VpcId=clixx_vpc.id, EnableDnsSupport={'Value': True})
    clixx_ec2_client.modify_vpc_attribute(VpcId=clixx_vpc.id, EnableDnsHostnames={'Value': True})
    print(f"VPC created: {clixx_vpc.id} with Name tag 'CLIXXSTACKVPC'")
else:
    print(f"VPC already exists with CIDR block {clixx_vpc_cidr_block}")
clixx_vpc_id = clixx_vpcs['Vpcs'][0]['VpcId'] if clixx_vpcs['Vpcs'] else clixx_vpc.id

# --- Subnets ---
clixx_subnets_1 = clixx_ec2_client.describe_subnets(Filters=[{'Name': 'cidr', 'Values': [clixx_public_subnet_cidr_block_1]}])
if not clixx_subnets_1['Subnets']:
    clixx_subnet_1 = clixx_ec2_client.create_subnet(CidrBlock=clixx_public_subnet_cidr_block_1, VpcId=clixx_vpc_id, AvailabilityZone=clixx_aws_region + "a")
    clixx_ec2_client.create_tags(Resources=[clixx_subnet_1['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': "CLIXXSTACKPUBSUB"}])
    print(f"Public Subnet 1 created: {clixx_subnet_1['Subnet']['SubnetId']} with Name tag 'CLIXXSTACKPUBSUB'")
else:
    print(f"Public Subnet 1 already exists with CIDR block {clixx_public_subnet_cidr_block_1}")
clixx_subnet_1_id = clixx_subnets_1['Subnets'][0]['SubnetId'] if clixx_subnets_1['Subnets'] else clixx_subnet_1['Subnet']['SubnetId']

clixx_subnets_2 = clixx_ec2_client.describe_subnets(Filters=[{'Name': 'cidr', 'Values': [clixx_public_subnet_cidr_block_2]}])
if not clixx_subnets_2['Subnets']:
    clixx_subnet_2 = clixx_ec2_client.create_subnet(CidrBlock=clixx_public_subnet_cidr_block_2, VpcId=clixx_vpc_id, AvailabilityZone=clixx_aws_region + "b")
    clixx_ec2_client.create_tags(Resources=[clixx_subnet_2['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': "CLIXXSTACKPUBSUB2"}])
    print(f"Public Subnet 2 created: {clixx_subnet_2['Subnet']['SubnetId']} with Name tag 'CLIXXSTACKPUBSUB2'")
else:
    print(f"Public Subnet 2 already exists with CIDR block {clixx_public_subnet_cidr_block_2}")
clixx_subnet_2_id = clixx_subnets_2['Subnets'][0]['SubnetId'] if clixx_subnets_2['Subnets'] else clixx_subnet_2['Subnet']['SubnetId']

clixx_private_subnets_1 = clixx_ec2_client.describe_subnets(Filters=[{'Name': 'cidr', 'Values': [clixx_private_subnet_cidr_block_1]}])
if not clixx_private_subnets_1['Subnets']:
    clixx_private_subnet_1 = clixx_ec2_client.create_subnet(CidrBlock=clixx_private_subnet_cidr_block_1, VpcId=clixx_vpc_id, AvailabilityZone=clixx_aws_region + "a")
    clixx_ec2_client.create_tags(Resources=[clixx_private_subnet_1['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': "CLIXXSTACKPRIVSUB1"}])
    print(f"Private Subnet 1 created: {clixx_private_subnet_1['Subnet']['SubnetId']} with Name tag 'CLIXXSTACKPRIVSUB1'")
else:
    print(f"Private Subnet 1 already exists with CIDR block {clixx_private_subnet_cidr_block_1}")
clixx_private_subnet_1_id = clixx_private_subnets_1['Subnets'][0]['SubnetId'] if clixx_private_subnets_1['Subnets'] else clixx_private_subnet_1['Subnet']['SubnetId']

clixx_private_subnets_2 = clixx_ec2_client.describe_subnets(Filters=[{'Name': 'cidr', 'Values': [clixx_private_subnet_cidr_block_2]}])
if not clixx_private_subnets_2['Subnets']:
    clixx_private_subnet_2 = clixx_ec2_client.create_subnet(CidrBlock=clixx_private_subnet_cidr_block_2, VpcId=clixx_vpc_id, AvailabilityZone=clixx_aws_region + "b")
    clixx_ec2_client.create_tags(Resources=[clixx_private_subnet_2['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': "CLIXXSTACKPRIVSUB2"}])
    print(f"Private Subnet 2 created: {clixx_private_subnet_2['Subnet']['SubnetId']} with Name tag 'CLIXXSTACKPRIVSUB2'")
else:
    print(f"Private Subnet 2 already exists with CIDR block {clixx_private_subnet_cidr_block_2}")
clixx_private_subnet_2_id = clixx_private_subnets_2['Subnets'][0]['SubnetId'] if clixx_private_subnets_2['Subnets'] else clixx_private_subnet_2['Subnet']['SubnetId']

# --- Internet Gateway ---
clixx_igw_list = list(clixx_ec2_resource.internet_gateways.filter(Filters=[{'Name': 'attachment.vpc-id', 'Values': [clixx_vpc_id]}]))
if not clixx_igw_list:
    clixx_igw = clixx_ec2_resource.create_internet_gateway()
    clixx_ec2_client.attach_internet_gateway(VpcId=clixx_vpc_id, InternetGatewayId=clixx_igw.id)
    clixx_ec2_client.create_tags(Resources=[clixx_igw.id], Tags=[{'Key': 'Name', 'Value': 'CLIXXSTACKIGW'}])
    print(f"Internet Gateway created: {clixx_igw.id} with Name tag 'CLIXXSTACKIGW'")
else:
    clixx_igw = clixx_igw_list[0]
    print(f"Internet Gateway already exists with ID {clixx_igw.id}")

# --- Route Tables ---
clixx_pub_route_table_list = list(clixx_ec2_resource.route_tables.filter(Filters=[{'Name': 'association.main', 'Values': ['false']}]))
if not clixx_pub_route_table_list:
    clixx_pub_route_table = clixx_ec2_resource.create_route_table(VpcId=clixx_vpc_id)
    clixx_ec2_client.create_tags(Resources=[clixx_pub_route_table.id], Tags=[{'Key': 'Name', 'Value': 'CLIXXSTACKPUBRT'}])
    print(f"Public Route Table created: {clixx_pub_route_table.id} with Name tag 'CLIXXSTACKPUBRT'")
else:
    clixx_pub_route_table = clixx_pub_route_table_list[0]
    print(f"Public Route Table already exists with ID {clixx_pub_route_table.id}")

clixx_priv_route_table_list = list(clixx_ec2_resource.route_tables.filter(Filters=[{'Name': 'association.main', 'Values': ['false']}]))
if not clixx_priv_route_table_list:
    clixx_priv_route_table = clixx_ec2_resource.create_route_table(VpcId=clixx_vpc_id)
    clixx_ec2_client.create_tags(Resources=[clixx_priv_route_table.id], Tags=[{'Key': 'Name', 'Value': 'CLIXXSTACKPRIVRT'}])
    print(f"Private Route Table created: {clixx_priv_route_table.id} with Name tag 'CLIXXSTACKPRIVRT'")
else:
    clixx_priv_route_table = clixx_priv_route_table_list[0]
    print(f"Private Route Table already exists with ID {clixx_priv_route_table.id}")

# --- Route for Internet Access for Public Subnets ---
clixx_routes = [route for route in clixx_pub_route_table.routes if route.destination_cidr_block == '0.0.0.0/0']
if not clixx_routes:
    clixx_pub_route_table.create_route(
        DestinationCidrBlock='0.0.0.0/0',
        GatewayId=clixx_igw.id
    )
    print("Public route created for Internet access")
else:
    print("Public route for Internet access already exists")

# --- Associate Subnets with Route Tables ---
clixx_pub_associations = [assoc for assoc in clixx_pub_route_table.associations if assoc.subnet_id in [clixx_subnet_1_id, clixx_subnet_2_id]]
if not clixx_pub_associations:
    clixx_pub_route_table.associate_with_subnet(SubnetId=clixx_subnet_1_id) 
    clixx_pub_route_table.associate_with_subnet(SubnetId=clixx_subnet_2_id)
    print("Public subnets associated with Public Route Table")
else:
    print("Public subnets already associated with Public Route Table")

clixx_priv_associations = [assoc for assoc in clixx_priv_route_table.associations if assoc.subnet_id in [clixx_private_subnet_1_id, clixx_private_subnet_2_id]]
if not clixx_priv_associations:
    clixx_priv_route_table.associate_with_subnet(SubnetId=clixx_private_subnet_1_id)
    clixx_priv_route_table.associate_with_subnet(SubnetId=clixx_private_subnet_2_id)
    print("Private subnets associated with Private Route Table")
else:
    print("Private subnets already associated with Private Route Table")
print("Route tables created and associated with subnets.")

# --- Security Group ---
clixx_existing_public_sg = list(clixx_ec2_resource.security_groups.filter(Filters=[{'Name': 'group-name', 'Values': ['CLIXXSTACKSG']}]))
if not clixx_existing_public_sg:
    clixx_public_sg = clixx_ec2_resource.create_security_group(
        GroupName='CLIXXSTACKSG',
        Description='Public Security Group for App Servers',
        VpcId=clixx_vpc.id
    )
    clixx_public_sg.create_tags(Tags=[{'Key': 'Name', 'Value': 'CLIXXSTACKSG'}])
    clixx_ec2_client.authorize_security_group_ingress(
        GroupId=clixx_public_sg.id,
        IpPermissions=[
            {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},
            {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},
            {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
        ]
    )
    print(f"Public Security Group created: {clixx_public_sg.id}")
else:
    clixx_public_sg = clixx_existing_public_sg[0]
    print(f"Public Security Group already exists with ID: {clixx_public_sg.id}")

clixx_existing_private_sg = list(clixx_ec2_resource.security_groups.filter(Filters=[{'Name': 'group-name', 'Values': ['CLIXXSTACKSGPRIV']}]))
if not clixx_existing_private_sg:
    clixx_private_sg = clixx_ec2_resource.create_security_group(
        GroupName='CLIXXSTACKSGPRIV',
        Description='Private Security Group for RDS and EFS',
        VpcId=clixx_vpc.id
    )
    clixx_private_sg.create_tags(Tags=[{'Key': 'Name', 'Value': 'CLIXXSTACKSGPRIV'}])
    clixx_ec2_client.authorize_security_group_ingress(
        GroupId=clixx_private_sg.id,
        IpPermissions=[
            {'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},
            {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},
        ]
    )
    print(f"Private Security Group created: {clixx_private_sg.id}")
else:
    clixx_private_sg = clixx_existing_private_sg[0]
    print(f"Private Security Group already exists with ID: {clixx_private_sg.id}")
print(f"Security groups created: Public SG (ID: {clixx_public_sg.id}), Private SG (ID: {clixx_private_sg.id})")

# --- RDS Instance ---
clixx_DBSubnetGroupName = 'CLIXXSTACKDBSUBNETGROUP'
clixx_response = clixx_rds_client.describe_db_subnet_groups()
clixx_db_subnet_group_exists = False
for clixx_subnet_group in clixx_response['DBSubnetGroups']:
    if clixx_subnet_group['DBSubnetGroupName'] == clixx_DBSubnetGroupName:
        clixx_db_subnet_group_exists = True
        clixx_DBSubnetGroupName = clixx_subnet_group['DBSubnetGroupName']
        print(f"DB Subnet Group '{clixx_DBSubnetGroupName}' already exists. Proceeding with the existing one.")
        break

if not clixx_db_subnet_group_exists:
    clixx_response = clixx_rds_client.create_db_subnet_group(
        DBSubnetGroupName=clixx_DBSubnetGroupName,
        SubnetIds=[clixx_private_subnet_1_id, clixx_private_subnet_2_id],
        DBSubnetGroupDescription='My stack DB subnet group',
        Tags=[{'Key': 'Name', 'Value': 'CLIXXSTACKDBSUBNETGROUP'}]
    )
    clixx_DBSubnetGroupName = clixx_response['DBSubnetGroup']['DBSubnetGroupName']
    print(f"DB Subnet Group '{clixx_DBSubnetGroupName}' created successfully.")

clixx_db_instances = clixx_rds_client.describe_db_instances()
clixx_db_instance_identifiers = [db['DBInstanceIdentifier'] for db in clixx_db_instances['DBInstances']]
if clixx_db_instance_identifier in clixx_db_instance_identifiers:
    clixx_instances = clixx_rds_client.describe_db_instances(DBInstanceIdentifier=clixx_db_instance_identifier)
    print(f"DB Instance '{clixx_db_instance_identifier}' already exists. Details: {clixx_instances}")
else:
    print(f"DB Instance '{clixx_db_instance_identifier}' not found. Restoring from snapshot...")
    clixx_response = clixx_rds_client.restore_db_instance_from_db_snapshot(
        DBInstanceIdentifier=clixx_db_instance_identifier,
        DBSnapshotIdentifier=clixx_db_snapshot_identifier,
        DBInstanceClass=clixx_db_instance_class,
        VpcSecurityGroupIds=[clixx_private_sg.id],
        DBSubnetGroupName=clixx_DBSubnetGroupName,
        PubliclyAccessible=False,
        Tags=[{'Key': 'Name', 'Value': 'wordpressdbclixx'}]
    )
    print(f"Restore operation initiated. Response: {clixx_response}")

# --- Create EFS file system ---
clixx_efs_response = clixx_efs_client.describe_file_systems(
    CreationToken='CLiXX-EFS'
)

# If EFS exists, proceed with the existing EFS
if clixx_efs_response['FileSystems']:
    clixx_file_system_id = clixx_efs_response['FileSystems'][0]['FileSystemId']
    print(f"EFS already exists with FileSystemId: {clixx_file_system_id}")
else:
    # Create EFS if it doesn't exist
    clixx_efs_response = clixx_efs_client.create_file_system(
        CreationToken='CLiXX-EFS',
        PerformanceMode='generalPurpose'
    )
    clixx_file_system_id = clixx_efs_response['FileSystemId']
    print(f"EFS created with FileSystemId: {clixx_file_system_id}")

# Wait until the EFS file system is in 'available' state
while True:
    clixx_efs_info = clixx_efs_client.describe_file_systems(
        FileSystemId=clixx_file_system_id
    )
    clixx_lifecycle_state = clixx_efs_info['FileSystems'][0]['LifeCycleState']
    if clixx_lifecycle_state == 'available':
        print(f"EFS CLiXX-EFS is now available with FileSystemId: {clixx_file_system_id}")
        break
    else:
        print(f"EFS is in '{clixx_lifecycle_state}' state. Waiting for it to become available...")
        time.sleep(10)

# Add a tag to the EFS file system
clixx_efs_client.create_tags(FileSystemId=clixx_file_system_id, Tags=[{'Key': 'Name', 'Value': 'CLiXX-EFS'}])

# After ensuring the file system is available, create the mount targets in the private subnets
clixx_private_subnet_ids = [clixx_private_subnet_1_id, clixx_private_subnet_2_id]
for clixx_private_subnet_id in clixx_private_subnet_ids:
    # Check if mount target already exists for the subnet
    clixx_mount_targets_response = clixx_efs_client.describe_mount_targets(
        FileSystemId=clixx_file_system_id
    )
    # Extract the list of subnet IDs for existing mount targets
    clixx_existing_mount_targets = [mt['SubnetId'] for mt in clixx_mount_targets_response['MountTargets']]
    # If the current subnet does not have a mount target, create one
    if clixx_private_subnet_id not in clixx_existing_mount_targets:
        clixx_mount_target_response = clixx_efs_client.create_mount_target(
            FileSystemId=clixx_file_system_id,
            SubnetId=clixx_private_subnet_id,
            SecurityGroups=[clixx_private_sg.id]
        )
        print(f"Mount target created in Private Subnet: {clixx_private_subnet_id}")
    else:
        print(f"Mount target already exists in Private Subnet: {clixx_private_subnet_id}")

# Attach Lifecycle Policy (optional)
clixx_efs_client.put_lifecycle_configuration(
    FileSystemId=clixx_file_system_id,
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
clixx_all_tg_response = clixx_elbv2_client.describe_target_groups()
clixx_target_groups = clixx_all_tg_response['TargetGroups']
# Check if 'CLiXX-TG' exists in the list of target groups
clixx_target_group_arn = None
for clixx_tg in clixx_target_groups:
    if clixx_tg['TargetGroupName'] == 'CLiXX-TG':
        clixx_target_group_arn = clixx_tg['TargetGroupArn']
        print(f"Target Group already exists with ARN: {clixx_target_group_arn}")
        break
if clixx_target_group_arn is None:
    # Target group does not exist, create a new one
    print("Target Group 'CLiXX-TG' not found. Creating a new target group.")
    clixx_target_group = clixx_elbv2_client.create_target_group(
        Name='CLiXX-TG',
        Protocol='HTTP',
        Port=80,
        VpcId=clixx_vpc.id,
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
    clixx_target_group_arn = clixx_target_group['TargetGroups'][0]['TargetGroupArn']
    print(f"Target Group created with ARN: {clixx_target_group_arn}")

# --- Create Application Load Balancer ---
# List all load balancers
clixx_all_lb_response = clixx_elbv2_client.describe_load_balancers()
clixx_load_balancers = clixx_all_lb_response['LoadBalancers']
# Check if 'CLiXX-LB' exists in the list of load balancers
clixx_load_balancer_arn = None
for clixx_lb in clixx_load_balancers:
    if clixx_lb['LoadBalancerName'] == 'CLiXX-LB':
        clixx_load_balancer_arn = clixx_lb['LoadBalancerArn']
        print(f"Load Balancer already exists with ARN: {clixx_load_balancer_arn}")
        break
if clixx_load_balancer_arn is None:
    # Load balancer does not exist, create a new one
    print("Load Balancer 'CLiXX-LB' not found. Creating a new load balancer.")
    clixx_load_balancer = clixx_elbv2_client.create_load_balancer(
        Name='CLiXX-LB',
        Subnets=[clixx_subnet_1_id, clixx_subnet_2_id],
        SecurityGroups=[clixx_public_sg.id],
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
    clixx_load_balancer_arn = clixx_load_balancer['LoadBalancers'][0]['LoadBalancerArn']
    print(f"Load Balancer created with ARN: {clixx_load_balancer_arn}")

# Create Listener for the Load Balancer (HTTP & HTTPS)
# Retrieve listeners for the load balancer
clixx_http_listener_response = clixx_elbv2_client.describe_listeners(LoadBalancerArn=clixx_load_balancer_arn)
clixx_existing_listeners = clixx_http_listener_response['Listeners']

# Check if HTTP listener exists
clixx_http_listener_exists = any(listener['Protocol'] == 'HTTP' for listener in clixx_existing_listeners)
if not clixx_http_listener_exists:
    clixx_elbv2_client.create_listener(
        LoadBalancerArn=clixx_load_balancer_arn,
        Protocol='HTTP',
        Port=80,
        DefaultActions=[{'Type': 'forward', 'TargetGroupArn': clixx_target_group_arn}]
    )
    print(f"HTTP Listener created for Load Balancer: {clixx_load_balancer_arn}")
else:
    print("HTTP Listener already exists.")

# Check if HTTPS listener exists
clixx_https_listener_exists = any(listener['Protocol'] == 'HTTPS' for listener in clixx_existing_listeners)
if not clixx_https_listener_exists:
    clixx_elbv2_client.create_listener(
        LoadBalancerArn=clixx_load_balancer_arn,
        Protocol='HTTPS',
        Port=443,
        SslPolicy='ELBSecurityPolicy-2016-08',
        Certificates=[{
            'CertificateArn': clixx_certificate_arn
        }],
        DefaultActions=[{'Type': 'forward', 'TargetGroupArn': clixx_target_group_arn}]
    )
    print(f"HTTPS Listener created for Load Balancer: {clixx_load_balancer_arn}")
else:
    print("HTTPS Listener already exists.")

# --- Create Route 53 record for the load balancer ---
clixx_route53_response = clixx_route53_client.list_resource_record_sets(
    HostedZoneId=clixx_hosted_zone_id
)
# Check if the record already exists using a broader approach
clixx_record_exists = any(record['Name'] == clixx_record_name for record in clixx_route53_response['ResourceRecordSets'])
if not clixx_record_exists:
    clixx_route53_client.change_resource_record_sets(
        HostedZoneId=clixx_hosted_zone_id,
        ChangeBatch={
            'Comment': 'Create a record for the CLiXX Load Balancer',
            'Changes': [{
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
            }]
        }
    )
    print(f"Route 53 record created for {clixx_record_name}")
else:
    print(f"Route 53 record already exists for {clixx_record_name}")

# Encode the user data to Base64
clixx_user_data_script = f'''#!/bin/bash -x
# Basic logging
exec > >(tee /var/log/userdata.log) 2>&1

# Set variables
DB_USER="wordpressuser"
DB_USER_PASSWORD="W3lcome123"
DB_HOST="wordpressdbclixx.cdk4eccemey1.us-east-1.rds.amazonaws.com"
DB_NAME="wordpressdb"
efs_name="CLiXX-EFS"
clixx_file_system_id="{clixx_file_system_id}"
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
MOUNT_POINT="/var/www/html"
RECORD_NAME="{clixx_record_name}"
export DB_USER DB_USER_PASSWORD DB_HOST DB_NAME RECORD_NAME

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
cd "$MOUNT_POINT"
if [ -f "wp-config-sample.php" ]; then
    cp wp-config-sample.php wp-config.php
    sed -i "s/database_name_here/${DB_NAME}/; s/username_here/${DB_USER}/; s/password_here/${DB_USER_PASSWORD}/; s/localhost/${DB_HOST}/" wp-config.php
    sed -i "81i if (isset(\$_SERVER['HTTP_X_FORWARDED_PROTO']) && \$_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {{ \$_SERVER['HTTPS'] = 'on'; }}" wp-config.php
else
    echo "wp-config-sample.php does not exist!" >> /var/log/userdata.log
    exit 1
fi

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

# WordPress Installation on EFS
cd "$MOUNT_POINT"
sudo wget https://wordpress.org/latest.tar.gz
sudo tar -xzf latest.tar.gz
sudo mv wordpress/* "$MOUNT_POINT"
sudo rm -rf wordpress latest.tar.gz

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
    print(f"Launch Template already exists with ID: {clixx_launch_template_id}")
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
    print(f"Launch Template created with ID: {clixx_launch_template_id}")

# --- Create Auto Scaling Group ---
# List all Auto Scaling Groups and check for 'CLiXX-ASG'
clixx_all_asg_response = clixx_autoscaling_client.describe_auto_scaling_groups()
clixx_asg_names = [asg['AutoScalingGroupName'] for asg in clixx_all_asg_response['AutoScalingGroups']]
if 'CLiXX-ASG' in clixx_asg_names:
    print("Auto Scaling Group already exists.")
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
    print("Auto Scaling Group created successfully.")


