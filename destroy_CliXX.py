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

##################### Delete the DB instance
# Step 1: Check for and delete RDS instance
db_instance_name = 'wordpressdbclixx'
rds_instances = rds_client.describe_db_instances()
db_instance_exists = any(instance['DBInstanceIdentifier'] == db_instance_name for instance in rds_instances['DBInstances'])
if db_instance_exists:
    rds_client.delete_db_instance(
        DBInstanceIdentifier=db_instance_name,
        SkipFinalSnapshot=True
    )
    print(f"RDS instance '{db_instance_name}' deletion initiated.")
else:
    print(f"RDS instance '{db_instance_name}' not found.")

# Step 2: Wait for RDS instance deletion
while db_instance_exists:
    rds_instances = rds_client.describe_db_instances()
    db_instance_exists = any(instance['DBInstanceIdentifier'] == db_instance_name for instance in rds_instances['DBInstances'])
    if not db_instance_exists:
        print(f"RDS instance '{db_instance_name}' deleted successfully.")
    else:
        print(f"Waiting for RDS instance '{db_instance_name}' to be deleted...")
        time.sleep(10)

################### Delete Application Load Balancer
# Name of the load balancer to delete
lb_name = 'CLiXX-LB'
# Describe all load balancers to find the one with the specified name
load_balancers = elbv2_client.describe_load_balancers()
# Loop through load balancers and find the one with the matching name
for lb in load_balancers['LoadBalancers']:
    if lb['LoadBalancerName'] == lb_name:
        lb_arn = lb['LoadBalancerArn']
        
        # Delete the load balancer using its ARN
        elbv2_client.delete_load_balancer(LoadBalancerArn=lb_arn)
        print(f"Application Load Balancer '{lb_name}' deleted.")
        break

##################### Delete mount target befor deleting efs file
# Specify the EFS name
efs_name = 'CLiXX-EFS'
# Describe all file systems
fs_info = efs_client.describe_file_systems()
file_system_id = None
# Find the file system with the specified name
for fs in fs_info['FileSystems']:
    tags = efs_client.list_tags_for_resource(ResourceId=fs['FileSystemId'])['Tags']
    if any(tag['Key'] == 'Name' and tag['Value'] == efs_name for tag in tags):
        file_system_id = fs['FileSystemId']
        print(f"Found EFS with File System ID: {file_system_id}")
        break

if file_system_id is None:
    print(f"No EFS found with the name '{efs_name}'.")
else:
    # Retrieve all mount targets for the specified EFS
    mount_targets_info = efs_client.describe_mount_targets(FileSystemId=file_system_id)
    mount_target_ids = [mount['MountTargetId'] for mount in mount_targets_info['MountTargets']]

    # Delete each mount target
    for mount_target_id in mount_target_ids:
        efs_client.delete_mount_target(MountTargetId=mount_target_id)
        print(f"Deleted mount target: {mount_target_id}")

        # Wait for the mount target to be deleted
        while True:
            time.sleep(5)
            mount_target_info = efs_client.describe_mount_targets(FileSystemId=file_system_id)

            if not any(mount['MountTargetId'] == mount_target_id for mount in mount_target_info['MountTargets']):
                print(f"Mount target {mount_target_id} is deleted.")
                break

    # Delete the EFS file system after all mount targets are deleted
    efs_client.delete_file_system(FileSystemId=file_system_id)
    print(f"Deleted EFS with File System ID: {file_system_id}")

#################### Delete Target Group
# Define your target group name
tg_name = 'CLiXX-TG'
# Remove the Target Group if it exists
response = elbv2_client.describe_target_groups(Names=[tg_name])
if response['TargetGroups']:
    tg_arn = response['TargetGroups'][0]['TargetGroupArn']
    # Delete the Target Group
    elbv2_client.delete_target_group(TargetGroupArn=tg_arn)
    print(f"Target Group '{tg_name}' deleted.")
else:
    print(f"Target group '{tg_name}' does not exist.")

################## Delete Route 53 record for the load balancer
# Specify your Hosted Zone ID and the record name
hosted_zone_id = 'Z0881876FFUR3OKRNM20'
record_name = 'dev.clixx-dasola.com'
# --- Route 53 Record Deletion ---

# Check if the Route 53 record set already exists
response = route53_client.list_resource_record_sets(HostedZoneId=hosted_zone_id)
record_found = False

for record in response['ResourceRecordSets']:
    if record['Name'].rstrip('.') == record_name:
        route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'DELETE',
                        'ResourceRecordSet': record
                    }
                ]
            }
        )
        record_found = True
        break  # Exit the loop after deletion
    print(f"Record '{record_name}' deleted.")

#################### Delete Auto Scaling Group 
# Specify the Auto Scaling Group Name
autoscaling_group_name = 'CLiXX-ASG'
# Delete the Auto Scaling Group
response = autoscaling_client.delete_auto_scaling_group(
    AutoScalingGroupName=autoscaling_group_name,
    ForceDelete=True  
)
print("Auto Scaling Group deleted:", response)
# Check if the Auto Scaling Group is deleted
while True:
    time.sleep(120)  # Wait for a few seconds
    asg_status = autoscaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=[autoscaling_group_name]
    )
    if not asg_status['AutoScalingGroups']:
        print(f"Auto Scaling Group '{autoscaling_group_name}' deleted successfully.")
        break

#################### Delete Launch Template
# Specify the Launch Template Name
launch_template_name = 'CLiXX-LT'
# Get the Launch Template ID based on the Launch Template Name
response = ec2_client.describe_launch_templates(
    Filters=[{'Name': 'launch-template-name', 'Values': [launch_template_name]}]
)
# Extract the Launch Template ID
launch_template_id = response['LaunchTemplates'][0]['LaunchTemplateId']
# Delete the Launch Template
delete_response = ec2_client.delete_launch_template(
    LaunchTemplateId=launch_template_id
)
print("Launch Template deleted:", delete_response)

#################### Fetch and Delete Security Group
# Security Group Names
public_sg_name = 'TESTSTACKSG'
private_sg_name = 'TESTSTACKSGPRIV'
# ---- Deleting Public Security Group ----
# Fetch the public security group by name
public_sg = list(ec2_resource.security_groups.filter(Filters=[{'Name': 'group-name', 'Values': [public_sg_name]}]))
if public_sg:
    public_sg_id = public_sg[0].id

    # Describe instances using the public security group
    public_instances = ec2_client.describe_instances(Filters=[{'Name': 'instance.group-id', 'Values': [public_sg_id]}])
    if public_instances['Reservations']:
        print(f"Cannot delete Security Group '{public_sg_name}' (ID: {public_sg_id}). Instances are still using this SG.")
    else:
        # Describe Network Interfaces (ENIs) attached to this security group
        public_enis = ec2_client.describe_network_interfaces(Filters=[{'Name': 'group-id', 'Values': [public_sg_id]}])
        if public_enis['NetworkInterfaces']:
            print(f"Cannot delete Security Group '{public_sg_name}' (ID: {public_sg_id}). Network Interfaces (ENIs) are still using this SG.")
        else:
            # No dependencies found, proceed to delete the security group
            print(f"Deleting Security Group: {public_sg_name} (ID: {public_sg_id})")
            ec2_client.delete_security_group(GroupId=public_sg_id)
            print(f"Security Group '{public_sg_name}' (ID: {public_sg_id}) deleted successfully.")
else:
    print(f"Security Group '{public_sg_name}' not found.")
# ---- Deleting Private Security Group ----
# Fetch the private security group by name
private_sg = list(ec2_resource.security_groups.filter(Filters=[{'Name': 'group-name', 'Values': [private_sg_name]}]))
if private_sg:
    private_sg_id = private_sg[0].id

    # Describe instances using the private security group
    private_instances = ec2_client.describe_instances(Filters=[{'Name': 'instance.group-id', 'Values': [private_sg_id]}])
    if private_instances['Reservations']:
        print(f"Cannot delete Security Group '{private_sg_name}' (ID: {private_sg_id}). Instances are still using this SG.")
    else:
        # Describe Network Interfaces (ENIs) attached to this security group
        private_enis = ec2_client.describe_network_interfaces(Filters=[{'Name': 'group-id', 'Values': [private_sg_id]}])
        if private_enis['NetworkInterfaces']:
            print(f"Cannot delete Security Group '{private_sg_name}' (ID: {private_sg_id}). Network Interfaces (ENIs) are still using this SG.")
        else:
            # No dependencies found, proceed to delete the security group
            print(f"Deleting Security Group: {private_sg_name} (ID: {private_sg_id})")
            ec2_client.delete_security_group(GroupId=private_sg_id)
            print(f"Security Group '{private_sg_name}' (ID: {private_sg_id}) deleted successfully.")
else:
    print(f"Security Group '{private_sg_name}' not found.")

#################### Fetch and Delete DB Subnet Group
# DB Subnet Group Name
DBSubnetGroupName = 'teststackdbsubnetgroup'
# --- Check if DB Subnet Group Exists ---
response = rds_client.describe_db_subnet_groups()
# Flag to check if the subnet group exists
db_subnet_group_exists = False
# Loop through all subnet groups to find a match
for subnet_group in response['DBSubnetGroups']:
    if subnet_group['DBSubnetGroupName'] == DBSubnetGroupName:
        db_subnet_group_exists = True
        print(f"DB Subnet Group '{DBSubnetGroupName}' found. Proceeding with checks.")
        break
# --- Delete DB Subnet Group if it exists ---
if db_subnet_group_exists:
    # Check if any databases are associated with the subnet group
    dbs_response = rds_client.describe_db_instances()
    dbs_using_subnet_group = []
    
    # Check all databases to find if they are using the DB Subnet Group
    for db_instance in dbs_response['DBInstances']:
        if db_instance['DBSubnetGroup']['DBSubnetGroupName'] == DBSubnetGroupName:
            dbs_using_subnet_group.append(db_instance['DBInstanceIdentifier'])
    if dbs_using_subnet_group:
        print(f"Databases using the subnet group: {dbs_using_subnet_group}. Waiting for deletion...")
        # Wait until all databases are deleted
        for db_instance_id in dbs_using_subnet_group:
            while True:
                try:
                    db_instance_status = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_id)
                    status = db_instance_status['DBInstances'][0]['DBInstanceStatus']
                    if status == 'deleting':
                        print(f"Database '{db_instance_id}' is still being deleted. Waiting...")
                    else:
                        print(f"Database '{db_instance_id}' has status: {status}")
                    time.sleep(30)  # Wait for 30 seconds before checking again
                except rds_client.exceptions.DBInstanceNotFoundFault:
                    print(f"Database '{db_instance_id}' deleted successfully.")
                    break

        # Once all databases are deleted, proceed to delete the DB Subnet Group
        print(f"All databases deleted. Proceeding to delete DB Subnet Group '{DBSubnetGroupName}'.")
        rds_client.delete_db_subnet_group(DBSubnetGroupName=DBSubnetGroupName)
        print(f"DB Subnet Group '{DBSubnetGroupName}' deleted successfully.")
    else:
        # No databases are using the subnet group, safe to delete
        print(f"No databases found using DB Subnet Group '{DBSubnetGroupName}'. Proceeding to delete.")
        rds_client.delete_db_subnet_group(DBSubnetGroupName=DBSubnetGroupName)
        print(f"DB Subnet Group '{DBSubnetGroupName}' deleted successfully.")
else:
    print(f"DB Subnet Group '{DBSubnetGroupName}' not found.")

#################### Delete the VPC 
# Specify the CIDR block and VPC name
vpc_cidr_block = '10.0.0.0/16'
vpc_name = 'TESTSTACKVPC'
# Fetch the VPC by CIDR block and VPC name
vpcs = ec2_client.describe_vpcs(
    Filters=[
        {'Name': 'cidr', 'Values': [vpc_cidr_block]},
        {'Name': 'tag:Name', 'Values': [vpc_name]}
    ]
)
# Fetch the VPC by CIDR block and VPC name
vpcs = ec2_client.describe_vpcs(
    Filters=[
        {'Name': 'cidr', 'Values': [vpc_cidr_block]},
        {'Name': 'tag:Name', 'Values': [vpc_name]}
    ]
)
if vpcs['Vpcs']:
    # Get the VPC ID
    vpc_id = vpcs['Vpcs'][0]['VpcId']
    print(f"VPC found: {vpc_id} with Name '{vpc_name}'. Deleting dependencies...")

    # 1. Detach and delete internet gateways
    igws = ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
    for igw in igws['InternetGateways']:
        igw_id = igw['InternetGatewayId']
        print(f"Detaching and deleting Internet Gateway: {igw_id}")
        ec2_client.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        ec2_client.delete_internet_gateway(InternetGatewayId=igw_id)
    # 2. Delete NAT gateways
    nat_gateways = ec2_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    for nat_gw in nat_gateways['NatGateways']:
        nat_gw_id = nat_gw['NatGatewayId']
        print(f"Deleting NAT Gateway: {nat_gw_id}")
        ec2_client.delete_nat_gateway(NatGatewayId=nat_gw_id)
    # 3. Delete subnets
    subnets = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    for subnet in subnets['Subnets']:
        subnet_id = subnet['SubnetId']
        print(f"Deleting Subnet: {subnet_id}")
        ec2_client.delete_subnet(SubnetId=subnet_id)
    # 4. Delete route tables (except the main route table)
    route_tables = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    for rt in route_tables['RouteTables']:
        rt_id = rt['RouteTableId']
        associations = rt['Associations']
        if not any(assoc['Main'] for assoc in associations):
            print(f"Deleting Route Table: {rt_id}")
            ec2_client.delete_route_table(RouteTableId=rt_id)
    # 5. Delete security groups (except default group)
    security_groups = ec2_client.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    for sg in security_groups['SecurityGroups']:
        if sg['GroupName'] != 'default':
            sg_id = sg['GroupId']
            print(f"Deleting Security Group: {sg_id}")
            ec2_client.delete_security_group(GroupId=sg_id)
    # 6. Delete VPC peering connections
    vpc_peering_connections = ec2_client.describe_vpc_peering_connections(Filters=[{'Name': 'requester-vpc-info.vpc-id', 'Values': [vpc_id]}])
    for pcx in vpc_peering_connections['VpcPeeringConnections']:
        pcx_id = pcx['VpcPeeringConnectionId']
        print(f"Deleting VPC Peering Connection: {pcx_id}")
        ec2_client.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)
    # Finally, delete the VPC
    print(f"Deleting VPC: {vpc_id}")
    ec2_client.delete_vpc(VpcId=vpc_id)
    print(f"VPC {vpc_id} with Name '{vpc_name}' deleted.")
else:
    print(f"No VPC found with CIDR block {vpc_cidr_block} and Name '{vpc_name}'")
