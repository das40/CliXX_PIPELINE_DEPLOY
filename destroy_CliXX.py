#!/usr/bin/env python3
import boto3
import logging
import time
from botocore.exceptions import ClientError

# Set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

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

# Resource identifiers
db_instance_name = 'wordpressdbclixx'
lb_name = 'CLiXX-LB'
efs_name = 'CLiXX-EFS'
tg_name = 'CLiXX-TG'
autoscaling_group_name = 'CLiXX-ASG'
launch_template_name = 'CLiXX-LT'
hosted_zone_id = 'Z0881876FFUR3OKRNM20'
record_name = 'dev.clixx-dasola.com'
public_sg_name = 'CLIXXSTACKSG'
private_sg_name = 'CLIXXSTACKSGPRIV'
DBSubnetGroupName = 'clixxstackdbsubnetgroup'
vpc_name = 'CLIXXSTACKVPC'
vpc_cidr_block = '10.0.0.0/16'


RETRY_LIMIT = 5

def delete_with_retries(delete_func, *args, **kwargs):
    for attempt in range(RETRY_LIMIT):
        try:
            delete_func(*args, **kwargs)
            return
        except ClientError as e:
            logger.warning(f"Attempt {attempt + 1} failed: {e}")
            if attempt < RETRY_LIMIT - 1:
                time.sleep(10)
            else:
                logger.error(f"Failed to delete after {RETRY_LIMIT} attempts.")
                raise


def delete_rds_instance():
    try:
        rds_client.delete_db_instance(DBInstanceIdentifier=db_instance_name, SkipFinalSnapshot=True)
        logger.info(f"RDS instance '{db_instance_name}' deletion initiated.")
    except ClientError as e:
        if "DBInstanceNotFound" in str(e):
            logger.info(f"RDS instance '{db_instance_name}' not found, skipping.")
        else:
            logger.error(f"Failed to delete RDS Instance: {e}")

# Use delete_with_retries for RDS instance deletion
delete_with_retries(delete_rds_instance)


def delete_load_balancer():
    try:
        load_balancers = elbv2_client.describe_load_balancers(Names=[lb_name])
        lb_arn = load_balancers['LoadBalancers'][0]['LoadBalancerArn']
        elbv2_client.delete_load_balancer(LoadBalancerArn=lb_arn)
        logger.info(f"Application Load Balancer '{lb_name}' deletion initiated.")
    except ClientError as e:
        if "LoadBalancerNotFound" in str(e):
            logger.info(f"Load Balancer '{lb_name}' not found, skipping.")
        else:
            logger.error(f"Failed to delete Load Balancer: {e}")
# Wrap the delete function in delete_with_retries
delete_with_retries(delete_load_balancer)


def delete_efs_and_mount_targets():
    try:
        fs_info = efs_client.describe_file_systems()
        for fs in fs_info['FileSystems']:
            tags = efs_client.list_tags_for_resource(ResourceId=fs['FileSystemId'])['Tags']
            if any(tag['Key'] == 'Name' and tag['Value'] == efs_name for tag in tags):
                file_system_id = fs['FileSystemId']
                mount_targets = efs_client.describe_mount_targets(FileSystemId=file_system_id)['MountTargets']
                for mt in mount_targets:
                    efs_client.delete_mount_target(MountTargetId=mt['MountTargetId'])
                    logger.info(f"Deleted mount target: {mt['MountTargetId']}")
                time.sleep(5)  # Wait for mount targets to delete
                efs_client.delete_file_system(FileSystemId=file_system_id)
                logger.info(f"EFS '{efs_name}' deleted.")
                break
    except ClientError as e:
        if "FileSystemNotFound" in str(e):
            logger.info(f"EFS '{efs_name}' not found, skipping.")
        else:
            logger.error(f"Failed to delete EFS or its mount targets: {e}")
delete_with_retries(delete_efs_and_mount_targets)

def delete_target_group():
    try:
        response = elbv2_client.describe_target_groups(Names=[tg_name])
        tg_arn = response['TargetGroups'][0]['TargetGroupArn']
        elbv2_client.delete_target_group(TargetGroupArn=tg_arn)
        logger.info(f"Target Group '{tg_name}' deleted.")
    except ClientError as e:
        if "TargetGroupNotFound" in str(e):
            logger.info(f"Target group '{tg_name}' not found, skipping.")
        else:
            logger.error(f"Failed to delete Target Group: {e}")

def delete_autoscaling_group():
    try:
        autoscaling_client.delete_auto_scaling_group(AutoScalingGroupName=autoscaling_group_name, ForceDelete=True)
        logger.info(f"Auto Scaling Group '{autoscaling_group_name}' deletion initiated.")
    except ClientError as e:
        logger.error(f"Failed to delete Auto Scaling Group: {e}")

def delete_launch_template():
    try:
        response = ec2_client.describe_launch_templates(Filters=[{'Name': 'launch-template-name', 'Values': [launch_template_name]}])
        launch_template_id = response['LaunchTemplates'][0]['LaunchTemplateId']
        ec2_client.delete_launch_template(LaunchTemplateId=launch_template_id)
        logger.info(f"Launch Template '{launch_template_name}' deleted.")
    except ClientError as e:
        if "InvalidLaunchTemplateName.NotFoundException" in str(e):
            logger.info(f"Launch Template '{launch_template_name}' not found, skipping.")
        else:
            logger.error(f"Failed to delete Launch Template: {e}")

def delete_security_group(sg_name):
    try:
        security_group = ec2_client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': [sg_name]}])
        sg_id = security_group['SecurityGroups'][0]['GroupId']
        ec2_client.delete_security_group(GroupId=sg_id)
        logger.info(f"Security Group '{sg_name}' deleted.")
    except ClientError as e:
        if "DependencyViolation" in str(e):
            logger.warning(f"Dependency exists for Security Group '{sg_name}', cannot delete yet.")
        elif "InvalidGroup.NotFound" in str(e):
            logger.info(f"Security Group '{sg_name}' not found, skipping.")
        else:
            logger.error(f"Failed to delete Security Group '{sg_name}': {e}")

def delete_route53_record():
    try:
        response = route53_client.list_resource_record_sets(HostedZoneId=hosted_zone_id)
        for record in response['ResourceRecordSets']:
            if record['Name'].rstrip('.') == record_name:
                route53_client.change_resource_record_sets(
                    HostedZoneId=hosted_zone_id,
                    ChangeBatch={
                        'Changes': [{'Action': 'DELETE', 'ResourceRecordSet': record}]
                    }
                )
                logger.info(f"Record '{record_name}' deleted.")
                break
    except ClientError as e:
        logger.error(f"Failed to delete Route 53 record: {e}")

def delete_vpc_dependencies(vpc_id):
    # Detach and delete internet gateways
    igws = ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
    for igw in igws['InternetGateways']:
        ec2_client.detach_internet_gateway(InternetGatewayId=igw['InternetGatewayId'], VpcId=vpc_id)
        ec2_client.delete_internet_gateway(InternetGatewayId=igw['InternetGatewayId'])
        logger.info(f"Internet Gateway '{igw['InternetGatewayId']}' detached and deleted.")
    # Delete NAT Gateways
    nat_gateways = ec2_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    for nat_gw in nat_gateways['NatGateways']:
        ec2_client.delete_nat_gateway(NatGatewayId=nat_gw['NatGatewayId'])
        logger.info(f"NAT Gateway '{nat_gw['NatGatewayId']}' deletion initiated.")
        time.sleep(5)
    # Delete subnets and route tables
    #... Similar deletion methods for subnets, route tables, and VPC as above

#################### Fetch and Delete DB Subnet Group
# DB Subnet Group Name
DBSubnetGroupName = 'clixxstackdbsubnetgroup'
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
vpc_name = 'CLIXXSTACKVPC'
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

    print(f"No VPC found with CIDR block {vpc_cidr_block} and Name '{vpc_name}'")
