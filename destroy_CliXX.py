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
lb_name = 'CLIXX-LoadBalancer'
efs_name = 'CLiXX-EFS'
tg_name = 'CLiXX-TG'
autoscaling_group_name = 'CLiXX-ASG'
launch_template_name = 'CLiXX-LT'
hosted_zone_id = 'Z0881876FFUR3OKRNM20'
record_name = 'dev.clixx-dasola.com'
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

# Define delete functions for resources
def delete_rds_instance():
    try:
        rds_client.delete_db_instance(DBInstanceIdentifier=db_instance_name, SkipFinalSnapshot=True)
        logger.info(f"RDS instance '{db_instance_name}' deletion initiated.")
    except ClientError as e:
        if "DBInstanceNotFound" in str(e):
            logger.info(f"RDS instance '{db_instance_name}' not found, skipping.")
        else:
            logger.error(f"Failed to delete RDS Instance: {e}")

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
                time.sleep(5)
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

delete_with_retries(delete_target_group)

def delete_autoscaling_group():
    try:
        autoscaling_client.delete_auto_scaling_group(AutoScalingGroupName=autoscaling_group_name, ForceDelete=True)
        logger.info(f"Auto Scaling Group '{autoscaling_group_name}' deletion initiated.")
    except ClientError as e:
        logger.error(f"Failed to delete Auto Scaling Group: {e}")

delete_with_retries(delete_autoscaling_group)

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

delete_with_retries(delete_launch_template)

def delete_route53_record():
    try:
        response = route53_client.list_resource_record_sets(HostedZoneId=hosted_zone_id)
        for record in response['ResourceRecordSets']:
            if record['Name'].rstrip('.') == record_name:
                route53_client.change_resource_record_sets(
                    HostedZoneId=hosted_zone_id,
                    ChangeBatch={'Changes': [{'Action': 'DELETE', 'ResourceRecordSet': record}]}
                )
                logger.info(f"Record '{record_name}' deleted.")
                break
    except ClientError as e:
        logger.error(f"Failed to delete Route 53 record: {e}")

delete_with_retries(delete_route53_record)

# Delete VPC and its dependencies
def delete_internet_gateways(vpc_id):
    igws = ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
    for igw in igws['InternetGateways']:
        igw_id = igw['InternetGatewayId']
        logger.info(f"Detaching and deleting Internet Gateway: {igw_id}")
        delete_with_retries(ec2_client.detach_internet_gateway, InternetGatewayId=igw_id, VpcId=vpc_id)
        delete_with_retries(ec2_client.delete_internet_gateway, InternetGatewayId=igw_id)

def delete_nat_gateways(vpc_id):
    nat_gateways = ec2_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    for nat_gw in nat_gateways['NatGateways']:
        nat_gw_id = nat_gw['NatGatewayId']
        logger.info(f"Deleting NAT Gateway: {nat_gw_id}")
        delete_with_retries(ec2_client.delete_nat_gateway, NatGatewayId=nat_gw_id)
        wait_for_nat_gateway_deletion(nat_gw_id)

def wait_for_nat_gateway_deletion(nat_gw_id):
    while True:
        try:
            response = ec2_client.describe_nat_gateways(NatGatewayIds=[nat_gw_id])
            state = response['NatGateways'][0]['State']
            if state == 'deleted':
                logger.info(f"NAT Gateway {nat_gw_id} has been deleted.")
                break
            else:
                logger.info(f"NAT Gateway {nat_gw_id} is in state '{state}'. Waiting for deletion...")
                time.sleep(10)
        except ClientError as e:
            if 'NatGatewayNotFound' in str(e):
                logger.info(f"NAT Gateway {nat_gw_id} not found, assumed deleted.")
                break
            else:
                raise e

def delete_subnets(vpc_id):
    subnets = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    for subnet in subnets['Subnets']:
        subnet_id = subnet['SubnetId']
        logger.info(f"Deleting Subnet: {subnet_id}")
        delete_with_retries(ec2_client.delete_subnet, SubnetId=subnet_id)

def delete_route_tables(vpc_id):
    route_tables = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    for rt in route_tables['RouteTables']:
        rt_id = rt['RouteTableId']
        associations = rt.get('Associations', [])
        if not any(assoc.get('Main', False) for assoc in associations):
            logger.info(f"Deleting Route Table: {rt_id}")
            delete_with_retries(ec2_client.delete_route_table, RouteTableId=rt_id)

def delete_security_groups(vpc_id):
    security_groups = ec2_client.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    for sg in security_groups['SecurityGroups']:
        if sg['GroupName'] != 'default':
            sg_id = sg['GroupId']
            logger.info(f"Deleting Security Group: {sg_id}")
            delete_with_retries(ec2_client.delete_security_group, GroupId=sg_id)

def delete_vpc(vpc_id):
    delete_internet_gateways(vpc_id)
    delete_nat_gateways(vpc_id)
    delete_subnets(vpc_id)
    delete_route_tables(vpc_id)
    delete_security_groups(vpc_id)
    logger.info(f"Deleting VPC: {vpc_id}")
    delete_with_retries(ec2_client.delete_vpc, VpcId=vpc_id)

# Main delete flow for VPC
vpcs = ec2_client.describe_vpcs(
    Filters=[
        {'Name': 'cidr', 'Values': [vpc_cidr_block]},
        {'Name': 'tag:Name', 'Values': [vpc_name]}
    ]
)

if vpcs['Vpcs']:
    vpc_id = vpcs['Vpcs'][0]['VpcId']
    logger.info(f"VPC found: {vpc_id} with Name '{vpc_name}'. Deleting dependencies...")
    delete_vpc(vpc_id)
else:
    logger.info(f"No VPC found with CIDR block {vpc_cidr_block} and Name '{vpc_name}'")
