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

def delete_rds_instance():
    try:
        rds_client.delete_db_instance(DBInstanceIdentifier=db_instance_name, SkipFinalSnapshot=True)
        logger.info(f"RDS instance '{db_instance_name}' deletion initiated.")
        while True:
            time.sleep(10)
            instances = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_name)
            if not instances['DBInstances']:
                break
    except ClientError as e:
        if "DBInstanceNotFound" in str(e):
            logger.info(f"RDS instance '{db_instance_name}' not found, skipping.")
        else:
            logger.error(f"Failed to delete RDS Instance: {e}")

def delete_load_balancer():
    try:
        lb_arn = elbv2_client.describe_load_balancers(Names=[lb_name])['LoadBalancers'][0]['LoadBalancerArn']
        elbv2_client.delete_load_balancer(LoadBalancerArn=lb_arn)
        logger.info(f"Application Load Balancer '{lb_name}' deletion initiated.")
    except ClientError as e:
        if "LoadBalancerNotFound" in str(e):
            logger.info(f"Load Balancer '{lb_name}' not found, skipping.")

def delete_efs():
    try:
        fs_info = efs_client.describe_file_systems()
        for fs in fs_info['FileSystems']:
            tags = efs_client.list_tags_for_resource(ResourceId=fs['FileSystemId'])['Tags']
            if any(tag['Key'] == 'Name' and tag['Value'] == efs_name for tag in tags):
                file_system_id = fs['FileSystemId']
                for mt in efs_client.describe_mount_targets(FileSystemId=file_system_id)['MountTargets']:
                    efs_client.delete_mount_target(MountTargetId=mt['MountTargetId'])
                efs_client.delete_file_system(FileSystemId=file_system_id)
                logger.info(f"EFS '{efs_name}' deleted.")
    except ClientError as e:
        if "FileSystemNotFound" in str(e):
            logger.info(f"EFS '{efs_name}' not found, skipping.")

def delete_target_group():
    try:
        tg_arn = elbv2_client.describe_target_groups(Names=[tg_name])['TargetGroups'][0]['TargetGroupArn']
        elbv2_client.delete_target_group(TargetGroupArn=tg_arn)
        logger.info(f"Target Group '{tg_name}' deleted.")
    except ClientError as e:
        if "TargetGroupNotFound" in str(e):
            logger.info(f"Target group '{tg_name}' not found, skipping.")

def delete_autoscaling_group():
    try:
        autoscaling_client.delete_auto_scaling_group(AutoScalingGroupName=autoscaling_group_name, ForceDelete=True)
        logger.info(f"Auto Scaling Group '{autoscaling_group_name}' deletion initiated.")
    except ClientError as e:
        if "ValidationError" in str(e) and "not found" in str(e):
            logger.info(f"Auto Scaling Group '{autoscaling_group_name}' not found, skipping.")

def delete_launch_template():
    try:
        lt_id = ec2_client.describe_launch_templates(Filters=[{'Name': 'launch-template-name', 'Values': [launch_template_name]}])['LaunchTemplates'][0]['LaunchTemplateId']
        ec2_client.delete_launch_template(LaunchTemplateId=lt_id)
        logger.info(f"Launch Template '{launch_template_name}' deleted.")
    except ClientError as e:
        logger.error(f"Failed to delete Launch Template: {e}")

def delete_route53_record():
    try:
        for record in route53_client.list_resource_record_sets(HostedZoneId=hosted_zone_id)['ResourceRecordSets']:
            if record['Name'].rstrip('.') == record_name:
                route53_client.change_resource_record_sets(
                    HostedZoneId=hosted_zone_id,
                    ChangeBatch={'Changes': [{'Action': 'DELETE', 'ResourceRecordSet': record}]}
                )
                logger.info(f"Record '{record_name}' deleted.")
    except ClientError as e:
        logger.error(f"Failed to delete Route 53 record: {e}")

def terminate_instances(vpc_id):
    instances = ec2_client.describe_instances(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Reservations']
    for reservation in instances:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            logger.info(f"Terminating instance {instance_id} in VPC {vpc_id}.")
            ec2_client.terminate_instances(InstanceIds=[instance_id])
            ec2_client.get_waiter('instance_terminated').wait(InstanceIds=[instance_id])

def delete_subnets(vpc_id):
    subnets = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']
    for subnet in subnets:
        subnet_id = subnet['SubnetId']
        logger.info(f"Deleting Subnet: {subnet_id}")
        ec2_client.delete_subnet(SubnetId=subnet_id)

def delete_nat_gateways(vpc_id):
    nat_gateways = ec2_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['NatGateways']
    for nat_gw in nat_gateways:
        nat_gw_id = nat_gw['NatGatewayId']
        logger.info(f"Deleting NAT Gateway: {nat_gw_id}")
        ec2_client.delete_nat_gateway(NatGatewayId=nat_gw_id)
        ec2_client.get_waiter('nat_gateway_deleted').wait(NatGatewayIds=[nat_gw_id])

def disassociate_and_release_elastic_ips():
    addresses = ec2_client.describe_addresses(Filters=[{'Name': 'domain', 'Values': ['vpc']}])['Addresses']
    for address in addresses:
        public_ip = address['PublicIp']
        allocation_id = address['AllocationId']
        # Disassociate if there is an association
        if 'AssociationId' in address:
            association_id = address['AssociationId']
            logger.info(f"Disassociating Elastic IP: {public_ip}")
            ec2_client.disassociate_address(AssociationId=association_id)
            time.sleep(5)  # Brief wait to ensure disassociation completes
        # Release the EIP
        logger.info(f"Releasing Elastic IP: {public_ip}")
        ec2_client.release_address(AllocationId=allocation_id)

def delete_internet_gateways(vpc_id):
    # Ensure all Elastic IPs are disassociated and released before detaching IGW
    disassociate_and_release_elastic_ips()
    igws = ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])['InternetGateways']
    for igw in igws:
        igw_id = igw['InternetGatewayId']
        logger.info(f"Detaching and deleting Internet Gateway: {igw_id}")
        ec2_client.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        ec2_client.delete_internet_gateway(InternetGatewayId=igw_id)
def delete_vpc(vpc_id):
    delete_internet_gateways(vpc_id)
    terminate_instances(vpc_id)
    delete_subnets(vpc_id)
    delete_nat_gateways(vpc_id)
    delete_internet_gateways(vpc_id)
    logger.info(f"Deleting VPC: {vpc_id}")
    ec2_client.delete_vpc(VpcId=vpc_id)

def find_vpc():
    vpcs = ec2_client.describe_vpcs(
        Filters=[
            {'Name': 'cidr', 'Values': [vpc_cidr_block]},
            {'Name': 'tag:Name', 'Values': [vpc_name]}
        ]
    )
    if vpcs['Vpcs']:
        vpc_id = vpcs['Vpcs'][0]['VpcId']
        logger.info(f"VPC found: {vpc_id} with Name '{vpc_name}'")
        return vpc_id
    else:
        logger.info(f"No VPC found with CIDR block {vpc_cidr_block} and Name '{vpc_name}'")
        return None

# Run deletion functions in sequence
delete_rds_instance()
delete_load_balancer()
delete_efs()
delete_target_group()
delete_autoscaling_group()
delete_launch_template()
delete_route53_record()

vpc_id = find_vpc()
if vpc_id:
    delete_vpc(vpc_id)
