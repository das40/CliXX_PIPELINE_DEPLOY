import boto3
import logging
from botocore.exceptions import ClientError
import time

# Set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Assume Role to interact with AWS resources
clixx_sts_client = boto3.client('sts')
clixx_assumed_role_object = clixx_sts_client.assume_role(
    RoleArn='arn:aws:iam::619071313311:role/Engineer',
    RoleSessionName='mysession'
)
clixx_credentials = clixx_assumed_role_object['Credentials']

# Create clients with assumed role credentials
clixx_ec2_client = boto3.client('ec2', region_name='us-east-1',
                                aws_access_key_id=clixx_credentials['AccessKeyId'],
                                aws_secret_access_key=clixx_credentials['SecretAccessKey'],
                                aws_session_token=clixx_credentials['SessionToken'])
clixx_elbv2_client = boto3.client('elbv2', region_name='us-east-1',
                                  aws_access_key_id=clixx_credentials['AccessKeyId'],
                                  aws_secret_access_key=clixx_credentials['SecretAccessKey'],
                                  aws_session_token=clixx_credentials['SessionToken'])
clixx_rds_client = boto3.client('rds', region_name='us-east-1',
                                aws_access_key_id=clixx_credentials['AccessKeyId'],
                                aws_secret_access_key=clixx_credentials['SecretAccessKey'],
                                aws_session_token=clixx_credentials['SessionToken'])
clixx_efs_client = boto3.client('efs', region_name='us-east-1',
                                aws_access_key_id=clixx_credentials['AccessKeyId'],
                                aws_secret_access_key=clixx_credentials['SecretAccessKey'],
                                aws_session_token=clixx_credentials['SessionToken'])
clixx_route53_client = boto3.client('route53',
                                    aws_access_key_id=clixx_credentials['AccessKeyId'],
                                    aws_secret_access_key=clixx_credentials['SecretAccessKey'],
                                    aws_session_token=clixx_credentials['SessionToken'])
clixx_autoscaling_client = boto3.client('autoscaling', region_name='us-east-1',
                                        aws_access_key_id=clixx_credentials['AccessKeyId'],
                                        aws_secret_access_key=clixx_credentials['SecretAccessKey'],
                                        aws_session_token=clixx_credentials['SessionToken'])

# Resource identifiers
clixx_db_instance_identifier = 'wordpressdbclixx'
clixx_DBSubnetGroupName = 'CLIXXSTACKDBSUBNETGROUP'
clixx_target_group_name = 'CLIXX-TG'
clixx_lb_name = 'CLIXX-LoadBalancer'
clixx_auto_scaling_group_name = 'CLiXX-ASG'
clixx_launch_template_name = 'CLiXX-LT'
clixx_hosted_zone_id = 'Z0881876FFUR3OKRNM20'
clixx_record_name = 'dev.clixx-dasola.com'
clixx_security_groups = ['CLIXX-PublicSG', 'CLIXX-PrivateSG']
clixx_vpc_id = ''  # Leave empty; it will be retrieved dynamically if not provided.
clixx_efs_name = 'CLiXX-EFS'

# Retrieve VPC ID if not provided
if not clixx_vpc_id:
    vpcs = clixx_ec2_client.describe_vpcs(Filters=[{'Name': 'tag:Name', 'Values': ['CLIXXSTACKVPC']}])
    if vpcs['Vpcs']:
        clixx_vpc_id = vpcs['Vpcs'][0]['VpcId']
        logger.info(f"Found VPC with ID: {clixx_vpc_id}")
    else:
        logger.warning("VPC with name 'CLIXXSTACKVPC' not found. Skipping VPC and subnet deletion.")

# Delete Auto Scaling Group
try:
    response = clixx_autoscaling_client.describe_auto_scaling_groups(AutoScalingGroupNames=[clixx_auto_scaling_group_name])
    if response['AutoScalingGroups']:
        clixx_autoscaling_client.delete_auto_scaling_group(AutoScalingGroupName=clixx_auto_scaling_group_name, ForceDelete=True)
        logger.info(f"Auto Scaling Group '{clixx_auto_scaling_group_name}' deleted.")
except ClientError as e:
    logger.error(f"Failed to delete Auto Scaling Group: {e}")

# Delete Launch Template
try:
    response = clixx_ec2_client.describe_launch_templates(LaunchTemplateNames=[clixx_launch_template_name])
    if response['LaunchTemplates']:
        clixx_ec2_client.delete_launch_template(LaunchTemplateName=clixx_launch_template_name)
        logger.info(f"Launch Template '{clixx_launch_template_name}' deleted.")
except ClientError as e:
    if 'NotFound' in str(e):
        logger.info(f"Launch Template '{clixx_launch_template_name}' not found, skipping.")
    else:
        logger.error(f"Failed to delete Launch Template: {e}")

# Delete Load Balancer
try:
    response = clixx_elbv2_client.describe_load_balancers(Names=[clixx_lb_name])
    if response['LoadBalancers']:
        clixx_elbv2_client.delete_load_balancer(LoadBalancerArn=response['LoadBalancers'][0]['LoadBalancerArn'])
        logger.info(f"Load Balancer '{clixx_lb_name}' deleted.")
        time.sleep(30)  # Wait for LB to delete
except ClientError as e:
    if 'LoadBalancerNotFound' in str(e):
        logger.info(f"Load Balancer '{clixx_lb_name}' not found, skipping.")
    else:
        logger.error(f"Failed to delete Load Balancer: {e}")

# Delete Target Group
try:
    response = clixx_elbv2_client.describe_target_groups(Names=[clixx_target_group_name])
    if response['TargetGroups']:
        clixx_elbv2_client.delete_target_group(TargetGroupArn=response['TargetGroups'][0]['TargetGroupArn'])
        logger.info(f"Target Group '{clixx_target_group_name}' deleted.")
except ClientError as e:
    if 'TargetGroupNotFound' in str(e):
        logger.info(f"Target Group '{clixx_target_group_name}' not found, skipping.")
    else:
        logger.error(f"Failed to delete Target Group: {e}")

# Delete RDS Instance
try:
    response = clixx_rds_client.describe_db_instances(DBInstanceIdentifier=clixx_db_instance_identifier)
    if response['DBInstances']:
        clixx_rds_client.delete_db_instance(DBInstanceIdentifier=clixx_db_instance_identifier, SkipFinalSnapshot=True)
        logger.info(f"RDS Instance '{clixx_db_instance_identifier}' deletion initiated.")
except ClientError as e:
    if 'DBInstanceNotFound' in str(e):
        logger.info(f"RDS Instance '{clixx_db_instance_identifier}' not found, skipping.")
    else:
        logger.error(f"Failed to delete RDS Instance: {e}")

# Delete DB Subnet Group
try:
    response = clixx_rds_client.describe_db_subnet_groups(DBSubnetGroupName=clixx_DBSubnetGroupName)
    if response['DBSubnetGroups']:
        clixx_rds_client.delete_db_subnet_group(DBSubnetGroupName=clixx_DBSubnetGroupName)
        logger.info(f"DB Subnet Group '{clixx_DBSubnetGroupName}' deleted.")
except ClientError as e:
    if 'DBSubnetGroupNotFound' in str(e):
        logger.info(f"DB Subnet Group '{clixx_DBSubnetGroupName}' not found, skipping.")
    else:
        logger.error(f"Failed to delete DB Subnet Group: {e}")

# Delete EFS Mount Targets and EFS
try:
    response = clixx_efs_client.describe_file_systems(CreationToken=clixx_efs_name)
    if response['FileSystems']:
        file_system_id = response['FileSystems'][0]['FileSystemId']
        mount_targets = clixx_efs_client.describe_mount_targets(FileSystemId=file_system_id)
        for target in mount_targets['MountTargets']:
            clixx_efs_client.delete_mount_target(MountTargetId=target['MountTargetId'])
            logger.info(f"Deleted EFS mount target: {target['MountTargetId']}")
        time.sleep(5)  # Allow time for mount targets to delete
        clixx_efs_client.delete_file_system(FileSystemId=file_system_id)
        logger.info(f"EFS '{file_system_id}' deleted.")
except ClientError as e:
    logger.error(f"Failed to delete EFS or its mount targets: {e}")

# Delete Route 53 Record
try:
    response = clixx_route53_client.list_resource_record_sets(HostedZoneId=clixx_hosted_zone_id)
    for record in response['ResourceRecordSets']:
        if record['Name'].startswith(clixx_record_name):
            clixx_route53_client.change_resource_record_sets(
                HostedZoneId=clixx_hosted_zone_id,
                ChangeBatch={
                    'Changes': [
                        {
                            'Action': 'DELETE',
                            'ResourceRecordSet': record
                        }
                    ]
                }
            )
            logger.info(f"Route 53 record '{clixx_record_name}' deleted.")
except ClientError as e:
    logger.error(f"Failed to delete Route 53 record: {e}")

# Delete Security Groups
for sg_name in clixx_security_groups:
    try:
        response = clixx_ec2_client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': [sg_name]}])
        if response['SecurityGroups']:
            clixx_ec2_client.delete_security_group(GroupId=response['SecurityGroups'][0]['GroupId'])
            logger.info(f"Security Group '{sg_name}' deleted.")
    except ClientError as e:
        logger.error(f"Failed to delete Security Group '{sg_name}': {e}")

# Delete Subnets
if clixx_vpc_id:
    try:
        response = clixx_ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [clixx_vpc_id]}])
        for subnet in response['Subnets']:
            clixx_ec2_client.delete_subnet(SubnetId=subnet['SubnetId'])
            logger.info(f"Subnet '{subnet['SubnetId']}' deleted.")
    except ClientError as e:
        logger.error(f"Failed to delete subnets: {e}")

# Delete VPC
if clixx_vpc_id:
    try:
        clixx_ec2_client.delete_vpc(VpcId=clixx_vpc_id)
        logger.info(f"VPC '{clixx_vpc_id}' deleted.")
    except ClientError as e:
        logger.error(f"Failed to delete VPC: {e}")
