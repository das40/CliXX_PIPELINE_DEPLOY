#!/usr/bin/env python3
import boto3, time, base64

# Assume Role to interact with AWS resources
session_client = boto3.client('sts')
assumed_role_data = session_client.assume_role(
    RoleArn='arn:aws:iam::619071313311:role/Engineer',
    RoleSessionName='clixx_session'
)
session_creds = assumed_role_data['Credentials']

# Create boto3 clients with assumed role credentials
ec2_client = boto3.client('ec2', region_name="us-east-1", 
                          aws_access_key_id=session_creds['AccessKeyId'], 
                          aws_secret_access_key=session_creds['SecretAccessKey'], 
                          aws_session_token=session_creds['SessionToken'])

elbv2_client = boto3.client('elbv2', region_name="us-east-1", 
                            aws_access_key_id=session_creds['AccessKeyId'], 
                            aws_secret_access_key=session_creds['SecretAccessKey'], 
                            aws_session_token=session_creds['SessionToken'])

rds_client = boto3.client('rds', region_name="us-east-1", 
                          aws_access_key_id=session_creds['AccessKeyId'], 
                          aws_secret_access_key=session_creds['SecretAccessKey'], 
                          aws_session_token=session_creds['SessionToken'])

efs_client = boto3.client('efs', region_name="us-east-1", 
                          aws_access_key_id=session_creds['AccessKeyId'], 
                          aws_secret_access_key=session_creds['SecretAccessKey'], 
                          aws_session_token=session_creds['SessionToken'])

route53_client = boto3.client('route53', 
                              aws_access_key_id=session_creds['AccessKeyId'], 
                              aws_secret_access_key=session_creds['SecretAccessKey'], 
                              aws_session_token=session_creds['SessionToken'])

autoscaling_client = boto3.client('autoscaling', region_name="us-east-1", 
                                  aws_access_key_id=session_creds['AccessKeyId'], 
                                  aws_secret_access_key=session_creds['SecretAccessKey'], 
                                  aws_session_token=session_creds['SessionToken'])

# Deletion Variables
clixx_db_identifier = "ClixxAppDB"
lb_name = "ClixxLoadBalancer"
efs_name = "Clixx-EFS"
tg_name = "ClixxTargetGroup"
hosted_zone_id = "Z032607324NJ585T59J7F"
record_name = "dev.clixx-dasola.com"
autoscaling_group_name = "ClixxAutoScalingGroup"
launch_template_name = "ClixxLaunchTemplate"
public_sg_name = "ClixxPublicSG"
private_sg_name = "ClixxPrivateSG"
db_subnet_group_name = "ClixxDBSubnetGroup"
clixx_vpc_cidr_block = "10.10.0.0/16"
vpc_name = "CLixxVPC"

# Delete RDS Instance
db_instances = rds_client.describe_db_instances()
if any(instance['DBInstanceIdentifier'] == clixx_db_identifier for instance in db_instances['DBInstances']):
    rds_client.delete_db_instance(DBInstanceIdentifier=clixx_db_identifier, SkipFinalSnapshot=True)
    print(f"RDS instance '{clixx_db_identifier}' deletion initiated.")
    while any(instance['DBInstanceIdentifier'] == clixx_db_identifier for instance in rds_client.describe_db_instances()['DBInstances']):
        print(f"Waiting for RDS instance '{clixx_db_identifier}' to be deleted...")
        time.sleep(10)
    print(f"RDS instance '{clixx_db_identifier}' deleted successfully.")

# Delete Load Balancer
load_balancers = elbv2_client.describe_load_balancers()['LoadBalancers']
for lb in load_balancers:
    if lb['LoadBalancerName'] == lb_name:
        elbv2_client.delete_load_balancer(LoadBalancerArn=lb['LoadBalancerArn'])
        print(f"Load Balancer '{lb_name}' deletion initiated.")

# Delete EFS and Mount Targets
efs_info = efs_client.describe_file_systems()
file_system_id = None
for fs in efs_info['FileSystems']:
    tags = efs_client.list_tags_for_resource(ResourceId=fs['FileSystemId'])['Tags']
    if any(tag['Key'] == 'Name' and tag['Value'] == efs_name for tag in tags):
        file_system_id = fs['FileSystemId']
        break

if file_system_id:
    mount_targets = efs_client.describe_mount_targets(FileSystemId=file_system_id)['MountTargets']
    for mount_target in mount_targets:
        efs_client.delete_mount_target(MountTargetId=mount_target['MountTargetId'])
        print(f"Deleted mount target: {mount_target['MountTargetId']} for EFS '{efs_name}'")
    efs_client.delete_file_system(FileSystemId=file_system_id)
    print(f"EFS '{efs_name}' deleted successfully.")

# Delete Target Group
target_groups = elbv2_client.describe_target_groups()['TargetGroups']
for tg in target_groups:
    if tg['TargetGroupName'] == tg_name:
        elbv2_client.delete_target_group(TargetGroupArn=tg['TargetGroupArn'])
        print(f"Target Group '{tg_name}' deleted successfully.")

# Delete Route 53 Record
record_sets = route53_client.list_resource_record_sets(HostedZoneId=hosted_zone_id)['ResourceRecordSets']
for record in record_sets:
    if record['Name'] == record_name:
        route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={'Changes': [{'Action': 'DELETE', 'ResourceRecordSet': record}]}
        )
        print(f"Route 53 record '{record_name}' deleted successfully.")

# Delete Auto Scaling Group
autoscaling_client.delete_auto_scaling_group(AutoScalingGroupName=autoscaling_group_name, ForceDelete=True)
print(f"Auto Scaling Group '{autoscaling_group_name}' deletion initiated.")

# Delete Launch Template
launch_templates = ec2_client.describe_launch_templates(Filters=[{'Name': 'launch-template-name', 'Values': [launch_template_name]}])
if launch_templates['LaunchTemplates']:
    ec2_client.delete_launch_template(LaunchTemplateId=launch_templates['LaunchTemplates'][0]['LaunchTemplateId'])
    print(f"Launch Template '{launch_template_name}' deleted successfully.")

# Delete Security Groups
for sg_name, sg_id in [(public_sg_name, 'public'), (private_sg_name, 'private')]:
    security_groups = list(ec2_client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': [sg_name]}])['SecurityGroups'])
    if security_groups:
        ec2_client.delete_security_group(GroupId=security_groups[0]['GroupId'])
        print(f"Security Group '{sg_name}' deleted successfully.")

# Delete DB Subnet Group
db_subnet_groups = rds_client.describe_db_subnet_groups()
if any(subnet['DBSubnetGroupName'] == db_subnet_group_name for subnet in db_subnet_groups['DBSubnetGroups']):
    rds_client.delete_db_subnet_group(DBSubnetGroupName=db_subnet_group_name)
    print(f"DB Subnet Group '{db_subnet_group_name}' deleted successfully.")

# Delete VPC and Dependencies
vpcs = ec2_client.describe_vpcs(Filters=[{'Name': 'cidr', 'Values': [clixx_vpc_cidr_block]}, {'Name': 'tag:Name', 'Values': [vpc_name]}])
if vpcs['Vpcs']:
    vpc_id = vpcs['Vpcs'][0]['VpcId']
    print(f"VPC '{vpc_name}' with ID '{vpc_id}' deletion initiated.")
    
    # Delete dependencies in order
    for igw in ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])['InternetGateways']:
        ec2_client.detach_internet_gateway(InternetGatewayId=igw['InternetGatewayId'], VpcId=vpc_id)
        ec2_client.delete_internet_gateway(InternetGatewayId=igw['InternetGatewayId'])
        print(f"Internet Gateway '{igw['InternetGatewayId']}' detached and deleted.")
    
    for subnet in ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']:
        ec2_client.delete_subnet(SubnetId=subnet['SubnetId'])
        print(f"Subnet '{subnet['SubnetId']}' deleted.")
    
    for route_table in ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['RouteTables']:
        if not any(assoc['Main'] for assoc in route_table['Associations']):
            ec2_client.delete_route_table(RouteTableId=route_table['RouteTableId'])
            print(f"Route Table '{route_table['RouteTableId']}' deleted.")
    
    for sg in ec2_client.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['SecurityGroups']:
        if sg['GroupName'] != 'default':
            ec2_client.delete_security_group(GroupId=sg['GroupId'])
            print(f"Security Group '{sg['GroupName']}' deleted.")
    
    ec2_client.delete_vpc(VpcId=vpc_id)
    print(f"VPC '{vpc_name}' deleted successfully.")
else:
    print(f"No VPC found with CIDR '{clixx_vpc_cidr_block}' and Name '{vpc_name}'.")
