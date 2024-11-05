#!/usr/bin/env python3
import boto3
import time

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
tg_name = 'CLIXX-TG'
autoscaling_group_name = 'CLiXX-ASG'
launch_template_name = 'CLiXX-LT'
public_sg_name = 'CLIXX-PublicSG'
private_sg_name = 'CLIXX-PrivateSG'
DBSubnetGroupName = 'CLIXXSTACKDBSUBNETGROUP'
vpc_name = 'CLIXXSTACKVPC'
vpc_cidr_block = '10.0.0.0/16'
hosted_zone_id = 'Z0881876FFUR3OKRNM20'
record_name = 'dev.clixx-dasola.com'
bastion_tag_key = 'Name'
bastion_tag_value = 'CLIXX-BastionHost'


##################### Delete the Bastion Server instance
def delete_bastion_server():
    bastion_instances = ec2_client.describe_instances(
        Filters=[
            {'Name': f'tag:{bastion_tag_key}', 'Values': [bastion_tag_value]},
            {'Name': 'instance-state-name', 'Values': ['running', 'stopped']}
        ]
    )

    for reservation in bastion_instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            ec2_client.terminate_instances(InstanceIds=[instance_id])
            print(f"Bastion server instance '{instance_id}' termination initiated.")
            # Wait until instance is terminated
            waiter = ec2_client.get_waiter('instance_terminated')
            waiter.wait(InstanceIds=[instance_id])
            print(f"Bastion server instance '{instance_id}' terminated.")


##################### Delete the DB instance
def delete_rds_instance():
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
    # Wait for RDS instance deletion
    while db_instance_exists:
        rds_instances = rds_client.describe_db_instances()
        db_instance_exists = any(instance['DBInstanceIdentifier'] == db_instance_name for instance in rds_instances['DBInstances'])
        if not db_instance_exists:
            print(f"RDS instance '{db_instance_name}' deleted successfully.")
        else:
            print(f"Waiting for RDS instance '{db_instance_name}' to be deleted...")
            time.sleep(10)

################### Delete Application Load Balancer
def delete_load_balancer():
    load_balancers = elbv2_client.describe_load_balancers()
    for lb in load_balancers['LoadBalancers']:
        if lb['LoadBalancerName'] == lb_name:
            lb_arn = lb['LoadBalancerArn']
            elbv2_client.delete_load_balancer(LoadBalancerArn=lb_arn)
            print(f"Application Load Balancer '{lb_name}' deleted.")
            break

##################### Delete mount targets before deleting EFS
def delete_efs():
    fs_info = efs_client.describe_file_systems()
    file_system_id = None
    for fs in fs_info['FileSystems']:
        tags = efs_client.list_tags_for_resource(ResourceId=fs['FileSystemId'])['Tags']
        if any(tag['Key'] == 'Name' and tag['Value'] == efs_name for tag in tags):
            file_system_id = fs['FileSystemId']
            print(f"Found EFS with File System ID: {file_system_id}")
            break

    if file_system_id:
        mount_targets_info = efs_client.describe_mount_targets(FileSystemId=file_system_id)
        for mount_target in mount_targets_info['MountTargets']:
            mount_target_id = mount_target['MountTargetId']
            efs_client.delete_mount_target(MountTargetId=mount_target_id)
            print(f"Deleted mount target: {mount_target_id}")
            while efs_client.describe_mount_targets(FileSystemId=file_system_id)['MountTargets']:
                print(f"Waiting for mount target {mount_target_id} to delete...")
                time.sleep(5)
        efs_client.delete_file_system(FileSystemId=file_system_id)
        print(f"Deleted EFS with File System ID: {file_system_id}")
    else:
        print(f"No EFS found with the name '{efs_name}'.")

#################### Delete Target Group
def delete_target_group():
    response = elbv2_client.describe_target_groups(Names=[tg_name])
    if response['TargetGroups']:
        tg_arn = response['TargetGroups'][0]['TargetGroupArn']
        elbv2_client.delete_target_group(TargetGroupArn=tg_arn)
        print(f"Target Group '{tg_name}' deleted.")

################## Delete Route 53 record
def delete_route53_record():
    response = route53_client.list_resource_record_sets(HostedZoneId=hosted_zone_id)
    for record in response['ResourceRecordSets']:
        if record['Name'].rstrip('.') == record_name:
            route53_client.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch={
                    'Changes': [{'Action': 'DELETE', 'ResourceRecordSet': record}]
                }
            )
            print(f"Record '{record_name}' deleted.")
            break

#################### Delete Auto Scaling Group 
def delete_autoscaling_group():
    response = autoscaling_client.delete_auto_scaling_group(
        AutoScalingGroupName=autoscaling_group_name,
        ForceDelete=True
    )
    print("Auto Scaling Group deleted:", response)
    while True:
        asg_status = autoscaling_client.describe_auto_scaling_groups(AutoScalingGroupNames=[autoscaling_group_name])
        if not asg_status['AutoScalingGroups']:
            print(f"Auto Scaling Group '{autoscaling_group_name}' deleted successfully.")
            break
        time.sleep(30)

#################### Delete Launch Template
def delete_launch_template():
    response = ec2_client.describe_launch_templates(Filters=[{'Name': 'launch-template-name', 'Values': [launch_template_name]}])
    if response['LaunchTemplates']:
        launch_template_id = response['LaunchTemplates'][0]['LaunchTemplateId']
        ec2_client.delete_launch_template(LaunchTemplateId=launch_template_id)
        print("Launch Template deleted:", launch_template_id)

#################### Delete Security Groups
def delete_security_groups():
    for sg_name in [public_sg_name, private_sg_name]:
        security_groups = ec2_client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': [sg_name]}])
        if security_groups['SecurityGroups']:
            sg_id = security_groups['SecurityGroups'][0]['GroupId']
            ec2_client.delete_security_group(GroupId=sg_id)
            print(f"Security Group '{sg_name}' deleted.")

#################### Delete DB Subnet Group
def delete_db_subnet_group():
    response = rds_client.describe_db_subnet_groups()
    db_subnet_group_exists = any(subnet['DBSubnetGroupName'] == DBSubnetGroupName for subnet in response['DBSubnetGroups'])
    if db_subnet_group_exists:
        rds_client.delete_db_subnet_group(DBSubnetGroupName=DBSubnetGroupName)
        print(f"DB Subnet Group '{DBSubnetGroupName}' deleted.")

#################### Delete the VPC and Dependencies
def delete_vpc():
    vpcs = ec2_client.describe_vpcs(Filters=[{'Name': 'cidr', 'Values': [vpc_cidr_block]}, {'Name': 'tag:Name', 'Values': [vpc_name]}])
    if vpcs['Vpcs']:
        vpc_id = vpcs['Vpcs'][0]['VpcId']
        print(f"VPC found: {vpc_id} with Name '{vpc_name}'. Deleting dependencies...")

        # 1. Detach and delete internet gateways
        igws = ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
        for igw in igws['InternetGateways']:
            igw_id = igw['InternetGatewayId']
            ec2_client.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
            ec2_client.delete_internet_gateway(InternetGatewayId=igw_id)
            print(f"Internet Gateway '{igw_id}' detached and deleted.")

        # 2. Delete NAT gateways
        nat_gateways = ec2_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for nat_gw in nat_gateways['NatGateways']:
            ec2_client.delete_nat_gateway(NatGatewayId=nat_gw['NatGatewayId'])
            print(f"NAT Gateway '{nat_gw['NatGatewayId']}' deleted.")

        # 3. Delete subnets
        subnets = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for subnet in subnets['Subnets']:
            ec2_client.delete_subnet(SubnetId=subnet['SubnetId'])
            print(f"Subnet '{subnet['SubnetId']}' deleted.")

        # 4. Delete route tables (except the main route table)
        route_tables = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for rt in route_tables['RouteTables']:
            if not any(assoc.get('Main', False) for assoc in rt.get('Associations', [])):
                ec2_client.delete_route_table(RouteTableId=rt['RouteTableId'])
                print(f"Route Table '{rt['RouteTableId']}' deleted.")

        # 5. Delete security groups
        delete_security_groups()

        # 6. Delete VPC
        ec2_client.delete_vpc(VpcId=vpc_id)
        print(f"VPC '{vpc_id}' with Name '{vpc_name}' deleted.")
    else:
        print(f"No VPC found with CIDR block {vpc_cidr_block} and Name '{vpc_name}'")

# Execute deletions
delete_bastion_server() 
delete_rds_instance()
delete_load_balancer()
delete_efs()
delete_target_group()
delete_route53_record()
delete_autoscaling_group()
delete_launch_template()
delete_db_subnet_group()
delete_vpc()
