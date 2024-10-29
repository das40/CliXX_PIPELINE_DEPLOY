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
lb_name = 'CLiXX-LB'
efs_name = 'CLiXX-EFS'
tg_name = 'CLiXX-TG'
hosted_zone_id = 'Z0881876FFUR3OKRNM20'
record_name = 'dev.clixx-dasola.com'
autoscaling_group_name = 'CLiXX-ASG'
launch_template_name = 'CLiXX-LT'
vpc_cidr_block = '10.0.0.0/16'
vpc_name = 'CLIXXSTACKVPC'

# 1. Delete RDS instance and wait
try:
    rds_client.delete_db_instance(DBInstanceIdentifier=db_instance_name, SkipFinalSnapshot=True)
    print(f"RDS instance '{db_instance_name}' deletion initiated.")
    while True:
        try:
            rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_name)
            print("Waiting for RDS instance to delete...")
            time.sleep(15)
        except rds_client.exceptions.DBInstanceNotFoundFault:
            print(f"RDS instance '{db_instance_name}' deleted.")
            break
except rds_client.exceptions.DBInstanceNotFoundFault:
    print(f"RDS instance '{db_instance_name}' not found.")

# 2. Delete Application Load Balancer
load_balancers = elbv2_client.describe_load_balancers()
for lb in load_balancers['LoadBalancers']:
    if lb['LoadBalancerName'] == lb_name:
        elbv2_client.delete_load_balancer(LoadBalancerArn=lb['LoadBalancerArn'])
        print(f"Application Load Balancer '{lb_name}' deleted.")

# 3. Delete EFS and mount targets
efs_name = 'CLiXX-EFS'
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
    for mount in mount_targets_info['MountTargets']:
        efs_client.delete_mount_target(MountTargetId=mount['MountTargetId'])
        print(f"Deleted mount target: {mount['MountTargetId']}")
        time.sleep(5)
    efs_client.delete_file_system(FileSystemId=file_system_id)
    print(f"Deleted EFS with File System ID: {file_system_id}")

# 4. Delete Target Group
response = elbv2_client.describe_target_groups(Names=[tg_name])
if response['TargetGroups']:
    elbv2_client.delete_target_group(TargetGroupArn=response['TargetGroups'][0]['TargetGroupArn'])
    print(f"Target Group '{tg_name}' deleted.")

# 5. Delete Route 53 record
response = route53_client.list_resource_record_sets(HostedZoneId=hosted_zone_id)
for record in response['ResourceRecordSets']:
    if record['Name'].rstrip('.') == record_name:
        route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={'Changes': [{'Action': 'DELETE', 'ResourceRecordSet': record}]}
        )
        print(f"Route 53 record '{record_name}' deleted.")

# 6. Delete Auto Scaling Group
autoscaling_client.delete_auto_scaling_group(AutoScalingGroupName=autoscaling_group_name, ForceDelete=True)
print(f"Auto Scaling Group '{autoscaling_group_name}' deletion initiated.")

# 7. Delete Launch Template
lt_response = ec2_client.describe_launch_templates(Filters=[{'Name': 'launch-template-name', 'Values': [launch_template_name]}])
for lt in lt_response['LaunchTemplates']:
    ec2_client.delete_launch_template(LaunchTemplateId=lt['LaunchTemplateId'])
    print(f"Launch Template '{launch_template_name}' deleted.")

# 8. Delete VPC and dependencies
vpcs = ec2_client.describe_vpcs(
    Filters=[
        {'Name': 'cidr', 'Values': [vpc_cidr_block]},
        {'Name': 'tag:Name', 'Values': [vpc_name]}
    ]
)

if vpcs['Vpcs']:
    vpc_id = vpcs['Vpcs'][0]['VpcId']
    print(f"VPC found: {vpc_id} with Name '{vpc_name}'. Deleting dependencies...")

    # Release Elastic IPs associated with the VPC
    addresses = ec2_client.describe_addresses()
    for address in addresses['Addresses']:
        if 'AssociationId' in address:
            ec2_client.disassociate_address(AssociationId=address['AssociationId'])
        if 'AllocationId' in address:
            ec2_client.release_address(AllocationId=address['AllocationId'])
            print(f"Released Elastic IP: {address['PublicIp']}")

    # Detach and delete internet gateways
    igws = ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
    for igw in igws['InternetGateways']:
        igw_id = igw['InternetGatewayId']
        for attempt in range(5):
            try:
                ec2_client.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
                ec2_client.delete_internet_gateway(InternetGatewayId=igw_id)
                print(f"Internet Gateway {igw_id} detached and deleted.")
                break
            except ec2_client.exceptions.ClientError as e:
                if 'DependencyViolation' in str(e):
                    print(f"Retrying detachment of Internet Gateway {igw_id} due to DependencyViolation...")
                    time.sleep(10)

    # Delete NAT gateways
    nat_gateways = ec2_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    for nat_gw in nat_gateways['NatGateways']:
        nat_gw_id = nat_gw['NatGatewayId']
        ec2_client.delete_nat_gateway(NatGatewayId=nat_gw_id)
        print(f"Deleting NAT Gateway: {nat_gw_id}")
        time.sleep(5)

    # Delete subnets
    subnets = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    for subnet in subnets['Subnets']:
        subnet_id = subnet['SubnetId']
        print(f"Deleting Subnet: {subnet_id}")

        # Detach and delete network interfaces within the subnet
        network_interfaces = ec2_client.describe_network_interfaces(Filters=[{'Name': 'subnet-id', 'Values': [subnet_id]}])
        for interface in network_interfaces['NetworkInterfaces']:
            eni_id = interface['NetworkInterfaceId']
            print(f"Deleting Network Interface: {eni_id}")
            if 'Attachment' in interface:
                attachment_id = interface['Attachment']['AttachmentId']
                try:
                    ec2_client.detach_network_interface(AttachmentId=attachment_id, Force=True)
                    print(f"Detached Network Interface: {eni_id}")
                    time.sleep(5)
                except ec2_client.exceptions.ClientError as e:
                    print(f"Error detaching Network Interface {eni_id}: {str(e)}")

            for attempt in range(5):
                try:
                    ec2_client.delete_network_interface(NetworkInterfaceId=eni_id)
                    print(f"Deleted Network Interface: {eni_id}")
                    break
                except ec2_client.exceptions.ClientError as e:
                    if 'DependencyViolation' in str(e):
                        print(f"Retrying deletion of Network Interface {eni_id} due to DependencyViolation...")
                        time.sleep(10)

        # Delete Subnet
        ec2_client.delete_subnet(SubnetId=subnet_id)
        print(f"Subnet {subnet_id} deleted.")

    # Delete Route Tables
    route_tables = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    for rt in route_tables['RouteTables']:
        rt_id = rt['RouteTableId']
        if not any(assoc['Main'] for assoc in rt.get('Associations', [])):
            ec2_client.delete_route_table(RouteTableId=rt_id)
            print(f"Route Table {rt_id} deleted.")

    # Delete Security Groups (excluding default)
    security_groups = ec2_client.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    for sg in security_groups['SecurityGroups']:
        if sg['GroupName'] != 'default':
            sg_id = sg['GroupId']
            ec2_client.delete_security_group(GroupId=sg_id)
            print(f"Security Group {sg_id} deleted.")

    # Delete VPC
    ec2_client.delete_vpc(VpcId=vpc_id)
    print(f"VPC '{vpc_name}' and all dependencies deleted.")
else:
    print(f"No VPC found with CIDR block {vpc_cidr_block} and Name '{vpc_name}'")
