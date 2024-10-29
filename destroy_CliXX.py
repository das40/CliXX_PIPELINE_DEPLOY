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

# Deletion sequence

# # 1. Delete RDS instance
# try:
#     rds_client.delete_db_instance(DBInstanceIdentifier=db_instance_name, SkipFinalSnapshot=True)
#     print(f"RDS instance '{db_instance_name}' deletion initiated.")
# except rds_client.exceptions.DBInstanceNotFoundFault:
#     print(f"RDS instance '{db_instance_name}' not found.")

# # 2. Delete Application Load Balancer
# load_balancers = elbv2_client.describe_load_balancers()
# for lb in load_balancers['LoadBalancers']:
#     if lb['LoadBalancerName'] == lb_name:
#         elbv2_client.delete_load_balancer(LoadBalancerArn=lb['LoadBalancerArn'])
#         print(f"Application Load Balancer '{lb_name}' deleted.")

# # 3. Delete EFS and mount targets
# efs_name = 'CLiXX-EFS'
# fs_info = efs_client.describe_file_systems()
# file_system_id = None
# for fs in fs_info['FileSystems']:
#     tags = efs_client.list_tags_for_resource(ResourceId=fs['FileSystemId'])['Tags']
#     if any(tag['Key'] == 'Name' and tag['Value'] == efs_name for tag in tags):
#         file_system_id = fs['FileSystemId']
#         print(f"Found EFS with File System ID: {file_system_id}")
#         break

# if file_system_id is None:
#     print(f"No EFS found with the name '{efs_name}'.")
# else:
#     mount_targets_info = efs_client.describe_mount_targets(FileSystemId=file_system_id)
#     mount_target_ids = [mount['MountTargetId'] for mount in mount_targets_info['MountTargets']]
#     for mount_target_id in mount_target_ids:
#         efs_client.delete_mount_target(MountTargetId=mount_target_id)
#         print(f"Deleted mount target: {mount_target_id}")

#         while True:
#             time.sleep(5)
#             mount_target_info = efs_client.describe_mount_targets(FileSystemId=file_system_id)
#             if not any(mount['MountTargetId'] == mount_target_id for mount in mount_target_info['MountTargets']):
#                 print(f"Mount target {mount_target_id} is deleted.")
#                 break

#     efs_client.delete_file_system(FileSystemId=file_system_id)
#     print(f"Deleted EFS with File System ID: {file_system_id}")

# # 4. Delete Target Group
# response = elbv2_client.describe_target_groups(Names=[tg_name])
# if response['TargetGroups']:
#     elbv2_client.delete_target_group(TargetGroupArn=response['TargetGroups'][0]['TargetGroupArn'])
#     print(f"Target Group '{tg_name}' deleted.")

# # 5. Delete Route 53 record
# response = route53_client.list_resource_record_sets(HostedZoneId=hosted_zone_id)
# for record in response['ResourceRecordSets']:
#     if record['Name'].rstrip('.') == record_name:
#         route53_client.change_resource_record_sets(
#             HostedZoneId=hosted_zone_id,
#             ChangeBatch={'Changes': [{'Action': 'DELETE', 'ResourceRecordSet': record}]}
#         )
#         print(f"Route 53 record '{record_name}' deleted.")

# # 6. Delete Auto Scaling Group
# autoscaling_client.delete_auto_scaling_group(AutoScalingGroupName=autoscaling_group_name, ForceDelete=True)
# print(f"Auto Scaling Group '{autoscaling_group_name}' deletion initiated.")

# # 7. Delete Launch Template
# lt_response = ec2_client.describe_launch_templates(Filters=[{'Name': 'launch-template-name', 'Values': [launch_template_name]}])
# for lt in lt_response['LaunchTemplates']:
#     ec2_client.delete_launch_template(LaunchTemplateId=lt['LaunchTemplateId'])
#     print(f"Launch Template '{launch_template_name}' deleted.")

# 8. Delete VPC and dependencies
# vpcs = ec2_client.describe_vpcs(
#     Filters=[
#         {'Name': 'cidr', 'Values': [vpc_cidr_block]},
#         {'Name': 'tag:Name', 'Values': [vpc_name]}
#     ]
# )

# if vpcs['Vpcs']:
#     vpc_id = vpcs['Vpcs'][0]['VpcId']
#     print(f"VPC found: {vpc_id} with Name '{vpc_name}'. Deleting dependencies...")

#     # Release Elastic IPs associated with the VPC
#     addresses = ec2_client.describe_addresses()
#     for address in addresses['Addresses']:
#         if 'AssociationId' in address:
#             ec2_client.disassociate_address(AssociationId=address['AssociationId'])
#         if 'AllocationId' in address:
#             ec2_client.release_address(AllocationId=address['AllocationId'])
#             print(f"Released Elastic IP: {address['PublicIp']}")

#     # Detach and delete internet gateways with retries
#     igws = ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
#     for igw in igws['InternetGateways']:
#         igw_id = igw['InternetGatewayId']
#         for attempt in range(5):
#             try:
#                 ec2_client.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
#                 ec2_client.delete_internet_gateway(InternetGatewayId=igw_id)
#                 print(f"Internet Gateway {igw_id} detached and deleted.")
#                 break
#             except ec2_client.exceptions.ClientError as e:
#                 if 'DependencyViolation' in str(e):
#                     print(f"Retrying detachment of Internet Gateway {igw_id} due to DependencyViolation...")
#                     time.sleep(10)
#                 else:
#                     raise

#     # Delete NAT gateways
#     nat_gateways = ec2_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
#     for nat_gw in nat_gateways['NatGateways']:
#         nat_gw_id = nat_gw['NatGatewayId']
#         ec2_client.delete_nat_gateway(NatGatewayId=nat_gw_id)
#         print(f"Deleting NAT Gateway: {nat_gw_id}")
#         time.sleep(5)  # Wait briefly for NAT gateway deletion

#     ## Delete subnets
# subnets = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
# for subnet in subnets['Subnets']:
#     subnet_id = subnet['SubnetId']
#     print(f"Deleting Subnet: {subnet_id}")

#     # Detach and delete network interfaces within the subnet
#     network_interfaces = ec2_client.describe_network_interfaces(Filters=[{'Name': 'subnet-id', 'Values': [subnet_id]}])
#     for interface in network_interfaces['NetworkInterfaces']:
#         eni_id = interface['NetworkInterfaceId']
#         print(f"Deleting Network Interface: {eni_id}")

#         # Check if the network interface is attached to an instance
#         if 'Attachment' in interface:
#             attachment_id = interface['Attachment']['AttachmentId']
#             try:
#                 print(f"Detaching Network Interface: {eni_id} from Attachment: {attachment_id}")
#                 ec2_client.detach_network_interface(AttachmentId=attachment_id, Force=True)
#                 time.sleep(5)  # Wait briefly for the detachment to complete
#             except ec2_client.exceptions.ClientError as e:
#                 if 'UnsupportedOperation' in str(e):
#                     print(f"Cannot detach interface {eni_id}. Skipping deletion.")
#                     continue
#                 else:
#                     raise

#         # Attempt to delete the network interface with retries
#         for attempt in range(5):  # Retry up to 5 times
#             try:
#                 ec2_client.delete_network_interface(NetworkInterfaceId=eni_id)
#                 print(f"Network Interface {eni_id} deleted.")
#                 break
#             except ec2_client.exceptions.ClientError as e:
#                 if 'DependencyViolation' in str(e):
#                     print(f"Retrying deletion of Network Interface {eni_id} due to DependencyViolation...")
#                     time.sleep(10)  # Wait before retrying
#                 else:
#                     raise  # Raise other exceptions if they occur

#     # Retry mechanism for subnet deletion
#     for attempt in range(5):  # Retry up to 5 times
#         try:
#             ec2_client.delete_subnet(SubnetId=subnet_id)
#             print(f"Subnet {subnet_id} deleted.")
#             break
#         except ec2_client.exceptions.ClientError as e:
#             if 'DependencyViolation' in str(e):
#                 print(f"Retrying deletion of Subnet {subnet_id} due to DependencyViolation...")
#                 time.sleep(10)  # Wait before retrying
#             else:
#                 raise  # Raise other exceptions if they occur


#     # Delete security groups
#     security_groups = ec2_client.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
#     for sg in security_groups['SecurityGroups']:
#         if sg['GroupName'] != 'default':
#             sg_id = sg['GroupId']
#             for attempt in range(5):
#                 try:
#                     ec2_client.delete_security_group(GroupId=sg_id)
#                     print(f"Security Group {sg_id} deleted.")
#                     break
#                 except ec2_client.exceptions.ClientError as e:
#                     if 'DependencyViolation' in str(e):
#                         print(f"Retrying deletion of Security Group {sg_id} due to DependencyViolation...")
#                         time.sleep(10)
#                     else:
#                         raise

    # Delete route tables
route_tables = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])

for rt in route_tables['RouteTables']:
    rt_id = rt['RouteTableId']
    print(f"Attempting to delete Route Table: {rt_id}")

    # Disassociate route table associations
    if 'Associations' in rt:
        for association in rt['Associations']:
            # Only disassociate non-main route tables
            if not association.get('Main', False):
                association_id = association['RouteTableAssociationId']
                try:
                    print(f"Disassociating Route Table Association: {association_id}")
                    ec2_client.disassociate_route_table(AssociationId=association_id)
                    time.sleep(2)  # Wait a moment for disassociation
                except ec2_client.exceptions.ClientError as e:
                    if 'DependencyViolation' in str(e):
                        print(f"DependencyViolation encountered while disassociating {association_id}. Retrying.")
                        time.sleep(5)
                    else:
                        print(f"Could not disassociate {association_id}: {str(e)}")
                        continue

    # Retry mechanism for deleting the route table
    for attempt in range(5):  # Retry up to 5 times
        try:
            ec2_client.delete_route_table(RouteTableId=rt_id)
            print(f"Route Table {rt_id} deleted.")
            break
        except ec2_client.exceptions.ClientError as e:
            if 'DependencyViolation' in str(e):
                print(f"Retrying deletion of Route Table {rt_id} due to DependencyViolation...")
                time.sleep(10)  # Wait before retrying
            else:
                print(f"Failed to delete Route Table {rt_id} due to: {str(e)}")
                break


    # Finally, delete the VPC
    ec2_client.delete_vpc(VpcId=vpc_id)
    print(f"VPC '{vpc_name}' and all dependencies deleted.")
