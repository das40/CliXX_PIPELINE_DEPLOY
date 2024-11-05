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
WAIT_TIMEOUT = 600

def wait_for_deletion(check_func, check_args={}, interval=10, timeout=WAIT_TIMEOUT):
    """Wait for a resource deletion to complete with a timeout."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if not check_func(**check_args):
            print("Resource deleted successfully.")
            return True
        print("Waiting for resource to delete...")
        time.sleep(interval)
    print("Timed out waiting for resource to delete.")
    return False

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
            waiter = ec2_client.get_waiter('instance_terminated')
            waiter.wait(InstanceIds=[instance_id])
            print(f"Bastion server instance '{instance_id}' terminated.")

def delete_rds_instance():
    try:
        rds_client.delete_db_instance(DBInstanceIdentifier=db_instance_name, SkipFinalSnapshot=True)
        print(f"RDS instance '{db_instance_name}' deletion initiated.")
        wait_for_deletion(
            check_func=lambda **args: any(db['DBInstanceIdentifier'] == db_instance_name for db in rds_client.describe_db_instances()['DBInstances'])
        )
    except rds_client.exceptions.DBInstanceNotFoundFault:
        print(f"RDS instance '{db_instance_name}' not found, skipping.")
    except Exception as e:
        print(f"Error deleting RDS instance: {e}")

def delete_load_balancer():
    try:
        load_balancers = elbv2_client.describe_load_balancers()
        for lb in load_balancers['LoadBalancers']:
            if lb['LoadBalancerName'] == lb_name:
                lb_arn = lb['LoadBalancerArn']
                elbv2_client.delete_load_balancer(LoadBalancerArn=lb_arn)
                print(f"Application Load Balancer '{lb_name}' deleted.")
                return
        print(f"Load Balancer '{lb_name}' not found, skipping.")
    except Exception as e:
        print(f"Error deleting Load Balancer '{lb_name}': {e}")

def delete_efs_and_mount_targets():
    try:
        fs_info = efs_client.describe_file_systems()
        file_system_id = next((fs['FileSystemId'] for fs in fs_info['FileSystems'] if any(tag['Key'] == 'Name' and tag['Value'] == efs_name for tag in efs_client.list_tags_for_resource(ResourceId=fs['FileSystemId'])['Tags'])), None)
        
        if file_system_id:
            print(f"Found EFS '{efs_name}' with ID: {file_system_id}")
            mount_targets = efs_client.describe_mount_targets(FileSystemId=file_system_id)['MountTargets']
            for mt in mount_targets:
                mount_target_id = mt['MountTargetId']
                efs_client.delete_mount_target(MountTargetId=mount_target_id)
                print(f"Deleted mount target: {mount_target_id}")
                wait_for_deletion(
                    check_func=lambda mt_id: any(mount['MountTargetId'] == mt_id for mount in efs_client.describe_mount_targets(FileSystemId=file_system_id)['MountTargets']),
                    check_args={'mt_id': mount_target_id}
                )
            efs_client.delete_file_system(FileSystemId=file_system_id)
            print(f"EFS '{efs_name}' deleted.")
        else:
            print(f"No EFS found with the name '{efs_name}', skipping.")
    except Exception as e:
        print(f"Error deleting EFS or mount targets: {e}")

def delete_target_group():
    try:
        response = elbv2_client.describe_target_groups(Names=[tg_name])
        if response['TargetGroups']:
            tg_arn = response['TargetGroups'][0]['TargetGroupArn']
            elbv2_client.delete_target_group(TargetGroupArn=tg_arn)
            print(f"Target Group '{tg_name}' deleted.")
        else:
            print(f"Target Group '{tg_name}' not found, skipping.")
    except elbv2_client.exceptions.TargetGroupNotFoundException:
        print(f"Target Group '{tg_name}' not found, skipping.")
    except Exception as e:
        print(f"Error deleting Target Group: {e}")

def delete_route53_record():
    try:
        response = route53_client.list_resource_record_sets(HostedZoneId=hosted_zone_id)
        for record in response['ResourceRecordSets']:
            if record['Name'].rstrip('.') == record_name:
                route53_client.change_resource_record_sets(
                    HostedZoneId=hosted_zone_id,
                    ChangeBatch={'Changes': [{'Action': 'DELETE', 'ResourceRecordSet': record}]}
                )
                print(f"Record '{record_name}' deleted.")
                return
        print(f"Record '{record_name}' not found, skipping.")
    except Exception as e:
        print(f"Error deleting Route 53 record: {e}")

def delete_autoscaling_group():
    try:
        autoscaling_client.delete_auto_scaling_group(AutoScalingGroupName=autoscaling_group_name, ForceDelete=True)
        print(f"Auto Scaling Group '{autoscaling_group_name}' deletion initiated.")
        wait_for_deletion(
            check_func=lambda **args: any(asg['AutoScalingGroupName'] == autoscaling_group_name for asg in autoscaling_client.describe_auto_scaling_groups()['AutoScalingGroups'])
        )
    except autoscaling_client.exceptions.ResourceInUseFault:
        print(f"Auto Scaling Group '{autoscaling_group_name}' not found, skipping.")
    except Exception as e:
        print(f"Error deleting Auto Scaling Group: {e}")

def delete_launch_template():
    try:
        response = ec2_client.describe_launch_templates(Filters=[{'Name': 'launch-template-name', 'Values': [launch_template_name]}])
        if response['LaunchTemplates']:
            launch_template_id = response['LaunchTemplates'][0]['LaunchTemplateId']
            ec2_client.delete_launch_template(LaunchTemplateId=launch_template_id)
            print(f"Launch Template '{launch_template_name}' deleted.")
        else:
            print(f"Launch Template '{launch_template_name}' not found, skipping.")
    except Exception as e:
        print(f"Error deleting Launch Template: {e}")

def delete_security_groups():
    for sg_name in [public_sg_name, private_sg_name]:
        try:
            security_groups = ec2_client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': [sg_name]}])
            if security_groups['SecurityGroups']:
                sg_id = security_groups['SecurityGroups'][0]['GroupId']
                ec2_client.delete_security_group(GroupId=sg_id)
                print(f"Security Group '{sg_name}' deleted.")
            else:
                print(f"Security Group '{sg_name}' not found, skipping.")
        except Exception as e:
            print(f"Error deleting Security Group '{sg_name}': {e}")

def delete_db_subnet_group():
    try:
        response = rds_client.describe_db_subnet_groups()
        db_subnet_group_exists = any(subnet['DBSubnetGroupName'] == DBSubnetGroupName for subnet in response['DBSubnetGroups'])
        if db_subnet_group_exists:
            rds_client.delete_db_subnet_group(DBSubnetGroupName=DBSubnetGroupName)
            print(f"DB Subnet Group '{DBSubnetGroupName}' deleted.")
        else:
            print(f"DB Subnet Group '{DBSubnetGroupName}' not found, skipping.")
    except Exception as e:
        print(f"Error deleting DB Subnet Group: {e}")

def disassociate_and_release_elastic_ips():
    addresses = ec2_client.describe_addresses()['Addresses']
    for address in addresses:
        allocation_id = address['AllocationId']
        if 'AssociationId' in address:
            association_id = address['AssociationId']
            try:
                ec2_client.disassociate_address(AssociationId=association_id)
                print(f"Disassociated Elastic IP: {address['PublicIp']}")
            except Exception as e:
                print(f"Failed to disassociate Elastic IP {address['PublicIp']}: {e}")
        
        try:
            ec2_client.release_address(AllocationId=allocation_id)
            print(f"Released Elastic IP: {address['PublicIp']}")
        except Exception as e:
            print(f"Failed to release Elastic IP {address['PublicIp']}: {e}")

def delete_nat_gateways(vpc_id):
    nat_gateways = ec2_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['NatGateways']
    for nat_gw in nat_gateways:
        nat_gw_id = nat_gw['NatGatewayId']
        try:
            ec2_client.delete_nat_gateway(NatGatewayId=nat_gw_id)
            print(f"Deleting NAT Gateway: {nat_gw_id}")
            wait_for_deletion(
                check_func=lambda: any(ng['NatGatewayId'] == nat_gw_id for ng in ec2_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['NatGateways'])
            )
        except Exception as e:
            print(f"Error deleting NAT Gateway '{nat_gw_id}': {e}")

def delete_internet_gateways(vpc_id):
    igws = ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])['InternetGateways']
    for igw in igws:
        igw_id = igw['InternetGatewayId']
        try:
            ec2_client.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
            ec2_client.delete_internet_gateway(InternetGatewayId=igw_id)
            print(f"Deleted Internet Gateway: {igw_id}")
        except Exception as e:
            print(f"Error deleting Internet Gateway '{igw_id}': {e}")

def delete_vpc():
    vpcs = ec2_client.describe_vpcs(Filters=[{'Name': 'tag:Name', 'Values': [vpc_name]}])
    if vpcs['Vpcs']:
        vpc_id = vpcs['Vpcs'][0]['VpcId']
        print(f"VPC found: {vpc_id} with Name '{vpc_name}'. Deleting dependencies...")

        # Delete all subnets after removing NAT gateways and internet gateways
        delete_nat_gateways(vpc_id)
        delete_internet_gateways(vpc_id)

        # Delete route tables (excluding the main route table)
        route_tables = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for rt in route_tables['RouteTables']:
            if not any(assoc.get('Main', False) for assoc in rt.get('Associations', [])):
                try:
                    ec2_client.delete_route_table(RouteTableId=rt['RouteTableId'])
                    print(f"Route Table '{rt['RouteTableId']}' deleted.")
                except Exception as e:
                    print(f"Failed to delete Route Table '{rt['RouteTableId']}': {e}")

        # Delete security groups and Elastic IPs
        delete_security_groups()
        disassociate_and_release_elastic_ips()

        # Delete subnets
        subnets = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for subnet in subnets['Subnets']:
            try:
                ec2_client.delete_subnet(SubnetId=subnet['SubnetId'])
                print(f"Subnet '{subnet['SubnetId']}' deleted.")
            except Exception as e:
                print(f"Failed to delete Subnet '{subnet['SubnetId']}': {e}")

        # Finally, delete the VPC
        try:
            ec2_client.delete_vpc(VpcId=vpc_id)
            print(f"VPC '{vpc_id}' with Name '{vpc_name}' deleted.")
        except Exception as e:
            print(f"Failed to delete VPC '{vpc_id}': {e}")
    else:
        print(f"No VPC found with Name '{vpc_name}'")

# Execute deletions
delete_bastion_server()
delete_rds_instance()
delete_load_balancer()
delete_efs_and_mount_targets()
delete_target_group()
delete_route53_record()
delete_autoscaling_group()
delete_launch_template()
delete_security_groups()
delete_db_subnet_group()
delete_vpc()  # This will call delete_nat_gateways and delete_internet_gateways with the correct vpc_id
