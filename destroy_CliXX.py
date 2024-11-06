#!/usr/bin/env python3
import boto3
import logging
import time
from botocore.exceptions import ClientError

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# AWS Configuration Variables
aws_region = "us-east-1"
vpc_name = "STACK-CP-VPC"
security_group_names = ['CLIXX-PublicSG', 'CLIXX-PrivateSG']
db_instance_identifiers = ['wordpressdbclixx']
efs_names = ['CLiXX-EFS']
load_balancer_names = ['CLIXX-LoadBalancer']
asg_names = ['CLiXX-ASG']
instance_names_to_delete = ['CLIXX-BastionHost']
role_arn = 'arn:aws:iam::619071313311:role/Engineer'
db_subnet_group_names = ['clixxstackdbsubnetgroup']
hosted_zone_id = "Z0881876FFUR3OKRNM20"
record_name= "dev.clixx-dasola.com"

# Assume Role to interact with AWS resources
sts_client = boto3.client('sts')
assumed_role_object = sts_client.assume_role(RoleArn=role_arn, RoleSessionName='engineer_session')
credentials = assumed_role_object['Credentials']

# Create boto3 clients with assumed role credentials
ec2_client = boto3.client('ec2', region_name=aws_region,
                           aws_access_key_id=credentials['AccessKeyId'],
                           aws_secret_access_key=credentials['SecretAccessKey'],
                           aws_session_token=credentials['SessionToken'])
elbv2_client = boto3.client('elbv2', region_name=aws_region,
                           aws_access_key_id=credentials['AccessKeyId'],
                           aws_secret_access_key=credentials['SecretAccessKey'],
                           aws_session_token=credentials['SessionToken'])
rds_client = boto3.client('rds', region_name=aws_region,
                           aws_access_key_id=credentials['AccessKeyId'],
                           aws_secret_access_key=credentials['SecretAccessKey'],
                           aws_session_token=credentials['SessionToken'])
efs_client = boto3.client('efs', region_name=aws_region,
                           aws_access_key_id=credentials['AccessKeyId'],
                           aws_secret_access_key=credentials['SecretAccessKey'],
                           aws_session_token=credentials['SessionToken'])
autoscaling_client = boto3.client('autoscaling', region_name=aws_region,
                            aws_access_key_id=credentials['AccessKeyId'],
                            aws_secret_access_key=credentials['SecretAccessKey'],
                            aws_session_token=credentials['SessionToken'])
route53_client = boto3.client('route53', region_name=aws_region,
                            aws_access_key_id=credentials['AccessKeyId'],
                            aws_secret_access_key=credentials['SecretAccessKey'],
                            aws_session_token=credentials['SessionToken'])

# Function Definitions

def delete_efs(efs_names):
    try:
        efs_filesystems = efs_client.describe_file_systems()
        deleted_filesystems = []

        for fs in efs_filesystems['FileSystems']:
            if fs.get('Name') in efs_names:
                file_system_id = fs['FileSystemId']
                delete_mount_targets(file_system_id)
                efs_client.delete_file_system(FileSystemId=file_system_id)
                logger.info(f"Deleted EFS: {fs.get('Name')} (ID: {file_system_id})")
                deleted_filesystems.append(file_system_id)

                # Wait for EFS deletion
                wait_for_efs_deletion(file_system_id)

        if not deleted_filesystems:
            logger.info(f"No EFS found with the names {efs_names}, skipping deletion.")
    except ClientError as e:
        logger.error(f"Error deleting EFS: {e}")

def wait_for_efs_deletion(file_system_id):
    while True:
        try:
            efs_client.describe_file_systems(FileSystemId=file_system_id)
            logger.info(f"Waiting for EFS (ID: {file_system_id}) to be deleted...")
            time.sleep(5)  # Check every 5 seconds
        except ClientError as e:
            if e.response['Error']['Code'] == 'FileSystemNotFound':
                logger.info(f"EFS (ID: {file_system_id}) has been successfully deleted.")
                break
            else:
                logger.error(f"Error checking EFS status: {e}")
                break

def delete_mount_targets(file_system_id):
    try:
        mount_targets = efs_client.describe_mount_targets(FileSystemId=file_system_id)
       
        for mt in mount_targets['MountTargets']:
            efs_client.delete_mount_target(MountTargetId=mt['MountTargetId'])
            logger.info(f"Deleted Mount Target: {mt['MountTargetId']} for EFS ID: {file_system_id}")

            # Wait for the mount target to be deleted
            wait_for_mount_target_deletion(mt['MountTargetId'])
   
        logger.info(f"All mount targets for EFS ID {file_system_id} have been deleted.")
       
    except ClientError as e:
        logger.error(f"Error deleting Mount Targets for EFS ID {file_system_id}: {e}")

def wait_for_mount_target_deletion(mount_target_id):
    while True:
        try:
            efs_client.describe_mount_targets(MountTargetId=mount_target_id)
            logger.info(f"Waiting for Mount Target (ID: {mount_target_id}) to be deleted...")
            time.sleep(5)  # Check every 5 seconds
        except ClientError as e:
            if e.response['Error']['Code'] == 'MountTargetNotFound':
                logger.info(f"Mount Target (ID: {mount_target_id}) has been successfully deleted.")
                break
            else:
                logger.error(f"Error checking Mount Target status: {e}")
                break

def delete_instances_by_names(instance_names):
    try:
        # Describe all instances
        response = ec2_client.describe_instances()
       
        instance_ids_to_terminate = []

        # Iterate over all reservations and instances
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                # Get the instance ID and name tag
                instance_id = instance['InstanceId']
                instance_tags = instance.get('Tags', [])
                instance_name = next(
                    (tag['Value'] for tag in instance_tags if tag['Key'] == 'Name'),
                    None
                )
               
                # Check if the instance name is in the provided list
                if instance_name in instance_names:
                    instance_ids_to_terminate.append(instance_id)

        if instance_ids_to_terminate:
            logger.info(f"Terminating instances: {instance_ids_to_terminate}")
            ec2_client.terminate_instances(InstanceIds=instance_ids_to_terminate)
            wait_for_termination(instance_ids_to_terminate)

        else:
            logger.info("No instances found to delete.")

    except ClientError as e:
        logger.error(f"Error deleting instances: {e}")

def wait_for_termination(instance_ids):
    while True:
        response = ec2_client.describe_instances(InstanceIds=instance_ids)
        running_instances = [
            instance for reservation in response['Reservations']
            for instance in reservation['Instances']
            if instance['State']['Name'] != 'terminated'
        ]
        if not running_instances:
            logger.info("All instances have been terminated.")
            break
        logger.info(f"Still waiting for instances to terminate: {[instance['InstanceId'] for instance in running_instances]}")
        time.sleep(10)


def delete_auto_scaling_groups(asg_names):
    try:
        # Describe all Auto Scaling Groups
        response = autoscaling_client.describe_auto_scaling_groups()

        if not response['AutoScalingGroups']:
            logger.info("No Auto Scaling Groups found, skipping deletion.")
            return

        for asg in response['AutoScalingGroups']:
            asg_name = asg['AutoScalingGroupName']
            if asg_name in asg_names:
                instances = asg['Instances']
                instance_ids = [instance['InstanceId'] for instance in instances]

                if instance_ids:
                    logger.info(f"Terminating instances in Auto Scaling Group: {asg_name} - {instance_ids}")
                    ec2_client.terminate_instances(InstanceIds=instance_ids)
                    wait_for_termination(instance_ids)

                autoscaling_client.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
                logger.info(f"Deleted Auto Scaling Group: {asg_name}")

    except ClientError as e:
        logger.error(f"Error deleting Auto Scaling Groups: {e}")


def wait_for_termination(instance_ids):
    while True:
        response = ec2_client.describe_instances(InstanceIds=instance_ids)
        running_instances = [instance for reservation in response['Reservations'] for instance in reservation['Instances'] if instance['State']['Name'] != 'terminated']
        if not running_instances:
            logger.info("All instances have been terminated.")
            break
        logger.info(f"Still waiting for instances to terminate: {[instance['InstanceId'] for instance in running_instances]}")
        time.sleep(10)

def delete_load_balancers(load_balancer_names):
    try:
        # Describe all load balancers
        response = elbv2_client.describe_load_balancers()
        existing_load_balancers = {lb['LoadBalancerName']: lb['LoadBalancerArn'] for lb in response['LoadBalancers']}
       
        for lb_name in load_balancer_names:
            if lb_name in existing_load_balancers:
                lb_arn = existing_load_balancers[lb_name]
                elbv2_client.delete_load_balancer(LoadBalancerArn=lb_arn)
                logger.info(f"Deleted Load Balancer: {lb_name}")

                # Wait until the load balancer is fully deleted
                wait_for_load_balancer_deletion(lb_name)
            else:
                logger.info(f"No Load Balancer found with the name: {lb_name}, skipping deletion.")

    except ClientError as e:
        if e.response['Error']['Code'] == 'LoadBalancerNotFound':
            logger.info(f"Load Balancer not found, skipping deletion.")
        else:
            logger.error(f"Error deleting Load Balancer: {e}")

def wait_for_load_balancer_deletion(load_balancer_name):
    while True:
        try:
            # Check the status of the load balancer
            response = elbv2_client.describe_load_balancers(Names=[load_balancer_name])
            logger.info(f"Current status of Load Balancer '{load_balancer_name}': {response['LoadBalancers'][0]['State']}")
           
            logger.info(f"Waiting for Load Balancer '{load_balancer_name}' to be deleted...")
            logger.info("Checking again in 20 seconds...")
            time.sleep(20)  # Wait for 20 seconds before checking again
        except ClientError as e:
            if e.response['Error']['Code'] == 'LoadBalancerNotFound':
                logger.info(f"Load Balancer '{load_balancer_name}' has been successfully deleted.")
                break
            else:
                logger.error(f"Error checking Load Balancer status: {e}")
                break


def wait_for_deletion(check_function, not_found_error_code, resource_type):
    while True:
        try:
            check_function()
            logger.info(f"Waiting for {resource_type} to be deleted...")
            time.sleep(5)
        except ClientError as e:
            if e.response['Error']['Code'] == not_found_error_code:
                logger.info(f"{resource_type} deleted successfully.")
                break
            logger.error(f"Error checking {resource_type} status: {e}")

def delete_rds_instances(db_instance_identifiers):
    for db_instance_identifier in db_instance_identifiers:
        try:
            rds_client.delete_db_instance(DBInstanceIdentifier=db_instance_identifier, SkipFinalSnapshot=True)
            logger.info(f"Initiated deletion of RDS instance: {db_instance_identifier}")

            # Wait for deletion with status messaging
            wait_for_rds_instance_deletion(db_instance_identifier)

        except ClientError as e:
            if e.response['Error']['Code'] == 'DBInstanceNotFound':
                logger.info(f"RDS instance {db_instance_identifier} not found, skipping deletion.")
            else:
                logger.error(f"Error deleting RDS instance {db_instance_identifier}: {e}")

def wait_for_rds_instance_deletion(instance_identifier, check_interval=30):
    while True:
        try:
            # Describe the RDS instance to get its current status
            response = rds_client.describe_db_instances(DBInstanceIdentifier=instance_identifier)
            db_instance_status = response['DBInstances'][0]['DBInstanceStatus']
            logger.info(f"Current status of RDS instance {instance_identifier}: {db_instance_status}")
           
            logger.info(f"Deletion in process for RDS instance {instance_identifier}. Checking again in {check_interval} seconds...")
            time.sleep(check_interval)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBInstanceNotFound':
                logger.info(f"RDS instance {instance_identifier} has been successfully deleted.")
                break
            else:
                logger.error(f"Error checking status of RDS instance {instance_identifier}: {e}")
                break
               
def delete_rds_subnet_groups(db_subnet_group_names):
    for db_subnet_group_name in db_subnet_group_names:
        try:
            response = rds_client.describe_db_subnet_groups(DBSubnetGroupName=db_subnet_group_name)
           
            if response['DBSubnetGroups']:
                rds_client.delete_db_subnet_group(DBSubnetGroupName=db_subnet_group_name)
                logger.info(f"Initiated deletion of DB Subnet Group: {db_subnet_group_name}")

                # Wait for deletion with status messaging
                wait_for_subnet_group_deletion(db_subnet_group_name)
            else:
                logger.info(f"DB Subnet Group '{db_subnet_group_name}' does not exist.")

        except ClientError as e:
            if e.response['Error']['Code'] == 'DBSubnetGroupNotFoundFault':
                logger.info(f"DB Subnet Group '{db_subnet_group_name}' does not exist.")
            else:
                logger.error(f"Error deleting DB Subnet Group '{db_subnet_group_name}': {e}")

def wait_for_subnet_group_deletion(subnet_group_name, check_interval=10):
    while True:
        try:
            rds_client.describe_db_subnet_groups(DBSubnetGroupName=subnet_group_name)
            logger.info(f"Still waiting for DB Subnet Group '{subnet_group_name}' to be deleted. Checking again in {check_interval} seconds...")
            time.sleep(check_interval)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBSubnetGroupNotFoundFault':
                logger.info(f"DB Subnet Group '{subnet_group_name}' has been successfully deleted.")
                break
            else:
                logger.error(f"Error checking status of DB Subnet Group '{subnet_group_name}': {e}")
                break

def remove_rules_from_security_groups(security_group_names, vpc_id):
    try:
        for sg_name in security_group_names:
            security_groups = ec2_client.describe_security_groups(
                Filters=[
                    {'Name': 'group-name', 'Values': [sg_name]},
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )

            for sg in security_groups['SecurityGroups']:
                # Remove all inbound rules
                if sg['IpPermissions']:
                    logger.info(f"Removing inbound rules from Security Group: {sg['GroupId']} (Name: {sg_name})")
                    ec2_client.revoke_security_group_ingress(GroupId=sg['GroupId'], IpPermissions=sg['IpPermissions'])

                # Remove all outbound rules
                if sg['IpPermissionsEgress']:
                    logger.info(f"Removing outbound rules from Security Group: {sg['GroupId']} (Name: {sg_name})")
                    ec2_client.revoke_security_group_egress(GroupId=sg['GroupId'], IpPermissions=sg['IpPermissionsEgress'])

    except ClientError as e:
        logger.error(f"Error removing rules from Security Groups: {e}")

def delete_security_groups(security_group_names, vpc_id):
    try:
        for sg_name in security_group_names:
            security_groups = ec2_client.describe_security_groups(
                Filters=[
                    {'Name': 'group-name', 'Values': [sg_name]},
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )

            for sg in security_groups['SecurityGroups']:
                # Now delete the security group after rules have been removed
                ec2_client.delete_security_group(GroupId=sg['GroupId'])
                logger.info(f"Deleted Security Group: {sg['GroupId']} (Name: {sg_name})")

    except ClientError as e:
        logger.error(f"Error deleting Security Groups: {e}")


def delete_subnets(vpc_id):
    try:
        subnets = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for subnet in subnets['Subnets']:
            ec2_client.delete_subnet(SubnetId=subnet['SubnetId'])
            logger.info(f"Deleted Subnet: {subnet['SubnetId']}")
    except ClientError as e:
        logger.error(f"Error deleting Subnets: {e}")

def delete_internet_gateway(vpc_id):
    try:
        igw = ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
        if igw['InternetGateways']:
            igw_id = igw['InternetGateways'][0]['InternetGatewayId']
            ec2_client.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
            ec2_client.delete_internet_gateway(InternetGatewayId=igw_id)
            logger.info(f"Deleted Internet Gateway: {igw_id}")
        else:
            logger.info("No Internet Gateway found for the specified VPC.")
    except ClientError as e:
        logger.error(f"Error deleting Internet Gateway: {e}")

def delete_route_tables(vpc_id):
    try:
        route_tables = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
       
        for rt in route_tables['RouteTables']:
            if rt.get('Associations'):
                if rt['Associations'][0]['Main']:
                    logger.info(f"Skipping main route table: {rt['RouteTableId']}")
                    continue

                for association in rt['Associations']:
                    # Disassociate using only the AssociationId
                    ec2_client.disassociate_route_table(AssociationId=association['RouteTableAssociationId'])
                    logger.info(f"Disassociated Route Table: {rt['RouteTableId']} from Subnet with Association ID: {association['RouteTableAssociationId']}.")

            # Now delete the route table
            ec2_client.delete_route_table(RouteTableId=rt['RouteTableId'])
            logger.info(f"Deleted Route Table: {rt['RouteTableId']}")

            # Wait for the route table to be deleted without using a lambda
            wait_for_route_table_deletion(rt['RouteTableId'])

    except ClientError as e:
        logger.error(f"Error deleting Route Tables: {e}")


def wait_for_route_table_deletion(route_table_id):
    while True:
        try:
            ec2_client.describe_route_tables(RouteTableIds=[route_table_id])
            logger.info("Waiting for Route Table to be deleted...")
            time.sleep(10)  # Check every 10 seconds
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidRouteTableID.NotFound':
                logger.info(f"Route Table {route_table_id} has been fully deleted.")
                break
            else:
                logger.error(f"Error checking Route Table status: {e}")
                break

def wait_for_nat_gateway_deletion(nat_gateway_id):
    while True:
        try:
            ec2_client.describe_nat_gateways(NatGatewayIds=[nat_gateway_id])
            logger.info("Waiting for NAT Gateway to be deleted...")
            time.sleep(10)  # Check every 10 seconds
        except ClientError as e:
            if e.response['Error']['Code'] == 'NatGatewayNotFound':
                logger.info(f"NAT Gateway {nat_gateway_id} has been fully deleted.")
                break
            else:
                logger.error(f"Error checking NAT Gateway status: {e}")
                break

def wait_for_nat_gateway_deletion(nat_gateway_id, check_interval=30):
    while True:
        try:
            response = ec2_client.describe_nat_gateways(NatGatewayIds=[nat_gateway_id])
            nat_gateway_status = response['NatGateways'][0]['State']
            logger.info(f"Current status of NAT Gateway {nat_gateway_id}: {nat_gateway_status}")

            if nat_gateway_status == 'deleted':
                logger.info(f"NAT Gateway {nat_gateway_id} has been successfully deleted.")
                break
           
            logger.info(f"Deletion in process for NAT Gateway {nat_gateway_id}. Checking again in {check_interval} seconds...")
            time.sleep(check_interval)
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidNatGatewayID.NotFound':
                logger.info(f"NAT Gateway {nat_gateway_id} has been successfully deleted.")
                break
            else:
                logger.error(f"Error checking status of NAT Gateway {nat_gateway_id}: {e}")
                break

def delete_nat_gateways(vpc_id):
    try:
        nat_gateways = ec2_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for nat in nat_gateways['NatGateways']:
            ec2_client.delete_nat_gateway(NatGatewayId=nat['NatGatewayId'])
            logger.info(f"Deleted NAT Gateway: {nat['NatGatewayId']}")

            # Wait for the NAT gateway to be deleted
            wait_for_nat_gateway_deletion(nat['NatGatewayId'])

    except ClientError as e:
        logger.error(f"Error deleting NAT Gateways: {e}")

def release_elastic_ips():
    try:
        addresses = ec2_client.describe_addresses()
        for addr in addresses['Addresses']:
            if 'AssociationId' in addr:
                logger.info(f"Releasing Elastic IP: {addr['PublicIp']}")
                ec2_client.release_address(AllocationId=addr['AllocationId'])
                logger.info(f"Released Elastic IP: {addr['PublicIp']}")
    except ClientError as e:
        logger.error(f"Error releasing Elastic IPs: {e}")

def release_public_ips():
    try:
        instances = ec2_client.describe_instances(Filters=[{'Name': 'network-interface.association.public-ip', 'Values': ['*']}])
        instances_to_stop = []

        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                for network_interface in instance['NetworkInterfaces']:
                    if 'Association' in network_interface and 'PublicIp' in network_interface['Association']:
                        public_ip = network_interface['Association']['PublicIp']
                        logger.info(f"Releasing public IP: {public_ip} from instance {instance['InstanceId']}")
                        ec2_client.stop_instances(InstanceIds=[instance['InstanceId']])
                        instances_to_stop.append(instance['InstanceId'])

        if instances_to_stop:
            wait_for_termination(instances_to_stop)
    except ClientError as e:
        logger.error(f"Error releasing public IPs: {e}")

def delete_all_network_interfaces(vpc_id):
    ec2_client = boto3.client('ec2')

    try:
        # Describe all network interfaces in the VPC
        network_interfaces = ec2_client.describe_network_interfaces(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )

        for ni in network_interfaces['NetworkInterfaces']:
            ni_id = ni['NetworkInterfaceId']
            try:
                # Delete the network interface
                ec2_client.delete_network_interface(NetworkInterfaceId=ni_id)
                logger.info(f"Deleted Network Interface: {ni_id}")

                # Wait for the network interface to be deleted
                waiter = ec2_client.get_waiter('network_interface_deleted')
                waiter.wait(NetworkInterfaceIds=[ni_id])
                logger.info(f"Confirmed deletion of Network Interface: {ni_id}")

            except ClientError as e:
                logger.error(f"Error deleting Network Interface {ni_id}: {e}")

    except ClientError as e:
        logger.error(f"Error describing network interfaces for VPC {vpc_id}: {e}")

def delete_all_elastic_ips():
    ec2_client = boto3.client('ec2')
   
    try:
        # Describe all Elastic IPs
        response = ec2_client.describe_addresses()
        addresses = response.get('Addresses', [])
       
        # Iterate over each Elastic IP
        for address in addresses:
            eip = address['PublicIp']
            print(f"Deleting Elastic IP: {eip}")
           
            # Release the Elastic IP
            ec2_client.release_address(AllocationId=address['AllocationId'])
   
    except Exception as e:
        print(f"An error occurred: {e}")


def remove_route53_record_set(hosted_zone_id, record_name):
    try:
        # Check if the Route 53 record set exists
        response = route53_client.list_resource_record_sets(HostedZoneId=hosted_zone_id)
        record_found = False

        for record in response['ResourceRecordSets']:
            if record['Name'].rstrip('.') == record_name:
                logging.info(f"Route 53 record set {record_name} found. Deleting it...")
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
                logging.info(f"Deleted existing Route 53 record set {record_name}.")
                record_found = True
                break  # Exit the loop after deletion

        # Wait for the deletion to complete if a record was found
        if record_found:
            logging.info(f"Waiting for deletion of Route 53 record set {record_name}...")
            for attempt in range(8):  # Check for up to 2 minutes
                time.sleep(15)  # Wait for 15 seconds before checking again
                response = route53_client.list_resource_record_sets(HostedZoneId=hosted_zone_id)
                deletion_status = any(record['Name'].rstrip('.') == record_name for record in response['ResourceRecordSets'])

                if not deletion_status:
                    logging.info(f"Route 53 record set {record_name} has been successfully deleted.")
                    break
                else:
                    logging.info(f"Route 53 record set {record_name} is still being deleted. Checking again in 15 seconds...")
            else:
                logging.warning(f"Route 53 record set {record_name} deletion still in progress after 2 minutes.")

    except Exception as e:
        logging.error(f"Error removing Route 53 record set: {str(e)}")

def delete_vpc(vpc_id):
    try:
        ec2_client.delete_vpc(VpcId=vpc_id)
        logger.info(f"Deleted VPC: {vpc_id}")
    except ClientError as e:
        logger.error(f"Error deleting VPC: {e}")

def wait_for_deletion(check_function, expected_error_code, resource_name):
    while True:
        try:
            check_function()
            logger.info(f"Waiting for {resource_name} to be deleted...")
            time.sleep(5)
        except ClientError as e:
            if e.response['Error']['Code'] == expected_error_code:
                logger.info(f"{resource_name} deleted successfully.")
                break
            logger.error(f"Error checking {resource_name} status: {e}")

def delete_vpcs(vpc_name, asg_names, load_balancer_names, db_instance_identifiers, efs_names, db_subnet_group_names, security_group_names):
    try:
        vpcs = ec2_client.describe_vpcs(Filters=[{'Name': 'tag:Name', 'Values': [vpc_name]}])
        if not vpcs['Vpcs']:
            logger.info(f"VPC {vpc_name} not found, skipping deletion.")
            return
       
        for vpc in vpcs['Vpcs']:
            vpc_id = vpc['VpcId']
            logger.info(f"Processing VPC: {vpc_id} (Name: {vpc_name})")
            delete_instances_by_names(instance_names_to_delete)
            delete_auto_scaling_groups(asg_names=asg_names)
            release_public_ips()
            delete_load_balancers(load_balancer_names=load_balancer_names)
            delete_rds_instances(db_instance_identifiers=db_instance_identifiers)
            delete_efs(efs_names=efs_names)
            delete_nat_gateways(vpc_id=vpc_id)
            release_elastic_ips()
            delete_rds_subnet_groups(db_subnet_group_names=db_subnet_group_names)
            delete_route_tables(vpc_id=vpc_id)
            delete_internet_gateway(vpc_id=vpc_id)
            delete_all_network_interfaces(vpc_id)
            remove_route53_record_set(hosted_zone_id=hosted_zone_id, record_name=record_name)
            remove_rules_from_security_groups(security_group_names=security_group_names, vpc_id=vpc_id)
            delete_security_groups(security_group_names=security_group_names, vpc_id=vpc_id)
            delete_all_elastic_ips()
            delete_subnets(vpc_id=vpc_id)
            delete_vpc(vpc_id=vpc_id)
            logger.info("Clixx deployment cleanup Completed.")
    except ClientError as e:
        logger.error(f"Error retrieving VPC: {e}")
 
def main():
    delete_vpcs(vpc_name=vpc_name, asg_names=asg_names, load_balancer_names=load_balancer_names, db_instance_identifiers=db_instance_identifiers, efs_names=efs_names, db_subnet_group_names=db_subnet_group_names, security_group_names=security_group_names)

if __name__ == "__main__":
    main()
