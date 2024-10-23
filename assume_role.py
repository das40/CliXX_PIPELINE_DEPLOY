#!/usr/bin/python

import boto3
import botocore
from botocore.exceptions import ClientError

# Create STS client
sts_client = boto3.client('sts')

try:
    # Calling the assume_role function
    assumed_role_object = sts_client.assume_role(
        RoleArn='arn:aws:iam::619071313311:role/Engineer', 
        RoleSessionName='mysession'
    )
    
    # Extract credentials
    credentials = assumed_role_object['Credentials']
    print("Assumed role successfully.")
    
    # Create EC2 client using the assumed role credentials
    ec2 = boto3.client(
        'ec2',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name='us-east-1'  # Specify your region here
    )
    
    # Fetch the default VPC (if needed)
    try:
        default_vpc = ec2.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
        vpc_id = default_vpc['Vpcs'][0]['VpcId']
        print(f"Using default VPC: {vpc_id}")
    except ClientError as e:
        print("Error fetching default VPC:", e)
        raise e

    # Check if the security group already exists
    try:
        response = ec2.describe_security_groups(GroupNames=['my-security-group'])
        print("Security group already exists:", response['SecurityGroups'][0]['GroupId'])
    except ClientError as e:
        if 'InvalidGroup.NotFound' in str(e):
            print("Security group not found, creating it now...")
            # Try creating the security group in the default VPC
            response = ec2.create_security_group(
                Description='My security group',
                GroupName='my-security-group',
                VpcId=vpc_id  # Use the fetched VPC ID
            )
            print("Security group created successfully:", response['GroupId'])
        else:
            print("Error while checking or creating security group:", e)

except ClientError as e:
    print("Error assuming role or making AWS requests:", e)
