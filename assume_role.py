#!/usr/bin/python

import boto3,botocore

sts_client=boto3.client('sts')

#Calling the assume_role function
assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::619071313311:role/Engineer', RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']

print(credentials)


ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])

# Check if the security group already exists
    try:
        response = ec2.describe_security_groups(GroupNames=['my-security-group'])
        print("Security group already exists:", response['SecurityGroups'][0]['GroupId'])
    except ClientError as e:
        if 'InvalidGroup.NotFound' in str(e):
            print("Security group not found, creating it now...")
            # Try creating the security group
            response = ec2.create_security_group(
                Description='My security group',
                GroupName='my-security-group',
                VpcId='vpc-0d9565fdd6b841224'  # Replace with your actual VPC ID
            )
            print("Security group created successfully:", response['GroupId'])
        else:
            print("Error while checking or creating security group:", e)

except ClientError as e:
    print("Error assuming role or making AWS requests:", e)

