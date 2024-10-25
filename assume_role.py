import boto3
from botocore.exceptions import ClientError

# Function to assume a role in the target account
def assume_role(role_arn, session_name):
    sts_client = boto3.client('sts')
    
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )
        credentials = response['Credentials']
        
        return {
            'aws_access_key_id': credentials['AccessKeyId'],
            'aws_secret_access_key': credentials['SecretAccessKey'],
            'aws_session_token': credentials['SessionToken']
        }
    except ClientError as e:
        print(f"Error assuming role: {e}")
        return None

# Call assume_role to get credentials for the engineering development account
role_arn = 'arn:aws:iam::619071313311:role/Engineer'
session_name = 'MyCodeBuildSession'

# Get the assumed role credentials
assumed_role_credentials = assume_role(role_arn, session_name)

if assumed_role_credentials:
    # Use the assumed role's credentials to create boto3 clients in the target account
    ec2_client = boto3.client('ec2', 
                              aws_access_key_id=assumed_role_credentials['aws_access_key_id'],
                              aws_secret_access_key=assumed_role_credentials['aws_secret_access_key'],
                              aws_session_token=assumed_role_credentials['aws_session_token'])
    
    rds_client = boto3.client('rds', 
                              aws_access_key_id=assumed_role_credentials['aws_access_key_id'],
                              aws_secret_access_key=assumed_role_credentials['aws_secret_access_key'],
                              aws_session_token=assumed_role_credentials['aws_session_token'])

    elb_client = boto3.client('elbv2',
                              aws_access_key_id=assumed_role_credentials['aws_access_key_id'],
                              aws_secret_access_key=assumed_role_credentials['aws_secret_access_key'],
                              aws_session_token=assumed_role_credentials['aws_session_token'])

    autoscaling_client = boto3.client('autoscaling',
                                      aws_access_key_id=assumed_role_credentials['aws_access_key_id'],
                                      aws_secret_access_key=assumed_role_credentials['aws_secret_access_key'],
                                      aws_session_token=assumed_role_credentials['aws_session_token'])
else:
    print("Failed to assume role. Exiting.")
    exit(1)
