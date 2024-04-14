import os
import boto3
import yaml
import json
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get the environment folder name
secrets_folder = os.getenv('ENV_FOLDER')

if not secrets_folder:
    raise ValueError("ENV_FOLDER environment variable is not set")

# Append a slash if it's not present
if not secrets_folder.endswith('/'):
    secrets_folder += '/'

# Load the YAML file
with open(secrets_folder + 'secrets.yaml', 'r') as file:
    secrets_config = yaml.safe_load(file)

# Create a KMS client
kms_client = boto3.client('kms')

# Create a Secrets Manager client
secretsmanager_client = boto3.client('secretsmanager')

# Iterate over each secret in the list of secrets
for secret in secrets_config['secrets']:
    if secret.get('isConsumableSecret', False):
        secret_name = secret['name']
        secret_description = secret['description']
        role_arns = secret.get('role_arns', [])
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": role_arns},
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": "*"
                }
            ]
        }

        policy_str = json.dumps(policy)

        try:
            secretsmanager_client.update_secret(
                SecretId=secret_name,
                Description=secret_description
            )
            
            secretsmanager_client.put_resource_policy(
                SecretId=secret_name,
                ResourcePolicy=policy_str
            )
            print(f"Updated secret {secret_name} with new description and policy.")
        except ClientError as e:
            print(f"Error updating secret {secret_name}: {e}")
    else:
        # Process secrets with isConsumableSecret: false
        secret_name = secret['name']
        kms_key_id = secret['kms_key_id']
        encrypted_file = secrets_folder + secret['name'] + ".enc"

        # Read and decrypt the data
        with open(encrypted_file, 'rb') as enc_file:
            encrypted_data = enc_file.read()

        decrypt_response = kms_client.decrypt(CiphertextBlob=encrypted_data, KeyId=kms_key_id)
        decrypted_data = decrypt_response['Plaintext']
        decrypted_secret = decrypted_data.decode('utf-8')

        try:
            # Update or create secret depending on its existence
            try:
                # Check if the secret already exists
                secretsmanager_client.describe_secret(SecretId=secret_name)
                exists = True
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    exists = False
                else:
                    raise
            
            if exists:
                secretsmanager_client.update_secret(
                    SecretId=secret_name,
                    SecretString=decrypted_secret
                )

                secretsmanager_client.put_resource_policy(
                    SecretId=secret_name,
                    ResourcePolicy=policy_str
                )

                print(f"Updated secret {secret_name}.")
            else:
                secretsmanager_client.create_secret(
                    Name=secret_name,
                    SecretString=decrypted_secret
                )

                secretsmanager_client.put_resource_policy(
                    SecretId=secret_name,
                    ResourcePolicy=policy_str
                )

                print(f"Created secret {secret_name}.")
        except ClientError as e:
            print(f"Error updating or creating secret {secret_name}: {e}")
