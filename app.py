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

# print(secrets_folder)

if not secrets_folder:
    raise ValueError("ENV_FOLDER environment variable is not set")

# Append a slash if it's not present
if not secrets_folder.endswith('/'):
    secrets_folder += '/'

# Load the YAML file
with open(secrets_folder + 'secrets.yaml', 'r') as file:
    secrets_config = yaml.safe_load(file)

# print(secrets_config)

# Create a KMS client
kms_client = boto3.client('kms')

# Create a Secrets Manager client
secretsmanager_client = boto3.client('secretsmanager')

# Iterate over each secret in the list of secrets
for secret in secrets_config['secrets']:
    # print(secret)
    secret_name = secret['name']
    # print(secret_name)
    secret_description = secret['description']
    # print(secret_description)
    kms_key_id = secret['kms_key_id']
    # print(kms_key_id) 
    encryted_file = secrets_folder + secret['name']+".enc"
    # print(encryted_file)
    role_arns = secret.get('role_arns', [])
    # print(role_arns)

    # Construct the policy document
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

    # Convert the policy document to a JSON string
    policy_str = json.dumps(policy)
    # print(policy_str)

    # Read the encrypted data
    with open(encryted_file, 'rb') as enc_file:
        encrypted_data = enc_file.read()
        # print(encrypted_data)

    # Decrypt the data
    decrypt_response = kms_client.decrypt(CiphertextBlob=encrypted_data, KeyId=kms_key_id)
    print(decrypt_response)
    decrypted_data = decrypt_response['Plaintext']
    decrypted_secret = decrypted_data.decode('utf-8') 

    try:
        response = secretsmanager_client.create_secret(
            Name=secret_name,
            Description=secret_description,
            SecretString=decrypted_secret,
        )
        
        try:
            response = secretsmanager_client.put_resource_policy(
                SecretId=secret_name,
                ResourcePolicy=policy_str
            )
            print(f"Policy attached to {secret_name}")
        except Exception as e:
            print(f"Error attaching policy to {secret_name}: {e}")

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceExistsException':
            print(f"Secret {secret_name} already exists. Skipping creation.")
        else:
            raise
