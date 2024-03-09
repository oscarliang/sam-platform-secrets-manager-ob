import boto3
import yaml
import json
from botocore.exceptions import ClientError

# Load the YAML file
with open('secrets.yaml', 'r') as file:
    secrets_config = yaml.safe_load(file)

# Create a KMS client
kms_client = boto3.client('kms')

# Create a Secrets Manager client
secretsmanager_client = boto3.client('secretsmanager')

# Iterate over each secret in the list of secrets
for secret in secrets_config['secrets']:
    secret_name = secret['name']
    secret_description = secret['description']
    kms_key_id = secret['kms_key_id'] 
    encryted_file = secret['name']+".enc"
    role_arns = secret.get('role_arns', [])

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
    print(policy_str)

    # Read the encrypted data
    with open(encryted_file, 'rb') as enc_file:
        encrypted_data = enc_file.read()

    # Decrypt the data
    decrypt_response = kms_client.decrypt(CiphertextBlob=encrypted_data, KeyId=kms_key_id)
    decrypted_data = decrypt_response['Plaintext']
    decrypted_secret = decrypted_data.decode('utf-8') 

    try:
        response = secretsmanager_client.create_secret(
            Name=secret_name,
            Description=secret_description,
            SecretString=decrypted_secret,
            # ResourcePolicy=policy_str
        )
        print(response)

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceExistsException':
            print(f"Secret {secret_name} already exists. Skipping creation.")
            response = secretsmanager_client.update_secret(
                SecretId=secret_name,
                Description=secret_description,
                SecretString=decrypted_secret
                # ResourcePolicy=policy_str
            )
            # print(response)
            # Update the resource-based policy of the secret
            try:
                response = secretsmanager_client.put_resource_policy(
                    SecretId=secret_name,
                    ResourcePolicy=policy_str
                )
                print(f"Policy attached to {secret_name}: {response}")
            except Exception as e:
                print(f"Error attaching policy to {secret_name}: {e}")

        else:
            raise
