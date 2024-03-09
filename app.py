import boto3
import yaml
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
            SecretString=decrypted_secret
        )
        print(response)

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceExistsException':
            print(f"Secret {secret_name} already exists. Skipping creation.")
            # response = secretsmanager_client.update_secret(...)
        else:
            raise
