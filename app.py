import boto3
import yaml
from botocore.exceptions import ClientError

# Load the YAML file
with open('secrets.yaml', 'r') as file:
    secrets_config = yaml.safe_load(file)
print(secrets_config);


# Extract the KMS key ID for the specific secret
kms_key_id = None
for secret in secrets_config['secrets']:
    if secret['name'] == 'nonprod-sql-rds-dbsecret':
        kms_key_id = secret['kms key id']
        #print(kms_key_id);
        break

if not kms_key_id:
    raise ValueError("KMS key ID not found in secrets.yaml")

# Create a KMS client
kms_client = boto3.client('kms')

# Read the encrypted data
with open('nonprod-sql-rds-dbsecret.enc', 'rb') as enc_file:
    encrypted_data = enc_file.read()
    #print(encrypted_data);

# Decrypt the data
decrypt_response = kms_client.decrypt(CiphertextBlob=encrypted_data, KeyId=kms_key_id)
decrypted_data = decrypt_response['Plaintext']
# print(decrypted_data);

decrypted_secret = decrypted_data.decode('utf-8') 
# print(decrypted_secret);

# Create a Secrets Manager client
secretsmanager_client = boto3.client('secretsmanager')

# Iterate over each secret in the list of secrets
for secret in secrets_config['secrets']:
    secret_name = secret['name']
    secret_description = secret['description']

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
