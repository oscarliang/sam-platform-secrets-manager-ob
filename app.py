import boto3
import yaml
import pprint

# Load the YAML file
with open('secrets.yaml', 'r') as file:
    secrets_config = yaml.safe_load(file)
# print(secrets_config);


# Extract the KMS key ID for the specific secret
kms_key_id = None
for secret in secrets_config['secrets']:
    if secret['name'] == 'nonprod-sql-rds-dbsecret':
        kms_key_id = secret['kms key id']
        print(kms_key_id);
        break

if not kms_key_id:
    raise ValueError("KMS key ID not found in secrets.yaml")

# Assume 'nonprod-sql-rds-dbsecret.enc' is the encrypted secret file
# You would need to replace this part with the actual decryption logic
# with open('nonprod-sql-rds-dbsecret.enc', 'r') as enc_file:
#     secret_value = decrypt_function(enc_file.read())  # Replace with actual decryption

# Create a Secrets Manager client
# client = boto3.client('secretsmanager')

# Create the secret in AWS Secrets Manager
# response = client.create_secret(
#     Name=secrets_config['name'],
#     Description=secrets_config['description'],
#     SecretString=secret_value
# )

# print(response)
