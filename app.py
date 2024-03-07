import boto3
import yaml

# Load the YAML file
with open('secrets.yaml', 'r') as file:
    secrets_config = yaml.safe_load(file)

# Assume 'nonprod-sql-rds-dbsecret.enc' is the encrypted secret file
# You would need to replace this part with the actual decryption logic
with open('nonprod-sql-rds-dbsecret.enc', 'r') as enc_file:
    secret_value = decrypt_function(enc_file.read())  # Replace with actual decryption

# Create a Secrets Manager client
client = boto3.client('secretsmanager')

# Create the secret in AWS Secrets Manager
response = client.create_secret(
    Name=secrets_config['name'],
    Description=secrets_config['description'],
    SecretString=secret_value
)

print(response)
