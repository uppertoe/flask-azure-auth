import os
import subprocess
import json
import random
import string
import requests
import base64
import subprocess
import tempfile
from azure.identity import AzureCliCredential, DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import StorageAccountCreateParameters, Sku, Kind
from dotenv import load_dotenv
from nacl import public

# Load environment variables from the .env file
load_dotenv('.container-env')

# Load variables from .env
AZURE_APP_NAME = os.getenv('AZURE_APP_NAME')
AZURE_RESOURCE_GROUP = os.getenv('AZURE_RESOURCE_GROUP')
AZURE_LOCATION = os.getenv('AZURE_LOCATION')
DOCKER_IMAGE_TAG = os.getenv('DOCKER_IMAGE_TAG')
AZURE_SUBSCRIPTION_ID = os.getenv('AZURE_SUBSCRIPTION_ID')
AZURE_TENANT_ID = os.getenv('AZURE_TENANT_ID')
REDIRECT_URI = os.getenv('REDIRECT_URI')
AZURE_STORAGE_ACCOUNT_NAME = os.getenv('AZURE_STORAGE_ACCOUNT_NAME')
AZURE_FILE_SHARE_NAME = os.getenv('AZURE_FILE_SHARE_NAME')
CUSTOM_DOMAIN = os.getenv('CUSTOM_DOMAIN')
AZURE_SCOPE = os.getenv('AZURE_SCOPE')
ALLOWED_EMAIL_DOMAIN = os.getenv('ALLOWED_EMAIL_DOMAIN')
ALLOWED_GROUP_IDS = os.getenv('ALLOWED_GROUP_IDS')

# GitHub Variables
GITHUB_REPO = os.getenv('GITHUB_REPO')  # Format: "owner/repo"
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')  # GitHub token with permissions to modify secrets

# Container App Environment variables
CONTAINER_ENV_NAME = os.getenv('CONTAINER_ENV_NAME', f'{AZURE_APP_NAME}-env')

# Other variables
GUNICORN_PORT = 8000

# Use Azure CLI for authentication
credential = AzureCliCredential()

# Initialize resource management and storage clients
resource_client = ResourceManagementClient(credential, AZURE_SUBSCRIPTION_ID)
storage_client = StorageManagementClient(credential, AZURE_SUBSCRIPTION_ID)

# Function to create the resource group if it doesn't exist
def create_resource_group_if_not_exists():
    print(f"Checking if resource group {AZURE_RESOURCE_GROUP} exists...")

    try:
        resource_group = resource_client.resource_groups.get(AZURE_RESOURCE_GROUP)
        print(f"Resource group {AZURE_RESOURCE_GROUP} already exists.")
    except Exception:
        print(f"Resource group {AZURE_RESOURCE_GROUP} does not exist. Creating it...")
        resource_client.resource_groups.create_or_update(
            AZURE_RESOURCE_GROUP,
            {"location": AZURE_LOCATION}
        )
        print(f"Resource group {AZURE_RESOURCE_GROUP} created successfully.")

# Function to provision the Azure File Share
def provision_azure_file_share():
    print(f"Checking if storage account {AZURE_STORAGE_ACCOUNT_NAME} exists...")

    try:
        storage_account = storage_client.storage_accounts.get_properties(AZURE_RESOURCE_GROUP, AZURE_STORAGE_ACCOUNT_NAME)
        print(f"Storage account {AZURE_STORAGE_ACCOUNT_NAME} exists.")
    except Exception:
        print(f"Storage account {AZURE_STORAGE_ACCOUNT_NAME} does not exist. Creating it...")
        storage_async_operation = storage_client.storage_accounts.begin_create(
            AZURE_RESOURCE_GROUP,
            AZURE_STORAGE_ACCOUNT_NAME,
            StorageAccountCreateParameters(
                sku=Sku(name="Standard_LRS"),
                kind=Kind.STORAGE_V2,
                location=AZURE_LOCATION
            )
        )
        storage_async_operation.result()  # Wait for the creation to complete
        print(f"Storage account {AZURE_STORAGE_ACCOUNT_NAME} created successfully.")

    storage_keys = storage_client.storage_accounts.list_keys(AZURE_RESOURCE_GROUP, AZURE_STORAGE_ACCOUNT_NAME)
    storage_account_key = storage_keys.keys[0].value
    print(f"Retrieved storage account key for {AZURE_STORAGE_ACCOUNT_NAME}.")

    # Create the file share if it doesn't exist
    try:
        file_shares = storage_client.file_shares.list(AZURE_RESOURCE_GROUP, AZURE_STORAGE_ACCOUNT_NAME)
        if any(share.name == AZURE_FILE_SHARE_NAME for share in file_shares):
            print(f"File share {AZURE_FILE_SHARE_NAME} already exists.")
        else:
            print(f"Creating file share {AZURE_FILE_SHARE_NAME}...")
            storage_client.file_shares.create(
                AZURE_RESOURCE_GROUP,
                AZURE_STORAGE_ACCOUNT_NAME,
                AZURE_FILE_SHARE_NAME,
                {}
            )
            print(f"File share {AZURE_FILE_SHARE_NAME} created successfully.")
    except Exception as e:
        print(f"Failed to create or access the file share: {e}")
    
    return storage_account_key

# Function to mount the Azure File Share in the Azure Container App
def mount_azure_file_share_in_container(storage_account_key):
    try:
        print(f"Mounting Azure File Share {AZURE_FILE_SHARE_NAME} to /mnt/public in the container app environment...")

        # Set the storage configuration in the container app environment
        subprocess.run([
            "az", "containerapp", "env", "storage", "set",
            "--name", CONTAINER_ENV_NAME,
            "--resource-group", AZURE_RESOURCE_GROUP,
            "--storage-name", AZURE_FILE_SHARE_NAME,  # Give the storage a name for reference
            "--azure-file-account-name", AZURE_STORAGE_ACCOUNT_NAME,
            "--azure-file-account-key", storage_account_key,
            "--azure-file-share-name", AZURE_FILE_SHARE_NAME,
            "--access-mode", "ReadWrite"
        ], check=True)

        print(f"Azure File Share {AZURE_FILE_SHARE_NAME} mounted successfully in environment {CONTAINER_ENV_NAME}.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to mount Azure File Share: {e}")
        raise

def register_resource_provider():
    # Required for container environment
    print("Registering Microsoft.OperationalInsights provider if not already registered...")
    
    subprocess.run([
        "az", "provider", "register", "-n", "Microsoft.OperationalInsights", "--wait"
    ], check=True)

    print("Microsoft.OperationalInsights provider registered successfully.")

def create_container_environment_if_not_exists():
    print(f"Checking if Azure Container Environment {CONTAINER_ENV_NAME} exists...")

    try:
        # Check if the environment exists
        result = subprocess.run([
            "az", "containerapp", "env", "show",
            "--name", CONTAINER_ENV_NAME,
            "--resource-group", AZURE_RESOURCE_GROUP,
            "--output", "json"
        ], check=True, capture_output=True, text=True)

        print(f"Azure Container Environment {CONTAINER_ENV_NAME} already exists.")
    except subprocess.CalledProcessError:
        print(f"Azure Container Environment {CONTAINER_ENV_NAME} does not exist. Creating it...")

        # Create the environment if it doesn't exist
        subprocess.run([
            "az", "containerapp", "env", "create",
            "--name", CONTAINER_ENV_NAME,
            "--resource-group", AZURE_RESOURCE_GROUP,
            "--location", AZURE_LOCATION
        ], check=True)

        print(f"Azure Container Environment {CONTAINER_ENV_NAME} created successfully.")

def create_azure_container_app(client_id, client_secret):
    print(f"Creating Azure Container App {AZURE_APP_NAME} using Docker image {DOCKER_IMAGE_TAG}...")

    # Handle empty or missing values for certain environment variables
    allowed_group_ids = ALLOWED_GROUP_IDS if ALLOWED_GROUP_IDS else None

    # Start building the YAML configuration
    yaml_config = f'''
    properties:
      managedEnvironmentId: /subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{AZURE_RESOURCE_GROUP}/providers/Microsoft.App/managedEnvironments/{CONTAINER_ENV_NAME}
      configuration: {{}}
      template:
        containers:
        - image: {DOCKER_IMAGE_TAG}
          name: {AZURE_APP_NAME}-container
          env:
            - name: AZURE_CLIENT_ID
              value: {client_id}
            - name: AZURE_CLIENT_SECRET
              value: {client_secret}
            - name: AZURE_TENANT_ID
              value: {AZURE_TENANT_ID}
            - name: REDIRECT_URI
              value: {REDIRECT_URI}
            - name: AZURE_SCOPE
              value: {AZURE_SCOPE}
            - name: ALLOWED_EMAIL_DOMAIN
              value: {ALLOWED_EMAIL_DOMAIN}
    '''

    # Conditionally include ALLOWED_GROUP_IDS only if it has a value
    if allowed_group_ids:
        yaml_config += f'''
            - name: ALLOWED_GROUP_IDS
              value: {allowed_group_ids}
        '''

    # Add resources and volumes configuration
    yaml_config += f'''
          resources:
            cpu: 0.25
            memory: 0.5Gi
          volumeMounts:
            - volumeName: azure-files-volume
              mountPath: /mnt/public
        volumes:
        - name: azure-files-volume
          storageType: AzureFile
          storageName: {AZURE_FILE_SHARE_NAME}
    '''

    try:
        # Write the YAML content to a temporary file
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as temp_yaml_file:
            temp_yaml_file.write(yaml_config)
            temp_yaml_file_path = temp_yaml_file.name
        
        # Use the temporary file as input for the `az containerapp create` command
        subprocess.run([
            "az", "containerapp", "create",
            "--name", AZURE_APP_NAME,
            "--resource-group", AZURE_RESOURCE_GROUP,
            "--yaml", temp_yaml_file_path
        ], check=True)

        print(f"Azure Container App {AZURE_APP_NAME} created successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to create Azure Container App: {e}")
        raise
    finally:
        # Clean up the temporary file
        if os.path.exists(temp_yaml_file_path):
            os.remove(temp_yaml_file_path)

# Function to enable ingress
def enable_ingress(container_app_name, resource_group, target_port=8000):
    print(f"Enabling ingress for container app {container_app_name} on port {target_port}...")
    subprocess.run([
        "az", "containerapp", "ingress", "enable",
        "--name", container_app_name,
        "--resource-group", resource_group,
        "--type", "external",
        "--target-port", str(target_port),
        "--transport", "auto"
    ], check=True)
    print(f"Ingress enabled on port {target_port}.")

# Function to determine if the domain is apex or subdomain
def get_domain_validation_method(domain_name):
    if domain_name.count('.') == 1:
        # Apex domain (example.com)
        validation_method = "TXT"
    else:
        # Subdomain (e.g., dev.example.com)
        validation_method = "CNAME"
    
    return validation_method

# Function to retrieve the IP or FQDN based on domain type
def get_dns_info(domain_name, container_app_name, resource_group, container_env_name):
    if domain_name.count('.') == 1:  # Apex domain
        # Get the static IP of the container app environment
        print("Retrieving static IP for apex domain DNS configuration...")
        result = subprocess.run([
            "az", "containerapp", "env", "show",
            "--name", container_env_name,
            "--resource-group", resource_group,
            "--query", "properties.staticIp",
            "--output", "tsv"
        ], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    else:
        # Get the FQDN of the container app for subdomain
        print("Retrieving FQDN for subdomain DNS configuration...")
        result = subprocess.run([
            "az", "containerapp", "show",
            "--name", container_app_name,
            "--resource-group", resource_group,
            "--query", "properties.configuration.ingress.fqdn",
            "--output", "tsv"
        ], capture_output=True, text=True, check=True)
        return result.stdout.strip()

# Function to get the domain verification code
def get_domain_verification_code(container_app_name, resource_group):
    print(f"Retrieving domain verification code for container app {container_app_name}...")
    result = subprocess.run([
        "az", "containerapp", "show",
        "--name", container_app_name,
        "--resource-group", resource_group,
        "--query", "properties.customDomainVerificationId",
        "--output", "tsv"
    ], capture_output=True, text=True, check=True)
    
    return result.stdout.strip()

# Function to configure DNS and display user-friendly instructions
def configure_dns(domain_name, container_app_name, resource_group, container_env_name):
    validation_method = get_domain_validation_method(domain_name)
    dns_value = get_dns_info(domain_name, container_app_name, resource_group, container_env_name)
    verification_code = get_domain_verification_code(container_app_name, resource_group)

    print("\nConfigure the following DNS records at your domain registrar:\n")
    
    if validation_method == "TXT":  # Apex domain
        print(f"Record Type: A")
        print(f"Host: @")
        print(f"Value: {dns_value}\n")
        print(f"Record Type: TXT")
        print(f"Host: asuid")
        print(f"Value: {verification_code}\n")
    else:  # Subdomain
        subdomain = domain_name.split('.')[0]
        print(f"Record Type: CNAME")
        print(f"Host: {subdomain}")
        print(f"Value: {dns_value}\n")
        print(f"Record Type: TXT")
        print(f"Host: asuid.{subdomain}")
        print(f"Value: {verification_code}\n")

# Function to check if custom domain and certificate are already configured
def is_custom_domain_configured(container_app_name, resource_group, domain_name):
    print(f"Checking if custom domain {domain_name} is already configured for {container_app_name}...")
    result = subprocess.run([
        "az", "containerapp", "hostname", "list",
        "--name", container_app_name,
        "--resource-group", resource_group,
        "--query", "[?name=='{}']".format(domain_name),
        "--output", "json"
    ], capture_output=True, text=True, check=True)
    
    domains = result.stdout.strip()
    return bool(domains)  # Return True if domain is found

# Function to check if the certificate is bound
def is_certificate_bound(container_app_name, resource_group, domain_name):
    print(f"Checking if certificate is bound to {domain_name} for {container_app_name}...")
    result = subprocess.run([
        "az", "containerapp", "hostname", "show",
        "--name", container_app_name,
        "--resource-group", resource_group,
        "--hostname", domain_name,
        "--query", "sslCertThumbprint",
        "--output", "tsv"
    ], capture_output=True, text=True)
    
    return bool(result.stdout.strip())

# Function to add the custom hostname to the environment
def add_custom_hostname(container_app_name, resource_group, domain_name, container_env_name):
    print(f"Adding custom hostname '{domain_name}' to container app '{container_app_name}' in environment '{CONTAINER_ENV_NAME}'...")
    
    try:
        subprocess.run([
            "az", "containerapp", "hostname", "add",
            "--hostname", domain_name,
            "--resource-group", resource_group,
            "--name", container_app_name,
        ], check=True)
        print(f"Custom hostname '{domain_name}' successfully added to container app.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to add custom hostname '{domain_name}': {e}")
        raise

# Function to check if the hostname was added
def is_custom_hostname_added(container_app_name, resource_group, domain_name):
    print(f"Checking if custom hostname '{domain_name}' is added to the container app '{container_app_name}'...")

    try:
        result = subprocess.run([
            "az", "containerapp", "hostname", "list",
            "--name", container_app_name,
            "--resource-group", resource_group,
            "--output", "json"
        ], capture_output=True, text=True, check=True)

        # Parse the JSON output
        hostnames = json.loads(result.stdout)

        # Check if the desired hostname exists in the list
        for hostname in hostnames:
            if hostname['name'] == domain_name:
                print(f"Hostname '{domain_name}' is found in the container app.")
                return True

        print(f"Hostname '{domain_name}' is not found in the container app.")
        return False

    except subprocess.CalledProcessError as e:
        print(f"Error checking hostname: {e}")
        return False

# Function to configure the custom domain and bind the certificate
def configure_custom_domain(container_app_name, resource_group, domain_name, container_env_name):
    # Add custom hostname if not already added
    if not is_custom_hostname_added(container_app_name, resource_group, domain_name):
        add_custom_hostname(container_app_name, resource_group, domain_name, container_env_name)

    # Check if custom domain and certificate are already configured
    if is_custom_domain_configured(container_app_name, resource_group, domain_name):
        if is_certificate_bound(container_app_name, resource_group, domain_name):
            print(f"Custom domain {domain_name} and certificate are already configured. Skipping setup.")
            return
        else:
            print(f"Custom domain {domain_name} is configured, but certificate is not bound. Proceeding with certificate setup.")
    else:
        # Add the domain to the container app
        print(f"Adding custom domain {domain_name} to container app {container_app_name}...")
        subprocess.run([
            "az", "containerapp", "hostname", "add",
            "--hostname", domain_name,
            "--resource-group", resource_group,
            "--name", container_app_name
        ], check=True)
    
    # Get the validation method based on domain type
    validation_method = get_domain_validation_method(domain_name)

    # Set up the Azure-managed certificate
    print(f"Setting up Azure-managed certificate for domain {domain_name}...")
    subprocess.run([
        "az", "containerapp", "hostname", "bind",
        "--hostname", domain_name,
        "--resource-group", resource_group,
        "--name", container_app_name,
        "--environment", container_env_name,
        "--validation-method", validation_method
    ], check=True)

    print(f"Custom domain {domain_name} and certificate successfully configured.")


# Register or retrieve the Azure AD application via Microsoft Graph API
def register_or_get_azure_ad_app():
    print(f"Checking for existing Azure AD App '{AZURE_APP_NAME}'...")

    token = credential.get_token("https://graph.microsoft.com/.default")

    headers = {
        'Authorization': f"Bearer {token.token}",
        'Content-Type': 'application/json'
    }

    # Search for existing application by display name
    search_url = f"https://graph.microsoft.com/v1.0/applications?$filter=displayName eq '{AZURE_APP_NAME}'"
    search_response = requests.get(search_url, headers=headers)

    if search_response.status_code != 200:
        raise Exception(f"Failed to search for existing Azure AD apps: {search_response.text}")

    search_results = search_response.json()
    if search_results.get('value'):
        # Application exists
        app_info = search_results['value'][0]
        client_id = app_info["appId"]
        app_id = app_info["id"]
        print(f"Found existing Azure AD app with client_id: {client_id}")

        # Ensure the redirect URI is up-to-date
        current_redirect_uris = app_info.get('web', {}).get('redirectUris', [])
        if REDIRECT_URI not in current_redirect_uris:
            print("Updating redirect URIs...")
            current_redirect_uris.append(REDIRECT_URI)
            update_data = {
                "web": {
                    "redirectUris": current_redirect_uris
                }
            }
            update_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}"
            update_response = requests.patch(update_url, headers=headers, json=update_data)
            if update_response.status_code != 204:
                raise Exception(f"Failed to update redirect URIs: {update_response.text}")
            print("Redirect URIs updated successfully.")
    else:
        print(f"No existing Azure AD app named '{AZURE_APP_NAME}' found. Creating a new one...")
        app_data = {
            "displayName": AZURE_APP_NAME,
            "signInAudience": "AzureADMyOrg",  # Single tenant
            "web": {
                "redirectUris": [REDIRECT_URI]
            }
        }

        response = requests.post(
            "https://graph.microsoft.com/v1.0/applications",
            headers=headers,
            json=app_data
        )

        if response.status_code != 201:
            raise Exception(f"Failed to register the Azure AD app: {response.text}")

        app_info = response.json()
        client_id = app_info["appId"]
        app_id = app_info["id"]

        print(f"Azure AD app registered successfully with client_id: {client_id}")

    return app_id, client_id

# Create or replace the Azure AD client secret
def create_or_replace_client_secret(app_id):
    print(f"Replacing client secrets for Azure AD App ID: {app_id}...")

    token = credential.get_token("https://graph.microsoft.com/.default")

    headers = {'Authorization': f"Bearer {token.token}", 'Content-Type': 'application/json'}

    password_credentials_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/passwordCredentials"
    password_response = requests.get(password_credentials_url, headers=headers)

    if password_response.status_code != 200:
        raise Exception(f"Failed to retrieve password credentials: {password_response.text}")

    password_credentials = password_response.json().get('value', [])

    for password_credential in password_credentials:
        key_id = password_credential['keyId']
        delete_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/removePassword"
        delete_data = {"keyId": key_id}
        requests.post(delete_url, headers=headers, json=delete_data)

    secret_data = {"passwordCredential": {"displayName": f"ClientSecret-{random.choice(string.ascii_lowercase)}"}}
    create_secret_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/addPassword"

    response = requests.post(create_secret_url, headers=headers, json=secret_data)

    if response.status_code != 200:
        raise Exception(f"Failed to create a client secret: {response.text}")

    client_secret = response.json()["secretText"]
    print("New client secret created successfully.")

    return client_secret

# Function to update GitHub secrets
def update_github_secret(secret_name, secret_value):
    print(f"Updating GitHub secret: {secret_name}...")

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    repo_owner, repo_name = GITHUB_REPO.split("/")

    public_key_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/public-key"
    public_key_response = requests.get(public_key_url, headers=headers)

    if public_key_response.status_code != 200:
        raise Exception(f"Failed to fetch public key: {public_key_response.text}")

    public_key_data = public_key_response.json()
    public_key_str = public_key_data['key']
    key_id = public_key_data['key_id']

    public_key_bytes = base64.b64decode(public_key_str)
    public_key_obj = public.PublicKey(public_key_bytes)
    sealed_box = public.SealedBox(public_key_obj)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    encrypted_value = base64.b64encode(encrypted).decode("utf-8")

    secret_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/{secret_name}"
    response = requests.put(secret_url, headers=headers, data=json.dumps({
        "encrypted_value": encrypted_value,
        "key_id": key_id
    }))

    if response.status_code not in [201, 204]:
        raise Exception(f"Failed to update GitHub secret {secret_name}: {response.text}")
    print(f"Successfully updated GitHub secret: {secret_name}")

def orchestrate_custom_domain():
    if not CUSTOM_DOMAIN:
        print("No custom domain provided. Skipping domain configuration.")
        return
    
    # Enable ingress for the container app
    enable_ingress(AZURE_APP_NAME, AZURE_RESOURCE_GROUP, GUNICORN_PORT)

    # Configure DNS first with instructions for the user
    configure_dns(CUSTOM_DOMAIN, AZURE_APP_NAME, AZURE_RESOURCE_GROUP, CONTAINER_ENV_NAME)

    # Wait for the user to add the DNS records
    input("\nPress Enter after you've configured the DNS records...")

    # Proceed with domain and certificate setup
    configure_custom_domain(AZURE_APP_NAME, AZURE_RESOURCE_GROUP, CUSTOM_DOMAIN, CONTAINER_ENV_NAME)

# Main function to provision and deploy resources
def main():
    try:
        create_resource_group_if_not_exists()

        storage_account_key = provision_azure_file_share()
        mount_azure_file_share_in_container(storage_account_key)

        # Create or check the Azure Container App Environment
        register_resource_provider()
        create_container_environment_if_not_exists()

        app_id, client_id = register_or_get_azure_ad_app()

        client_secret = create_or_replace_client_secret(app_id)

        # Create the Azure Container App, passing the client ID and secret
        create_azure_container_app(client_id, client_secret)

        update_github_secret("AZURE_STORAGE_ACCOUNT_NAME", AZURE_STORAGE_ACCOUNT_NAME)
        update_github_secret("AZURE_STORAGE_ACCOUNT_KEY", storage_account_key)
        update_github_secret("AZURE_FILE_SHARE_NAME", AZURE_FILE_SHARE_NAME)

        orchestrate_custom_domain()

        print(f"Deployment completed successfully for {AZURE_APP_NAME}!")
    except Exception as e:
        print(f"Deployment failed: {e}")
        exit(1)

if __name__ == "__main__":
    main()
