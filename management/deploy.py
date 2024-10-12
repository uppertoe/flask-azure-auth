import os
import random
import string
import subprocess
import json
import requests
import base64
import xml.etree.ElementTree as ET
from azure.identity import AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.web import WebSiteManagementClient
from dotenv import load_dotenv
from nacl import encoding, public

# Load environment variables from the .env file
FLASK_DIRECTORY = "../flask-app/"
load_dotenv(os.path.join(FLASK_DIRECTORY, ".env"))  # Ensure the .env file path is correct

# Deploy settings (loaded from .env)
AZURE_APP_NAME = os.getenv('AZURE_APP_NAME')
RESOURCE_GROUP = os.getenv('RESOURCE_GROUP')
LOCATION = os.getenv('LOCATION')
SUBSCRIPTION_ID = os.getenv('AZURE_SUBSCRIPTION_ID')
AZURE_TENANT_ID = os.getenv('AZURE_TENANT_ID')
REDIRECT_URI = os.getenv('REDIRECT_URI')

GITHUB_REPO = os.getenv('GITHUB_REPO')  # Format: "owner/repo"
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')  # Fine-grained personal access token with permissions to modify secrets

# Application settings
ALLOWED_EMAIL_DOMAIN = os.getenv('ALLOWED_EMAIL_DOMAIN')
ALLOWED_GROUP_IDS = os.getenv('ALLOWED_GROUP_IDS')
AZURE_SCOPE = os.getenv('AZURE_SCOPE')

# Other variables
RANDOM_SUFFIX = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

# Use Azure CLI for authentication
credential = AzureCliCredential()

# Initialize resource management and web management clients
resource_client = ResourceManagementClient(credential, SUBSCRIPTION_ID)
web_client = WebSiteManagementClient(credential, SUBSCRIPTION_ID)

# Deploy the Flask app using 'az webapp up'
def deploy_flask_app():
    print(f"Deploying the Flask app to {AZURE_APP_NAME} using 'az webapp up'...")

    deploy_command = [
        "az", "webapp", "up",
        "--resource-group", RESOURCE_GROUP,
        "--name", AZURE_APP_NAME,
        "--location", LOCATION,
        "--plan", f"{AZURE_APP_NAME}Plan",
        "--sku", "F1",
        "--runtime", "PYTHON|3.9"  # Specify your Python runtime version
    ]

    try:
        # Change to Flask directory
        os.chdir(FLASK_DIRECTORY)
        print(f"Changed working directory to {FLASK_DIRECTORY}")

        # Execute the deployment command
        subprocess.run(deploy_command, check=True)
        print(f"Flask app deployed successfully to {AZURE_APP_NAME}.")
    except subprocess.CalledProcessError as e:
        print(f"Deployment failed: {e}")
        raise
    except Exception as e:
        print(f"An error occurred: {e}")
        raise

# Register or retrieve the Azure AD application via Microsoft Graph API
def register_or_get_azure_ad_app():
    print(f"Checking for existing Azure AD App '{AZURE_APP_NAME}'...")

    global credential
    # Use Azure CLI credential to get an access token for Microsoft Graph
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
        client_id = app_info["appId"]  # Application (client) ID
        app_id = app_info["id"]        # Object ID
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
        # Application does not exist; create a new one
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

def create_or_replace_client_secret(app_id):
    print(f"Replacing client secrets for Azure AD App ID: {app_id}...")

    global credential
    # Use Azure CLI credential to get an access token for Microsoft Graph
    token = credential.get_token("https://graph.microsoft.com/.default")

    headers = {
        'Authorization': f"Bearer {token.token}",
        'Content-Type': 'application/json'
    }

    # Retrieve existing password credentials
    password_credentials_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/passwordCredentials"
    password_response = requests.get(password_credentials_url, headers=headers)

    if password_response.status_code != 200:
        raise Exception(f"Failed to retrieve password credentials: {password_response.text}")

    password_credentials = password_response.json().get('value', [])

    # Delete existing client secrets
    for password_credential in password_credentials:
        key_id = password_credential['keyId']
        print(f"Deleting old client secret with keyId: {key_id}")
        delete_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/removePassword"
        delete_data = {
            "keyId": key_id
        }
        delete_response = requests.post(delete_url, headers=headers, json=delete_data)
        if delete_response.status_code != 204:
            raise Exception(f"Failed to delete client secret {key_id}: {delete_response.text}")
        print(f"Deleted client secret {key_id} successfully.")

    # Create a new client secret
    secret_data = {
        "passwordCredential": {
            "displayName": f"ClientSecret-{RANDOM_SUFFIX}"
        }
    }

    create_secret_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/addPassword"

    response = requests.post(
        create_secret_url,
        headers=headers,
        json=secret_data
    )

    if response.status_code != 200:
        raise Exception(f"Failed to create a client secret: {response.text}")

    client_secret = response.json()["secretText"]
    print("New client secret created successfully.")

    return client_secret

# Set environment variables in the Web App
def set_app_settings(client_id, client_secret, tenant_id):
    print(f"Setting environment variables for {AZURE_APP_NAME}...")

    secret_key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

    app_settings = {
        'properties': {
            'FLASK_ENV': 'production',
            'SECRET_KEY': secret_key,
            'SCM_DO_BUILD_DURING_DEPLOYMENT': 'true',
            'AZURE_CLIENT_ID': client_id,
            'AZURE_CLIENT_SECRET': client_secret,
            'AZURE_TENANT_ID': tenant_id,
            'AZURE_SCOPE': AZURE_SCOPE,
            'REDIRECT_URI': REDIRECT_URI,
            'ALLOWED_EMAIL_DOMAIN': ALLOWED_EMAIL_DOMAIN,
            'ALLOWED_GROUP_IDS': ALLOWED_GROUP_IDS
        }
    }

    try:
        web_client.web_apps.update_application_settings(RESOURCE_GROUP, AZURE_APP_NAME, app_settings)
        print(f"Environment variables set successfully for {AZURE_APP_NAME}.")
    except Exception as e:
        print(f"Failed to set environment variables: {e}")
        raise

# Restart the Web App to apply the settings
def restart_web_app():
    print(f"Restarting the web app {AZURE_APP_NAME} to apply new settings...")
    try:
        web_client.web_apps.restart(RESOURCE_GROUP, AZURE_APP_NAME)
        print(f"Web app {AZURE_APP_NAME} restarted successfully.")
    except Exception as e:
        print(f"Failed to restart the web app: {e}")
        raise

# Fetch the Publish Profile and update GitHub secrets
def fetch_and_update_publish_profile():
    print(f"Fetching Publish Profile for {AZURE_APP_NAME}...")

    publish_profile_command = [
        "az", "webapp", "deployment", "list-publishing-profiles",
        "--name", AZURE_APP_NAME,
        "--resource-group", RESOURCE_GROUP,
        "--xml"
    ]

    try:
        result = subprocess.run(publish_profile_command, capture_output=True, text=True, check=True)
        publish_profile_xml = result.stdout
        if not publish_profile_xml.strip():
            raise Exception("Publish profile XML is empty.")
        print("Publish profile fetched successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to retrieve publish profile: {e.stderr}")
        raise
    except Exception as e:
        print(f"An error occurred while fetching publish profile: {e}")
        raise

    # Parse the XML to extract required variables
    try:
        root = ET.fromstring(publish_profile_xml)
        zip_deploy_profile = None
        for profile in root.findall('publishProfile'):
            if profile.get('publishMethod') == 'ZipDeploy':
                zip_deploy_profile = profile
                break

        if zip_deploy_profile is None:
            raise Exception("ZipDeploy publishProfile not found.")

        zip_username = zip_deploy_profile.get('userName')
        zip_password = zip_deploy_profile.get('userPWD')

        if not zip_username or not zip_password:
            raise Exception("Username or Password not found in ZipDeploy publishProfile.")

        print("Extracted ZipDeploy credentials successfully.")

    except ET.ParseError as e:
        print(f"Failed to parse publish profile XML: {e}")
        raise
    except Exception as e:
        print(f"Error extracting ZipDeploy credentials: {e}")
        raise

    # Update GitHub secrets with the extracted variables
    try:
        update_github_secret("AZURE_APP_NAME", AZURE_APP_NAME)
        update_github_secret("AZURE_KUDU_USERNAME", zip_username)
        update_github_secret("AZURE_KUDU_PASSWORD", zip_password)
        print("GitHub secrets AZURE_APP_NAME, AZURE_KUDU_USERNAME, and AZURE_KUDU_PASSWORD updated successfully.")
    except Exception as e:
        print(f"Failed to update GitHub secrets: {e}")
        raise

    return zip_username, zip_password

# Update GitHub secrets for the repo using the GitHub API
def update_github_secret(secret_name, secret_value):
    print(f"Updating GitHub secret: {secret_name}...")

    # Ensure secret_value is a string
    if isinstance(secret_value, dict):
        secret_value = json.dumps(secret_value)
    else:
        secret_value = str(secret_value)

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    repo_owner, repo_name = GITHUB_REPO.split("/")

    # Fetch the public key for the repository
    public_key_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/public-key"
    public_key_response = requests.get(public_key_url, headers=headers)

    if public_key_response.status_code != 200:
        raise Exception(f"Failed to fetch public key: {public_key_response.text}")

    public_key_data = public_key_response.json()
    public_key_str = public_key_data['key']
    key_id = public_key_data['key_id']

    # Decode the public key from Base64
    public_key_bytes = base64.b64decode(public_key_str)

    # Initialize a PublicKey object with decoded bytes
    public_key_obj = public.PublicKey(public_key_bytes)

    # Encrypt the secret using the public key
    sealed_box = public.SealedBox(public_key_obj)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    encrypted_value = base64.b64encode(encrypted).decode("utf-8")

    # Prepare the payload
    payload = {
        "encrypted_value": encrypted_value,
        "key_id": key_id
    }

    # Update the secret in GitHub
    secret_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/{secret_name}"
    response = requests.put(secret_url, headers=headers, data=json.dumps(payload))

    if response.status_code in [201, 204]:
        print(f"Successfully updated GitHub secret: {secret_name}")
    else:
        print(f"Failed to update GitHub secret {secret_name}: {response.text}")
        raise Exception(f"Failed to update GitHub secret {secret_name}")

def main():
    try:
        # Deploy the Flask app
        deploy_flask_app()

        # Register or retrieve the Azure AD App
        app_id, client_id = register_or_get_azure_ad_app()

        # Create or replace client secrets
        client_secret = create_or_replace_client_secret(app_id)

        # Set the environment variables for the web app
        set_app_settings(client_id, client_secret, AZURE_TENANT_ID)

        # Restart the web app to apply the new environment variables
        restart_web_app()

        # Fetch the Publish Profile and update GitHub secrets
        zip_username, zip_password = fetch_and_update_publish_profile()

        print(f"Deployment completed successfully for {AZURE_APP_NAME}!")
    except Exception as e:
        print(f"Deployment failed: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()
