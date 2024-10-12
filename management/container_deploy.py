import os
import subprocess
import json
import requests
import base64
from azure.identity import AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from dotenv import load_dotenv
from nacl import encoding, public

# Load environment variables from the .env file
load_dotenv()

# Load variables from .env
AZURE_APP_NAME = os.getenv('AZURE_APP_NAME')
RESOURCE_GROUP = os.getenv('RESOURCE_GROUP')
LOCATION = os.getenv('LOCATION')
DOCKER_IMAGE_TAG = os.getenv('DOCKER_IMAGE_TAG')  # Docker image tag from Docker Hub
SUBSCRIPTION_ID = os.getenv('AZURE_SUBSCRIPTION_ID')
TENANT_ID = os.getenv('AZURE_TENANT_ID')
REDIRECT_URI = os.getenv('REDIRECT_URI')
GITHUB_REPO = os.getenv('GITHUB_REPO')  # Format: "owner/repo"
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')  # GitHub token with permissions to modify secrets

# Use Azure CLI for authentication
credential = AzureCliCredential()

# Initialize resource management client
resource_client = ResourceManagementClient(credential, SUBSCRIPTION_ID)

# Function to create Azure Container App
def create_azure_container_app(client_id, client_secret):
    print(f"Creating Azure Container App {AZURE_APP_NAME} using Docker image {DOCKER_IMAGE_TAG}...")

    # Deploy the container app using the Docker image from Docker Hub
    subprocess.run([
        "az", "containerapp", "create",
        "--name", AZURE_APP_NAME,
        "--resource-group", RESOURCE_GROUP,
        "--location", LOCATION,
        "--image", DOCKER_IMAGE_TAG,
        "--environment-variables",
        f"AZURE_CLIENT_ID={client_id}",
        f"AZURE_CLIENT_SECRET={client_secret}",
        f"AZURE_TENANT_ID={TENANT_ID}",
        f"REDIRECT_URI={REDIRECT_URI}",
        "--cpu", "0.25",  # Free tier: 0.25 vCPU
        "--memory", "0.5Gi",  # Free tier: 0.5Gi memory
        "--ingress", "external",
        "--target-port", "5006",  # Use the port your Flask app runs on
        "--min-replicas", "1",
        "--max-replicas", "1"
    ], check=True)

    print(f"Azure Container App {AZURE_APP_NAME} created successfully with image {DOCKER_IMAGE_TAG}.")

# Register or retrieve the Azure AD application via Microsoft Graph API
def register_or_get_azure_ad_app():
    print(f"Checking for existing Azure AD App '{AZURE_APP_NAME}'...")

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

# Create or replace the Azure AD client secret
def create_or_replace_client_secret(app_id):
    print(f"Replacing client secrets for Azure AD App ID: {app_id}...")

    token = credential.get_token("https://graph.microsoft.com/.default")

    headers = {'Authorization': f"Bearer {token.token}", 'Content-Type': 'application/json'}

    # Retrieve existing password credentials
    password_credentials_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/passwordCredentials"
    password_response = requests.get(password_credentials_url, headers=headers)

    if password_response.status_code != 200:
        raise Exception(f"Failed to retrieve password credentials: {password_response.text}")

    password_credentials = password_response.json().get('value', [])

    # Delete existing client secrets
    for password_credential in password_credentials:
        key_id = password_credential['keyId']
        delete_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/removePassword"
        delete_data = {"keyId": key_id}
        requests.post(delete_url, headers=headers, json=delete_data)

    # Create a new client secret
    secret_data = {"passwordCredential": {"displayName": f"ClientSecret-{RANDOM_SUFFIX}"}}
    create_secret_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/addPassword"

    response = requests.post(create_secret_url, headers=headers, json=secret_data)

    if response.status_code != 200:
        raise Exception(f"Failed to create a client secret: {response.text}")

    client_secret = response.json()["secretText"]
    print("New client secret created successfully.")

    return client_secret

def main():
    try:
        # Register or retrieve the Azure AD App
        app_id, client_id = register_or_get_azure_ad_app()

        # Create or replace client secrets
        client_secret = create_or_replace_client_secret(app_id)

        # Deploy the containerized Flask app as an Azure Container App
        create_azure_container_app(client_id, client_secret)

        print(f"Azure AD app and Dockerized Flask app deployment completed successfully for {AZURE_APP_NAME}!")
    except Exception as e:
        print(f"Deployment failed: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()
