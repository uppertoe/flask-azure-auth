import os
import requests
from azure.identity import AzureCliCredential
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

APP_NAME = os.getenv('APP_NAME')
RESOURCE_GROUP = os.getenv('RESOURCE_GROUP')
TENANT_ID = os.getenv('AZURE_TENANT_ID')
APP_ID = os.getenv('AZURE_CLIENT_ID')  # This is the Azure AD App ID, not the Service Principal ID
SUBSCRIPTION_ID = os.getenv('AZURE_SUBSCRIPTION_ID')

print(f"Rotating secrets for {APP_NAME} (App ID: {APP_ID})")

# Use Azure CLI for authentication
credential = AzureCliCredential()

# Set headers for Microsoft Graph API
def get_headers():
    token = credential.get_token("https://graph.microsoft.com/.default")
    headers = {
        'Authorization': f'Bearer {token.token}',
        'Content-Type': 'application/json'
    }
    print(f"Token: {token.token}")  # Print token for debugging
    return headers

# Function to create a new client secret
def create_client_secret(app_id):
    headers = get_headers()
    print(f"Creating a new client secret for app {app_id}...")

    secret_data = {
        "passwordCredential": {
            "displayName": f"ClientSecret-{app_id}"
        }
    }

    response = requests.post(
        f"https://graph.microsoft.com/v1.0/applications/{app_id}/addPassword",
        headers=headers,
        json=secret_data
    )

    if response.status_code != 200:
        raise Exception(f"Failed to create a client secret: {response.text}")

    client_secret = response.json()["secretText"]
    print(f"New client secret created: {client_secret}")
    return client_secret

# Function to delete an old client secret
def delete_client_secret(app_id, key_id):
    headers = get_headers()
    print(f"Deleting client secret {key_id} for app {app_id}...")
    
    response = requests.delete(
        f"https://graph.microsoft.com/v1.0/applications/{app_id}/passwordCredentials/{key_id}",
        headers=headers
    )
    
    if response.status_code != 204:
        raise Exception(f"Failed to delete the client secret: {response.text}")
    
    print(f"Client secret {key_id} deleted successfully.")

# Function to set environment variables for Azure Web App
def set_azure_app_settings(client_secret):
    print(f"Updating environment variables for {APP_NAME} with new client secret...")

    os.system(f"az webapp config appsettings set --name {APP_NAME} --resource-group {RESOURCE_GROUP} "
              f"--settings AZURE_CLIENT_SECRET={client_secret}")

    print(f"Environment variables updated successfully for {APP_NAME}.")

# Main process to handle refreshing the client secret
def main():
    headers = get_headers()
    print(f"Fetching app details for {APP_ID} from Graph API...")  # Debug logging
    response = requests.get(f"https://graph.microsoft.com/v1.0/applications/{APP_ID}", headers=headers)
    print(f"Response status: {response.status_code}, Response text: {response.text}")  # Add response logging
    if response.status_code != 200:
        raise Exception(f"Failed to retrieve app details: {response.text}")

    
    app_info = response.json()
    
    # Check for existing client secrets
    existing_secrets = app_info.get('passwordCredentials', [])
    
    # If a secret exists, delete it before creating a new one
    if existing_secrets:
        for secret in existing_secrets:
            key_id = secret['keyId']
            delete_client_secret(APP_ID, key_id)

    # Create a new client secret
    new_client_secret = create_client_secret(APP_ID)

    # Update the Azure Web App's environment variables
    set_azure_app_settings(new_client_secret)

if __name__ == "__main__":
    main()
