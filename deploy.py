import os
import random
import string
import requests
from pathlib import Path
from azure.identity import AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.web.models import AppServicePlan
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

# Deploy settings (loaded from .env)
APP_NAME = os.getenv('APP_NAME')
RESOURCE_GROUP = os.getenv('RESOURCE_GROUP')
LOCATION = os.getenv('LOCATION')
RANDOM_SUFFIX = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
RUNTIME = "PYTHON|3.10"  # Python version for Linux

# Application settings
ALLOWED_EMAIL_DOMAIN = os.getenv('ALLOWED_EMAIL_DOMAIN')
ALLOWED_GROUP_IDS = os.getenv('ALLOWED_GROUP_IDS')

# Use Azure CLI for authentication
credential = AzureCliCredential()
subscription_id = os.getenv('AZURE_SUBSCRIPTION_ID')
tenant_id = os.getenv('AZURE_TENANT_ID')

if not subscription_id or not tenant_id:
    raise ValueError("AZURE_SUBSCRIPTION_ID and AZURE_TENANT_ID must be set in the environment.")

# Initialize resource management and web management clients
resource_client = ResourceManagementClient(credential, subscription_id)
web_client = WebSiteManagementClient(credential, subscription_id)

# Deploy the app using 'az webapp up'
def deploy_flask_app():
    print(f"Deploying the Flask app to {APP_NAME} using 'az webapp up'...")

    # The 'az webapp up' command creates and deploys the app
    # No equivalent CLI command available
    deploy_command = f"az webapp up --resource-group {RESOURCE_GROUP} --name {APP_NAME} --location {LOCATION} --plan {APP_NAME}Plan --sku F1"

    # Run the deployment command
    os.system(deploy_command)

    print(f"Flask app deployed successfully to {APP_NAME}.")

# Use Microsoft Graph API to register the Azure AD App
def register_azure_ad_app():
    print(f"Registering Azure AD App {APP_NAME}...")

    # Use Azure CLI credential to get an access token for Microsoft Graph
    token = credential.get_token("https://graph.microsoft.com/.default")

    headers = {
        'Authorization': f"Bearer {token.token}",
        'Content-Type': 'application/json'
    }

    # Register the Azure AD application
    app_data = {
        "displayName": f"FlaskAppAuth-{RANDOM_SUFFIX}",
        "signInAudience": "AzureADMyOrg",  # Single tenant (adjust if needed)
        "web": {
            "redirectUris": [f"https://{APP_NAME}.azurewebsites.net/login/authorized"]
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

    print(f"Azure AD app registered successfully with client_id: {client_id}")

    # Create a client secret
    secret_data = {
        "passwordCredential": {
            "displayName": f"ClientSecret-{RANDOM_SUFFIX}"
        }
    }

    response = requests.post(
        f"https://graph.microsoft.com/v1.0/applications/{app_info['id']}/addPassword",
        headers=headers,
        json=secret_data
    )

    if response.status_code != 200:
        raise Exception(f"Failed to create a client secret: {response.text}")

    client_secret = response.json()["secretText"]
    print(f"Client secret created: {client_secret}")

    return client_id, client_secret, tenant_id

# Set environment variables in the Web App
def set_app_settings(client_id, client_secret, tenant_id):
    print(f"Setting environment variables for {APP_NAME}...")

    secret_key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    
    # The application settings need to be wrapped in "properties"
    app_settings = {
        'properties': {
            'FLASK_ENV': 'production',
            'SECRET_KEY': secret_key,
            'SCM_DO_BUILD_DURING_DEPLOYMENT': True,
            'AZURE_CLIENT_ID': client_id,
            'AZURE_CLIENT_SECRET': client_secret,
            'AZURE_TENANT_ID': tenant_id,
            'AZURE_AUTHORITY': f"https://login.microsoftonline.com/{tenant_id}",
            'AZURE_SCOPE': 'email user.read',
            'REDIRECT_URI': f"https://{APP_NAME}.azurewebsites.net/login/authorized",
            'ALLOWED_EMAIL_DOMAIN': ALLOWED_EMAIL_DOMAIN,
            'ALLOWED_GROUP_IDS': ALLOWED_GROUP_IDS
        }
    }

    web_client.web_apps.update_application_settings(RESOURCE_GROUP, APP_NAME, app_settings)
    print(f"Environment variables set successfully for {APP_NAME}.")


# Restart the Web App to apply new environment variables
def restart_web_app():
    print(f"Restarting the web app {APP_NAME} to apply new settings...")
    web_client.web_apps.restart(RESOURCE_GROUP, APP_NAME)
    print(f"Web app {APP_NAME} restarted successfully.")


def main():

    # Package and deploy the Flask app
    deploy_flask_app()

    # Register the Azure AD App
    client_id, client_secret, tenant_id = register_azure_ad_app()

    # Set environment variables
    set_app_settings(client_id, client_secret, tenant_id)

    # Restart the web app to apply the new environment variables
    restart_web_app()

    print(f"Deployment completed successfully for {APP_NAME}!")

if __name__ == "__main__":
    main()
