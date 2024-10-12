import os
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

APP_NAME = os.getenv('APP_NAME')
RESOURCE_GROUP = os.getenv('RESOURCE_GROUP')
LOCATION = os.getenv('LOCATION')

# Deploy the app using 'az webapp up'
def deploy_flask_app():
    print(f"Deploying the Flask app to {APP_NAME} using 'az webapp up'...")

    # The 'az webapp up' command creates and deploys the app
    # No equivalent CLI command available
    deploy_command = f"az webapp up --resource-group {RESOURCE_GROUP} --name {APP_NAME} --location {LOCATION} --plan {APP_NAME}Plan --sku F1"

    # Run the deployment command
    os.system(deploy_command)

    print(f"Flask app deployed successfully to {APP_NAME}.")

if __name__ == "__main__":
    deploy_flask_app()