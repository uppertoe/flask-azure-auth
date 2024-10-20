import os
import subprocess
import json
import random
import string
import time
import requests
import base64
import subprocess
import tempfile
import dns.resolver
import tldextract
import datetime
from azure.identity import AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import (
    StorageAccountCreateParameters,
    StorageAccountUpdateParameters,
    Sku,
    Kind,
    AzureFilesIdentityBasedAuthentication,
    Identity,
)
from dotenv import load_dotenv
from nacl import public

# Load environment variables from the .env file
load_dotenv(".env")

# Load variables from .env
AZURE_APP_NAME = os.getenv("AZURE_APP_NAME")
AZURE_RESOURCE_GROUP = os.getenv("AZURE_RESOURCE_GROUP")
AZURE_LOCATION = os.getenv("AZURE_LOCATION")
DOCKER_IMAGE_TAG = os.getenv("DOCKER_IMAGE_TAG")
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
REDIRECT_URI = os.getenv("REDIRECT_URI")
AZURE_STORAGE_ACCOUNT_NAME = os.getenv("AZURE_STORAGE_ACCOUNT_NAME")
AZURE_FILE_SHARE_NAME = os.getenv("AZURE_FILE_SHARE_NAME")
CUSTOM_DOMAIN = os.getenv("CUSTOM_DOMAIN")
AZURE_SCOPE = os.getenv("AZURE_SCOPE")
ALLOWED_EMAIL_DOMAIN = os.getenv("ALLOWED_EMAIL_DOMAIN")
ALLOWED_GROUP_IDS = os.getenv("ALLOWED_GROUP_IDS")
MOUNT_PATH = os.getenv("MOUNT_PATH")

# GitHub Variables
GITHUB_REPO = os.getenv("GITHUB_REPO")  # Format: "owner/repo"
GITHUB_SECRETS_TOKEN = os.getenv(
    "GITHUB_SECRETS_TOKEN"
)  # GitHub token with permissions to modify secrets
CMS_GITHUB_TOKEN = os.getenv("CMS_GITHUB_TOKEN")
CMS_ALLOWED_EMAILS = os.getenv("CMS_ALLOWED_EMAILS")

# Container App Environment variables
CONTAINER_ENV_NAME = os.getenv("CONTAINER_ENV_NAME", f"{AZURE_APP_NAME}-env")

# Other variables
GUNICORN_PORT = 8000
FLASK_SECRET_KEY = "".join(random.choices(string.ascii_letters + string.digits, k=32))
SERVE_DIRECTORY = "public"  # Switch to temp/ for zero-downtime Hugo deployment

# Use Azure CLI for authentication
credential = AzureCliCredential()

# Initialize resource management and storage clients
resource_client = ResourceManagementClient(credential, AZURE_SUBSCRIPTION_ID)
storage_client = StorageManagementClient(credential, AZURE_SUBSCRIPTION_ID)

"""Log Azure CLI commands"""
# Create or open a log file for appending
log_filename = (
    f"logs/deploy_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
)
command_summary = []


# Function to log command output, appending to the same file
def log_command_output(command_str, result=None, error=None):
    timestamp = datetime.datetime.now()
    command_summary.append(f"{timestamp}: {command_str}")

    # Append detailed logs for the command
    with open(log_filename, "a") as log_file:
        log_file.write("\n" + "=" * 80 + "\n")
        log_file.write(f"Timestamp: {timestamp}\n")
        log_file.write(f"Command: {command_str}\n")
        if result:
            log_file.write(f"Result:\n{result}\n")
        if error:
            log_file.write(f"Error:\n{error}\n")
        log_file.write("=" * 80 + "\n")


# Wrapper function for subprocess.run with **kwargs to accept other optional arguments
def run_azure_cli(command, **kwargs):
    command_str = " ".join(command)
    try:
        result = subprocess.run(command, **kwargs)
        log_command_output(command_str, result=result.stdout)
        if kwargs.get("check", False) and result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, command)
        return result
    except subprocess.CalledProcessError as e:
        log_command_output(command_str, error=e.stderr)
        raise
    except Exception as e:
        log_command_output(command_str, error=str(e))
        raise


# Function to write the summary of all commands at the top of the log file
def write_command_summary():
    # Append a summary of commands at the top of the log file
    with open(log_filename, "r+") as log_file:
        existing_content = log_file.read()  # Read existing log content
        log_file.seek(0)  # Move to the beginning of the file
        log_file.write("Summary of commands run:\n")
        for command in command_summary:
            log_file.write(f"{command}\n")
        log_file.write("\nDetailed logs:\n")
        log_file.write(
            existing_content
        )  # Write the existing detailed logs after the summary


"""Commands"""


# Function to create the resource group if it doesn't exist
def create_resource_group_if_not_exists():
    print(f"Checking if resource group {AZURE_RESOURCE_GROUP} exists...")

    try:
        resource_group = resource_client.resource_groups.get(AZURE_RESOURCE_GROUP)
        print(f"Resource group {AZURE_RESOURCE_GROUP} already exists.")
    except Exception:
        print(f"Resource group {AZURE_RESOURCE_GROUP} does not exist. Creating it...")
        resource_client.resource_groups.create_or_update(
            AZURE_RESOURCE_GROUP, {"location": AZURE_LOCATION}
        )
        print(f"Resource group {AZURE_RESOURCE_GROUP} created successfully.")


# Function to provision the Azure File Share with Service Principal Access
def provision_azure_file_share():
    print(f"Checking if storage account {AZURE_STORAGE_ACCOUNT_NAME} exists...")

    try:
        # Check if the storage account exists
        storage_account = storage_client.storage_accounts.get_properties(
            AZURE_RESOURCE_GROUP, AZURE_STORAGE_ACCOUNT_NAME
        )
        print(f"Storage account {AZURE_STORAGE_ACCOUNT_NAME} exists.")

    except Exception:
        # If the storage account doesn't exist, create it
        print(
            f"Storage account {AZURE_STORAGE_ACCOUNT_NAME} does not exist. Creating it..."
        )
        storage_async_operation = storage_client.storage_accounts.begin_create(
            AZURE_RESOURCE_GROUP,
            AZURE_STORAGE_ACCOUNT_NAME,
            StorageAccountCreateParameters(
                sku=Sku(name="Standard_LRS"),
                kind=Kind.STORAGE_V2,
                location=AZURE_LOCATION,
                identity=Identity(
                    type="SystemAssigned"
                ),  # Enable managed identity during creation
            ),
        )
        storage_async_operation.result()  # Wait for the creation to complete
        print(f"Storage account {AZURE_STORAGE_ACCOUNT_NAME} created successfully.")

    # Enable Azure AD identity-based access for the storage account
    print(
        f"Enabling identity-based access on storage account {AZURE_STORAGE_ACCOUNT_NAME}..."
    )
    storage_client.storage_accounts.update(
        AZURE_RESOURCE_GROUP,
        AZURE_STORAGE_ACCOUNT_NAME,
        StorageAccountUpdateParameters(
            azure_files_identity_based_authentication=AzureFilesIdentityBasedAuthentication(
                directory_service_options="AADKERB"  # This allows Azure AD-based access
            ),
            identity=Identity(
                type="SystemAssigned"
            ),  # Ensure managed identity is enabled
        ),
    )
    print(f"Azure AD identity-based access enabled for {AZURE_STORAGE_ACCOUNT_NAME}.")

    storage_keys = storage_client.storage_accounts.list_keys(
        AZURE_RESOURCE_GROUP, AZURE_STORAGE_ACCOUNT_NAME
    )
    storage_account_key = storage_keys.keys[0].value
    print(f"Retrieved storage account key for {AZURE_STORAGE_ACCOUNT_NAME}.")

    # Create the file share if it doesn't exist
    try:
        file_shares = storage_client.file_shares.list(
            AZURE_RESOURCE_GROUP, AZURE_STORAGE_ACCOUNT_NAME
        )
        if any(share.name == AZURE_FILE_SHARE_NAME for share in file_shares):
            print(f"File share {AZURE_FILE_SHARE_NAME} already exists.")
        else:
            print(f"Creating file share {AZURE_FILE_SHARE_NAME}...")
            storage_client.file_shares.create(
                AZURE_RESOURCE_GROUP,
                AZURE_STORAGE_ACCOUNT_NAME,
                AZURE_FILE_SHARE_NAME,
                {},
            )
            print(f"File share {AZURE_FILE_SHARE_NAME} created successfully.")
    except Exception as e:
        print(f"Failed to create or access the file share: {e}")

    return storage_account_key


# Function to mount the Azure File Share in the Azure Container App
def mount_azure_file_share_in_container(storage_account_key):
    try:
        print(
            f"Mounting Azure File Share {AZURE_FILE_SHARE_NAME} to /mnt in the container app environment..."
        )

        # Set the storage configuration in the container app environment
        run_azure_cli(
            [
                "az",
                "containerapp",
                "env",
                "storage",
                "set",
                "--name",
                CONTAINER_ENV_NAME,
                "--resource-group",
                AZURE_RESOURCE_GROUP,
                "--storage-name",
                AZURE_FILE_SHARE_NAME,  # Give the storage a name for reference
                "--azure-file-account-name",
                AZURE_STORAGE_ACCOUNT_NAME,
                "--azure-file-account-key",
                storage_account_key,
                "--azure-file-share-name",
                AZURE_FILE_SHARE_NAME,
                "--access-mode",
                "ReadWrite",
            ],
            check=True,
        )

        print(
            f"Azure File Share {AZURE_FILE_SHARE_NAME} mounted successfully in environment {CONTAINER_ENV_NAME}."
        )
    except subprocess.CalledProcessError as e:
        print(f"Failed to mount Azure File Share: {e}")
        raise


def register_resource_provider():
    # Required for container environment
    print(
        "Registering Microsoft.OperationalInsights and Microsoft.App providers if not already registered..."
    )

    run_azure_cli(
        [
            "az",
            "provider",
            "register",
            "-namespace",
            "Microsoft.OperationalInsights",
            "--wait",
        ],
        check=True,
    )

    run_azure_cli(
        ["az", "provider", "register", "-n", "Microsoft.App", "--wait"],
        check=True,
    )

    print(
        "Microsoft.OperationalInsights and Microsoft.App provider registered successfully."
    )


def create_container_environment_if_not_exists():
    print(f"Checking if Azure Container Environment {CONTAINER_ENV_NAME} exists...")

    try:
        # Check if the environment exists
        result = run_azure_cli(
            [
                "az",
                "containerapp",
                "env",
                "show",
                "--name",
                CONTAINER_ENV_NAME,
                "--resource-group",
                AZURE_RESOURCE_GROUP,
                "--output",
                "json",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        print(f"Azure Container Environment {CONTAINER_ENV_NAME} already exists.")
    except subprocess.CalledProcessError:
        print(
            f"Azure Container Environment {CONTAINER_ENV_NAME} does not exist. Creating it..."
        )

        # Create the environment if it doesn't exist
        run_azure_cli(
            [
                "az",
                "containerapp",
                "env",
                "create",
                "--name",
                CONTAINER_ENV_NAME,
                "--resource-group",
                AZURE_RESOURCE_GROUP,
                "--location",
                AZURE_LOCATION,
            ],
            check=True,
        )

        print(f"Azure Container Environment {CONTAINER_ENV_NAME} created successfully.")


def create_azure_container_app(ad_client_id, sp_client_secret):
    print(
        f"Creating Azure Container App {AZURE_APP_NAME} using Docker image {DOCKER_IMAGE_TAG}..."
    )

    # Handle empty or missing values for certain environment variables
    allowed_group_ids = ALLOWED_GROUP_IDS if ALLOWED_GROUP_IDS else None

    # Start building the YAML configuration
    yaml_config = f"""
    properties:
      managedEnvironmentId: /subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{AZURE_RESOURCE_GROUP}/providers/Microsoft.App/managedEnvironments/{CONTAINER_ENV_NAME}
      configuration:
        activeRevisionsMode: Single
        ingress:
          allowInsecure: false
          external: true
          targetPort: 8000
          traffic:
          - latestRevision: true
            weight: 100
          transport: auto
      template:
          scale:
            minReplicas: 1
            maxReplicas: 1
          volumes:
          - name: azure-files-volume
            storageType: AzureFile
            storageName: {AZURE_FILE_SHARE_NAME}
          restartPolicy: Always
          containers:
          - image: {DOCKER_IMAGE_TAG}
            name: {AZURE_APP_NAME}-container
            resources:
              cpu: 0.25
              memory: 0.5Gi
            probes:
            - type: Liveness
              httpGet:
                path: "/liveness"
                port: 8000
              initialDelaySeconds: 5
              periodSeconds: 10
            volumeMounts:
            - mountPath: "/mnt"
              volumeName: azure-files-volume
            env:
            - name: AZURE_CLIENT_ID
              value: {ad_client_id}
            - name: AZURE_CLIENT_SECRET
              value: {sp_client_secret}
            - name: AZURE_TENANT_ID
              value: {AZURE_TENANT_ID}
            - name: REDIRECT_URI
              value: {REDIRECT_URI}
            - name: AZURE_SCOPE
              value: {AZURE_SCOPE}
            - name: ALLOWED_EMAIL_DOMAIN
              value: {ALLOWED_EMAIL_DOMAIN}
            - name: SECRET_KEY
              value: {FLASK_SECRET_KEY}
            - name: MOUNT_PATH
              value: {MOUNT_PATH}
            - name: CMS_ALLOWED_EMAILS
              value: {CMS_ALLOWED_EMAILS}
            - name: CMS_GITHUB_TOKEN
              value: {CMS_GITHUB_TOKEN}
    """

    # Conditionally include ALLOWED_GROUP_IDS only if it has a value
    if allowed_group_ids:
        yaml_config += f"""
              - name: ALLOWED_GROUP_IDS
                value: {allowed_group_ids}
        """

    try:
        # Write the YAML content to a temporary file
        with tempfile.NamedTemporaryFile(
            "w", delete=False, suffix=".yaml"
        ) as temp_yaml_file:
            temp_yaml_file.write(yaml_config)
            temp_yaml_file_path = temp_yaml_file.name

        # Use the temporary file as input for the `az containerapp create` command
        result = run_azure_cli(
            [
                "az",
                "containerapp",
                "create",
                "--name",
                AZURE_APP_NAME,
                "--resource-group",
                AZURE_RESOURCE_GROUP,
                "--yaml",
                temp_yaml_file_path,
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        print(f"Azure Container App {AZURE_APP_NAME} created successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to create Azure Container App: {e}")
        raise
    finally:
        # Clean up the temporary file
        if os.path.exists(temp_yaml_file_path):
            os.remove(temp_yaml_file_path)


# Function to determine if the domain is apex or subdomain
def get_domain_validation_method(domain_name):
    if domain_name.count(".") == 1:
        return "TXT"
    else:
        return "CNAME"


# Function to retrieve the required DNS info from Azure
def get_required_dns_info(
    domain_name, container_app_name, resource_group, container_env_name
):
    if domain_name.count(".") == 1:  # Apex domain (A record)
        result = run_azure_cli(
            [
                "az",
                "containerapp",
                "env",
                "show",
                "--name",
                container_env_name,
                "--resource-group",
                resource_group,
                "--query",
                "properties.staticIp",
                "--output",
                "tsv",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    else:  # Subdomain (CNAME)
        result = run_azure_cli(
            [
                "az",
                "containerapp",
                "show",
                "--name",
                container_app_name,
                "--resource-group",
                resource_group,
                "--query",
                "properties.configuration.ingress.fqdn",
                "--output",
                "tsv",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()


# Function to get the domain verification code
def get_domain_verification_code(container_app_name, resource_group):
    result = run_azure_cli(
        [
            "az",
            "containerapp",
            "show",
            "--name",
            container_app_name,
            "--resource-group",
            resource_group,
            "--query",
            "properties.customDomainVerificationId",
            "--output",
            "tsv",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


# Helper function to check actual DNS records of the custom domain
def check_dns_record_exists(record_type, domain, expected_value):
    extracted = tldextract.extract(domain)
    try:
        if record_type == "TXT":
            url = f"asuid.{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
        elif record_type == "A":
            url = f"{extracted.domain}.{extracted.suffix}"
        elif record_type == "CNAME":
            url = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
        else:
            return False

        answers = dns.resolver.resolve(url, record_type)

        for answer in answers:
            if expected_value in str(answer).strip('"'):
                return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False
    return False


# Function to configure DNS by comparing actual DNS with Azure's required DNS records
def configure_dns(domain_name, container_app_name, resource_group, container_env_name):
    # Extract the domain components
    extracted = tldextract.extract(domain_name)
    subdomain = extracted.subdomain
    full_domain = f"{extracted.domain}.{extracted.suffix}"

    validation_method = get_domain_validation_method(domain_name)
    required_dns_value = get_required_dns_info(
        domain_name, container_app_name, resource_group, container_env_name
    )
    verification_code = get_domain_verification_code(container_app_name, resource_group)

    # Notify if DNS info couldn't be retrieved, but still proceed
    if required_dns_value is None:
        print(
            f"Could not retrieve the required DNS information for {domain_name} from Azure."
        )
        required_dns_value = "<DNS_VALUE_MISSING>"

    # If it's an apex domain (A and TXT records)
    if validation_method == "TXT":
        a_record_exists = check_dns_record_exists("A", domain_name, required_dns_value)
        txt_record_exists = check_dns_record_exists(
            "TXT", domain_name, verification_code
        )

        if a_record_exists and txt_record_exists:
            print(
                f"DNS validation already configured for domain {full_domain}. No action needed."
            )
        else:
            print("\nConfigure the following DNS records at your domain registrar:\n")
            if not a_record_exists:
                print(f"Record Type: A")
                print(f"Host: @")
                print(f"Value: {required_dns_value}\n")
            if not txt_record_exists:
                print(f"Record Type: TXT")
                print(f"Host: @ (or asuid)")
                print(f"Value: {verification_code}\n")
            input("\nPress Enter after you've configured the DNS records...")

    # If it's a subdomain (CNAME and TXT records)
    else:
        if subdomain:
            host = f"{subdomain}.{full_domain}"
        else:
            host = full_domain

        cname_record_exists = check_dns_record_exists(
            "CNAME", domain_name, required_dns_value
        )
        txt_record_exists = check_dns_record_exists(
            "TXT", domain_name, verification_code
        )

        if cname_record_exists and txt_record_exists:
            print(
                f"DNS validation already configured for subdomain {host}. No action needed."
            )
        else:
            print("\nConfigure the following DNS records at your domain registrar:\n")
            if not cname_record_exists:
                print(f"Record Type: CNAME")
                print(f"Host: {host}")
                print(f"Value: {required_dns_value}\n")
            if not txt_record_exists:
                print(f"Record Type: TXT")
                print(f"Host: asuid.{subdomain}")
                print(f"Value: {verification_code}\n")
            input("\nPress Enter after you've configured the DNS records...")


# Function to check if custom domain and certificate are already configured
def is_custom_domain_configured(container_app_name, resource_group, domain_name):
    print(
        f"Checking if custom domain '{domain_name}' is already configured for {container_app_name}..."
    )
    try:
        result = run_azure_cli(
            [
                "az",
                "containerapp",
                "hostname",
                "list",
                "--name",
                container_app_name,
                "--resource-group",
                resource_group,
                "--output",
                "json",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        # Parse the list of hostnames to see if the domain is already added
        hostnames = json.loads(result.stdout)
        for hostname in hostnames:
            if hostname["name"] == domain_name:
                print(f"Custom domain '{domain_name}' is already configured.")
                return True

        print(f"Custom domain '{domain_name}' is not configured.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error checking for custom domain: {e}")
        return False


def is_certificate_bound(container_app_name, resource_group, domain_name):
    print(
        f"Checking if a certificate is bound to domain '{domain_name}' for {container_app_name}..."
    )

    try:
        # List the hostnames and check the binding info
        result = run_azure_cli(
            [
                "az",
                "containerapp",
                "hostname",
                "list",
                "--name",
                container_app_name,
                "--resource-group",
                resource_group,
                "--output",
                "json",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        hostnames = json.loads(result.stdout)

        # Go through the hostnames to find our domain and check for certificate details
        for hostname in hostnames:
            if hostname["name"] == domain_name:
                if "sslCertThumbprint" in hostname:
                    print(
                        f"Certificate is bound to domain '{domain_name}' with thumbprint: {hostname['sslCertThumbprint']}"
                    )
                    return True
                else:
                    print(f"No certificate bound to domain '{domain_name}'.")
                    return False

        print(f"Domain '{domain_name}' not found among the configured hostnames.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error checking certificate binding: {e}")
        return False


# Function to add the custom hostname to the environment
def add_custom_hostname(
    container_app_name, resource_group, domain_name, container_env_name
):
    print(
        f"Adding custom hostname '{domain_name}' to container app '{container_app_name}' in environment '{CONTAINER_ENV_NAME}'..."
    )

    try:
        run_azure_cli(
            [
                "az",
                "containerapp",
                "hostname",
                "add",
                "--hostname",
                domain_name,
                "--resource-group",
                resource_group,
                "--name",
                container_app_name,
            ],
            check=True,
        )
        print(f"Custom hostname '{domain_name}' successfully added to container app.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to add custom hostname '{domain_name}': {e}")
        raise


# Function to check if the hostname was added
def is_custom_hostname_added(container_app_name, resource_group, domain_name):
    print(
        f"Checking if custom hostname '{domain_name}' is added to the container app '{container_app_name}'..."
    )

    try:
        result = run_azure_cli(
            [
                "az",
                "containerapp",
                "hostname",
                "list",
                "--name",
                container_app_name,
                "--resource-group",
                resource_group,
                "--output",
                "json",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        # Parse the JSON output
        hostnames = json.loads(result.stdout)

        # Check if the desired hostname exists in the list
        for hostname in hostnames:
            if hostname["name"] == domain_name:
                print(f"Hostname '{domain_name}' is found in the container app.")
                return True

        print(f"Hostname '{domain_name}' is not found in the container app.")
        return False

    except subprocess.CalledProcessError as e:
        print(f"Error checking hostname: {e}")
        return False


# Function to configure the custom domain and bind the certificate
def configure_custom_domain(
    container_app_name, resource_group, domain_name, container_env_name
):
    # Add custom hostname if not already added
    if not is_custom_hostname_added(container_app_name, resource_group, domain_name):
        add_custom_hostname(
            container_app_name, resource_group, domain_name, container_env_name
        )
    else:
        print(
            f"Custom domain '{domain_name}' already exists. Skipping domain addition."
        )

    # Check if the custom domain is already configured
    if is_custom_domain_configured(container_app_name, resource_group, domain_name):
        # Check if the certificate is bound
        if is_certificate_bound(container_app_name, resource_group, domain_name):
            print(
                f"Custom domain '{domain_name}' and certificate are already configured and bound. Skipping setup."
            )
            return
        else:
            print(
                f"Custom domain '{domain_name}' is configured, but certificate is not bound. Proceeding with certificate binding."
            )
            # Bind existing certificate (no need to recreate)
            bind_existing_certificate(
                container_app_name, resource_group, domain_name, container_env_name
            )
            return
    else:
        # Add the domain to the container app
        print(
            f"Adding custom domain '{domain_name}' to container app '{container_app_name}'..."
        )
        run_azure_cli(
            [
                "az",
                "containerapp",
                "hostname",
                "add",
                "--hostname",
                domain_name,
                "--resource-group",
                resource_group,
                "--name",
                container_app_name,
            ],
            check=True,
        )

        # Proceed with certificate creation and binding
        print(f"Proceeding with new certificate setup for domain '{domain_name}'...")

        # Get the validation method based on domain type
        validation_method = get_domain_validation_method(domain_name)

        # Set up the Azure-managed certificate
        print(f"Setting up Azure-managed certificate for domain '{domain_name}'...")
        run_azure_cli(
            [
                "az",
                "containerapp",
                "hostname",
                "bind",
                "--hostname",
                domain_name,
                "--resource-group",
                resource_group,
                "--name",
                container_app_name,
                "--environment",
                container_env_name,
                "--validation-method",
                validation_method,
            ],
            check=True,
        )

    print(f"Custom domain '{domain_name}' and certificate successfully configured.")


def get_existing_certificates(container_env_name, resource_group):
    print(
        f"Checking for existing managed certificates in environment '{container_env_name}'..."
    )

    try:
        result = run_azure_cli(
            [
                "az",
                "containerapp",
                "env",
                "certificate",
                "list",
                "--name",
                container_env_name,
                "--resource-group",
                resource_group,
                "--output",
                "json",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        certificates = json.loads(result.stdout)
        return certificates
    except subprocess.CalledProcessError as e:
        print(f"Failed to list managed certificates: {e}")
        return []


def bind_existing_certificate(
    container_app_name, resource_group, domain_name, container_env_name
):
    print(f"Binding existing certificate to domain '{domain_name}'...")

    # Fetch the list of managed certificates in the environment
    certificates = get_existing_certificates(container_env_name, resource_group)
    try:
        # Check if a successful certificate for the domain exists
        matching_cert = None
        for cert in certificates:
            if (
                cert["properties"]["subjectName"] == domain_name
                and cert["properties"]["provisioningState"] == "Succeeded"
            ):
                matching_cert = cert
                break

        if matching_cert:
            cert_name = matching_cert["name"]
            print(
                f"Found existing certificate '{cert_name}' for domain '{domain_name}'. Binding it now..."
            )

            # Bind the existing certificate to the domain
            run_azure_cli(
                [
                    "az",
                    "containerapp",
                    "hostname",
                    "bind",
                    "--hostname",
                    domain_name,
                    "--resource-group",
                    resource_group,
                    "--name",
                    container_app_name,
                    "--environment",
                    container_env_name,
                    "--certificate",
                    cert_name,
                ],
                check=True,
            )

            print(
                f"Successfully bound certificate '{cert_name}' to domain '{domain_name}'."
            )
        else:
            print(
                f"No valid existing certificate found for domain '{domain_name}'. Cannot bind certificate."
            )

    except subprocess.CalledProcessError as e:
        print(f"Failed to bind existing certificate: {e}")
        raise


# Register or retrieve the Azure AD application via Microsoft Graph API
def register_or_get_azure_ad_app():
    print(f"Checking for existing Azure AD App '{AZURE_APP_NAME}'...")

    token = credential.get_token("https://graph.microsoft.com/.default")

    headers = {
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json",
    }

    # Search for existing application by display name
    search_url = f"https://graph.microsoft.com/v1.0/applications?$filter=displayName eq '{AZURE_APP_NAME}'"
    search_response = requests.get(search_url, headers=headers)

    if search_response.status_code != 200:
        raise Exception(
            f"Failed to search for existing Azure AD apps: {search_response.text}"
        )

    search_results = search_response.json()
    if search_results.get("value"):
        # Application exists
        app_info = search_results["value"][0]
        client_id = app_info["appId"]
        app_id = app_info["id"]
        print(f"Found existing Azure AD app with client_id: {client_id}")

        # Ensure the redirect URI is up-to-date
        current_redirect_uris = app_info.get("web", {}).get("redirectUris", [])
        if REDIRECT_URI not in current_redirect_uris:
            print("Updating redirect URIs...")
            current_redirect_uris.append(REDIRECT_URI)
            update_data = {"web": {"redirectUris": current_redirect_uris}}
            update_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}"
            update_response = requests.patch(
                update_url, headers=headers, json=update_data
            )
            if update_response.status_code != 204:
                raise Exception(
                    f"Failed to update redirect URIs: {update_response.text}"
                )
            print("Redirect URIs updated successfully.")
    else:
        print(
            f"No existing Azure AD app named '{AZURE_APP_NAME}' found. Creating a new one..."
        )
        app_data = {
            "displayName": AZURE_APP_NAME,
            "signInAudience": "AzureADMyOrg",  # Single tenant
            "web": {"redirectUris": [REDIRECT_URI]},
        }

        response = requests.post(
            "https://graph.microsoft.com/v1.0/applications",
            headers=headers,
            json=app_data,
        )

        if response.status_code != 201:
            raise Exception(f"Failed to register the Azure AD app: {response.text}")

        app_info = response.json()
        client_id = app_info["appId"]
        app_id = app_info["id"]

        print(f"Azure AD app registered successfully with client_id: {client_id}")

    return app_id, client_id


def create_service_principal():
    print(f"Creating Service Principal for {AZURE_APP_NAME}...")

    # Create the service principal with Contributor role on the resource group
    result = run_azure_cli(
        [
            "az",
            "ad",
            "sp",
            "create-for-rbac",
            "--name",
            AZURE_APP_NAME,
            "--role",
            "Container Apps Contributor",  # Container management permissions
            "--scopes",
            f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{AZURE_RESOURCE_GROUP}",
            "--json-auth",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    json_creds = result.stdout
    sp_info = json.loads(json_creds)
    client_id = sp_info["clientId"]
    client_secret = sp_info["clientSecret"]
    print(f"Service Principal created with client_id: {client_id}")

    # Assign "SStorage File Data Privileged Contributor" role to the service principal for REST API access
    print(
        f"Assigning Storage File Data Privileged Contributor role to {AZURE_APP_NAME} for file share REST API access..."
    )
    run_azure_cli(
        [
            "az",
            "role",
            "assignment",
            "create",
            "--assignee",
            client_id,
            "--role",
            "Storage File Data Privileged Contributor",  # Role for REST API access
            "--scope",
            f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{AZURE_RESOURCE_GROUP}/providers/Microsoft.Storage/storageAccounts/{AZURE_STORAGE_ACCOUNT_NAME}",
        ],
        check=True,
    )

    return client_id, client_secret, json_creds


# Function to update GitHub secrets
def update_github_secret(secret_name, secret_value):
    print(f"Updating GitHub secret: {secret_name}...")

    headers = {
        "Authorization": f"token {GITHUB_SECRETS_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }

    repo_owner, repo_name = GITHUB_REPO.split("/")

    public_key_url = (
        f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/public-key"
    )
    public_key_response = requests.get(public_key_url, headers=headers)

    if public_key_response.status_code != 200:
        raise Exception(f"Failed to fetch public key: {public_key_response.text}")

    public_key_data = public_key_response.json()
    public_key_str = public_key_data["key"]
    key_id = public_key_data["key_id"]

    public_key_bytes = base64.b64decode(public_key_str)
    public_key_obj = public.PublicKey(public_key_bytes)
    sealed_box = public.SealedBox(public_key_obj)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    encrypted_value = base64.b64encode(encrypted).decode("utf-8")

    secret_url = (
        f"https://api.github.com/repos/{GITHUB_REPO}/actions/secrets/{secret_name}"
    )
    response = requests.put(
        secret_url,
        headers=headers,
        data=json.dumps({"encrypted_value": encrypted_value, "key_id": key_id}),
    )

    if response.status_code not in [201, 204]:
        raise Exception(
            f"Failed to update GitHub secret {secret_name}: {response.text}"
        )
    time.sleep(1)
    print(f"Successfully updated GitHub secret: {secret_name}")


def orchestrate_custom_domain():

    if not CUSTOM_DOMAIN:
        print("No custom domain provided. Skipping domain configuration.")
        return

    # Configure DNS first with instructions for the user
    configure_dns(
        CUSTOM_DOMAIN, AZURE_APP_NAME, AZURE_RESOURCE_GROUP, CONTAINER_ENV_NAME
    )

    # Proceed with domain and certificate setup
    configure_custom_domain(
        AZURE_APP_NAME, AZURE_RESOURCE_GROUP, CUSTOM_DOMAIN, CONTAINER_ENV_NAME
    )


# Main function to provision and deploy resources
def main():
    try:
        register_resource_provider()  # Microsoft.OperationalInsights and Microsoft.App
        create_resource_group_if_not_exists()

        storage_account_key = provision_azure_file_share()

        # Create or check the Azure Container App Environment
        create_container_environment_if_not_exists()

        app_id, ad_client_id = register_or_get_azure_ad_app()

        sp_client_id, sp_client_secret, json_creds = create_service_principal()

        # Create the Azure Container App, passing the client ID and secret
        container_app = create_azure_container_app(ad_client_id, sp_client_secret)

        mount_azure_file_share_in_container(storage_account_key)

        update_github_secret("AZURE_CREDENTIALS", json_creds)
        update_github_secret("AZURE_CONTAINER_APP_NAME", AZURE_APP_NAME)
        update_github_secret("AZURE_RESOURCE_GROUP", AZURE_RESOURCE_GROUP)
        update_github_secret("AZURE_STORAGE_ACCOUNT_NAME", AZURE_STORAGE_ACCOUNT_NAME)
        update_github_secret("AZURE_FILE_SHARE_NAME", AZURE_FILE_SHARE_NAME)

        orchestrate_custom_domain()

        write_command_summary()

        print(f"Deployment completed successfully for {AZURE_APP_NAME}!")
    except Exception as e:
        print(f"Deployment failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
