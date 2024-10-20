## Overview

This Flask app handles authentication with Microsoft Entra and serves a static site to authenticated users.

The deploy script provisions the following Azure resources using the Azure CLI:
- Resource Group
- Storage Account and File Share
- Container Environment
- Container App
- Service Principal
- Managed certificate for a custom domain

Github Secrets are used to enable CI/CD of the static site component

### Built with
[![Python][python-img]][python-url]
[![Microsoft Azure][microsoft-azure-img]][microsoft-azure-url]
[![Flask][flask-img]][flask-url]
[![Docker][docker-img]][docker-url]
[![Decap CMS][decap-cms-img]][decap-cms-url]


## Getting started
### Prerequisites
- [Python 3](https://www.python.org/downloads/)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
- [Git](https://git-scm.com/downloads) - optional
- [Docker](https://docs.docker.com/get-started/get-docker/) - if deploying your own Docker image
- A custom domain name (eg. example.com) you can direct to your app - optional

### Installation
Use these steps to get set up for deploying the Flask app to Azure

The install script is *idempotent* and so may be re-run to rotate secrets, deploy new container images, or correct mistakes - without duplicating resources

1. Clone the repository
    ```sh
    git clone https://github.com/uppertoe/flask-azure-auth
    ```
2. Create and activate a virtual environment
    ```sh
    python3 -m venv .venv
    source .venv/bin/activate
    ```
3. Install Python dependencies to the virtual environment
    ```sh
    pip install -r requirements-dev.txt
    ```

### Deploy to Azure
1. Navigate to the deploy directory
    ```sh
    cd deploy
    ```
2. Set up the necessary environment variables
    ```sh
    mv .env.sample .env
    nano .env
    ```
3. Log in to the Azure CLI
    ```sh
    az login
    ```
4. Register the Microsoft.App and Microsoft.OperationInsights namespaces
    ```sh
    az provider register --namespace Microsoft.App
    az provider register --namespace Microsoft.OperationalInsights
    ```
5. Run the deploy script
    ```sh
    python deploy.py
    ```
6. Configure your domain name verification when prompted by the install script


## Security
The Azure deployment configures an environment that follows the [principle of least privilege](https://learn.microsoft.com/en-us/entra/identity-platform/secure-least-privileged-access).

### App design
- Flask-based Microsoft Authentication Library OAuth2 based on [the Microsoft Python reference implementation](https://github.com/Azure-Samples/ms-identity-python-webapp)
- Static site served by Flask's [send_from_directory()](https://tedboy.github.io/flask/generated/flask.send_from_directory.html)
- Proxying of Decap CMS requests to the GitHub API via the Flask server, allowing the secure use of a server-side personal-access token 

### User authentication
This Flask app uses the Microsoft Authentication Library (MSAL) to implement an OAuth 2.0 authentication process.

```msal.ConfidentialClientApplication.get_authorization_request_url``` starts the OAuth2 Authorization Code Grant.

The user is directed to the Microsoft Entra authorization page. After login, the user is directed to the redirect_uri specified in the Microsoft Entra configuration. Authorization code and state are sent back to the Flask app.

On reaching the redirect_uri, the authorization code is provided to the Flask app. ```msal.ConfidentialClientApplication.acquire_token_by_authorization_code``` implements the second half of the OAuth2 flow, and returns an access token if authentication is successful.

The Flask app then processes the access token, checking the returned claims for user access control




[python-img]: https://img.shields.io/static/v1?style=for-the-badge&message=Python&color=3776AB&logo=Python&logoColor=FFFFFF&label=
[python-url]: https://www.python.org/
[flask-img]: https://img.shields.io/static/v1?style=for-the-badge&message=Flask&color=000000&logo=Flask&logoColor=FFFFFF&label=
[flask-url]: https://flask.palletsprojects.com/
[docker-img]: https://img.shields.io/static/v1?style=for-the-badge&message=Docker&color=2496ED&logo=Docker&logoColor=FFFFFF&label=
[docker-url]: https://www.docker.com/
[decap-cms-img]: https://img.shields.io/static/v1?style=for-the-badge&message=Decap+CMS&color=FF0082&logo=Decap+CMS&logoColor=FFFFFF&label=
[decap-cms-url]: https://decapcms.org/
[microsoft-azure-img]: https://img.shields.io/static/v1?style=for-the-badge&message=Microsoft+Azure&color=00A3EE&logo=Microsoft+Azure&logoColor=FFFFFF&label=
[microsoft-azure-url]: https://azure.microsoft.com