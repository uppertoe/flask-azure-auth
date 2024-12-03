import os
import sys
import logging
import requests
import json
import string
import secrets
import time
import uuid
import random
import msal
from flask import (
    Flask,
    redirect,
    url_for,
    request,
    session,
    abort,
    send_from_directory,
    render_template,
    jsonify,
    render_template_string,
    Response,
    make_response,
)
from flask_session import Session
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, validate_csrf, generate_csrf
from urllib.parse import urlparse, urljoin, unquote
from dotenv import load_dotenv
from datetime import timedelta
from werkzeug.exceptions import NotFound
from apscheduler.schedulers.background import BackgroundScheduler
from utils import GitHubSecretUpdater

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

"""
Initialise Flask
"""
# Load .env for local dev
load_dotenv(".env")

# Initialize the Flask app
app = Flask(__name__)

app.logger.setLevel(logging.INFO)

# Initialize CSRF Protection
csrf = CSRFProtect(app)

"""
App Variables
"""

# Set app variables
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")
app.config["DEBUG"] = os.getenv("DEBUG", False)  # Defaults to False if not set
app.config["SESSION_COOKIE_SECURE"] = not app.debug  # Secure for production

if not app.debug:
    app.config["SESSION_COOKIE_HTTPONLY"] = (
        True  # Helps mitigate XSS attacks by making cookies inaccessible to JavaScript
    )
    app.config["SESSION_COOKIE_SAMESITE"] = (
        "Lax"  # Prevents CSRF attacks during third-party contexts
    )

# Load configurations from environment variables
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_SCOPE = os.getenv("AZURE_SCOPE", "").split()
REDIRECT_URI = os.getenv("REDIRECT_URI")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
ALLOWED_EMAIL_DOMAIN = os.getenv("ALLOWED_EMAIL_DOMAIN").split(",")
ALLOWED_GROUP_IDS = os.getenv("ALLOWED_GROUP_IDS", "").split(",")  # Optional
CMS_ALLOWED_EMAILS = os.getenv("CMS_ALLOWED_EMAILS", "").split(
    ","
)  # Users allowed access to CMS
CMS_GITHUB_TOKEN = os.getenv("CMS_GITHUB_TOKEN")  # Requires repo read/write permissions
GITHUB_SECRETS_TOKEN = os.getenv("GITHUB_SECRETS_TOKEN")  # Requires secrets permisions
GITHUB_REPO = os.getenv("GITHUB_REPO")  # username/repo
AZURE_AUTHORITY = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
MOUNT_PATH = (
    "" if app.debug else os.getenv("MOUNT_PATH", "/mnt")
)  # Path to mounted container volume
SESSION_PATH = f"{MOUNT_PATH}/flask_sessions"  # Ephemeral unless at mounted volume
SESSION_LIFETIME_DAYS = int(os.getenv("SESSION_LIFETIME_DAYS", 7))
LANDING_PAGE_MESSAGE = os.getenv(
    "LANDING_PAGE_MESSAGE", "Welcome to the Flask Authentication App"
)


"""
Initialise Session
"""
# Flask-Session to implement server-side sessions
# Entra access tokens are larger than permissible by client-side cookies
# Keeping these server-side simplifies handling of sensitive tokens
app.config["SESSION_TYPE"] = "filesystem"  # Filesystem
app.config["SESSION_FILE_DIR"] = SESSION_PATH  # Directory for session files
app.config["SESSION_PERMANENT"] = True  # Permanent session
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    days=SESSION_LIFETIME_DAYS
)  # Session lasts 7 days

# Client cookie contains session_id to retrieve server-side session
SESSION_COOKIE_NAME = app.config.get("SESSION_COOKIE_NAME", "session")

Session(app)

"""
Helper Functions
"""


def check_email_domain(user_email):
    # Check whether the email domain is in the allowed list
    for domain in ALLOWED_EMAIL_DOMAIN:
        if user_email.ends_with(domain):
            return True
    return False


def is_authenticated():
    # If there is no token cache in the session, not authenticated
    token_cache = load_cache()
    if not token_cache:
        return False

    # Get the signed-in accounts
    msal_app = build_msal_app()  # Calls load_cache
    accounts = msal_app.get_accounts()

    if accounts:
        token_response = msal_app.acquire_token_silent(
            scopes=AZURE_SCOPE,
            account=accounts[0],  # Use the first account in the cache
        )

        # Only authenticated accounts will return a valid token
        if "access_token" in token_response:
            return True  # User is authenticated

    return False  # Default to not authenticated


def cms_is_authenticated():
    """Check if the user is authenticated by verifying their email in the session"""
    user_email = session.get("user", {}).get(
        "email"
    )  # From verified claims when logged in
    return (
        user_email in CMS_ALLOWED_EMAILS and is_authenticated()
    )  # Ensure is authenticated


def is_safe_url(target):
    """
    Check if the target URL is safe by ensuring it is either a relative URL or matches the app's domain.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


"""
HTTP Security Settings
"""


@app.before_request
def check_https():
    if not app.debug:
        # Allow HTTP for internal health check requests
        if request.path == "/liveness":
            return None  # Bypass HTTPS enforcement for the probe within the container
        elif request.headers.get("X-Forwarded-Proto", "http") != "https":
            return redirect(request.url.replace("http://", "https://"))


@app.after_request
def set_security_headers(response):
    """
    Allow specific scripts relating to CMS use
    """
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "connect-src 'self' https://api.github.com https://www.githubstatus.com;"  # Allow CMS github access
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net/gh/hithismani/responsive-decap@main/dist/responsive.min.css; "  # Allow inline styles
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com; "  # Allow inline scripts and event handlers
        "img-src 'self' blob: https://avatars.githubusercontent.com; "
        "font-src 'self'; "
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    return response


@app.after_request
def add_cache_headers(response):
    # Apply long cache duration for static assets
    if request.path.startswith("/static") or any(
        request.path.endswith(ext)
        for ext in [".css", ".js", ".png", ".jpg", ".gif", ".svg"]
    ):
        response.headers["Cache-Control"] = "public, max-age=31536000"
    # Don't cache dynamic routes like logout, login, or authenticated content
    elif request.endpoint in ["logout", "login", "authorized", "index"]:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    else:
        # Default caching behavior for other routes (adjust as needed)
        response.headers["Cache-Control"] = "public, max-age=3600"
    return response


"""
Webhooks
These define routes by which the Github Workflow can manage the zero-downtime deployment of the static site.
There are two webhooks:
- Current state: which returns whether the 'blue' or the 'green' deployment of the static site is in current use
- Toggle state: which switches the active deployment

Zero downtime SSG deployment
- The Github Workflow deploys a website revision to the non-active directory
- Once copied, Flask is informed via the webhook to switch via the HUGO_PATH variable

Security:
- The webhook URLs are random strings set by environment variables
- The toggle webhook is further protected by a single-use password, which the Github Workflow accesses via secrets

State across multiple workers:
- The blue or green deployment status is saved to a file on the mounted volume.
- For Gunicorn workers to register a change, a scheduled task reads the file periodically
"""


def generate_random_webhook_secret(length=32):
    """
    Generates a random string for the webhook secret.

    :param length: The length of the random string (default is 32 characters).
    :return: A secure random string.
    """
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


GREEN_DIR = os.path.join(MOUNT_PATH, "green/")
BLUE_DIR = os.path.join(MOUNT_PATH, "blue/")
SERVE_DIRECTORY_STATE_PATH = os.path.join(MOUNT_PATH, "state/serve_directory.txt")
WEBHOOK_CURRENT_SERVE_DIRECTORY = os.getenv(
    "WEBHOOK_CURRENT_SERVE_DIRECTORY", generate_random_webhook_secret()
)
WEBHOOK_TOGGLE_SERVE_DIRECTORY = os.getenv(
    "WEBHOOK_TOGGLE_SERVE_DIRECTORY", generate_random_webhook_secret()
)

# Github Toggle webook password
PASSWORD_FILE = os.path.join(MOUNT_PATH, "state/github_password.txt")
LOCK_FILE = PASSWORD_FILE + ".lock"
PASSWORD_LIFETIME = 3600  # 1 hour
JITTER_RANGE = 0.1  # Jitter range in seconds (100 milliseconds)


"""
Set up directory structure on deploy
"""


def ensure_directory_exists(path):
    # Extract the direcotry from the file path
    directory = os.path.dirname(path)
    # Create the directory if it doesn't exist
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
        print(f"Created directory: {directory}")


def ensure_file_exists(file_path):
    if not os.path.exists(file_path):
        with open(file_path, "w") as file:
            file.write("")  # Write an empty string or initial content if needed
        print(f"Created file: {file_path}")
    else:
        print(f"File already exists: {file_path}")


# Ensure the paths exist on load
ensure_directory_exists(GREEN_DIR)
ensure_directory_exists(BLUE_DIR)
ensure_directory_exists(SERVE_DIRECTORY_STATE_PATH)
ensure_file_exists(SERVE_DIRECTORY_STATE_PATH)
ensure_file_exists(PASSWORD_FILE)  # state/ directory already created


def check_current_serve_directory():
    # Read the file to check its contents
    with open(SERVE_DIRECTORY_STATE_PATH, "r") as file:
        content = file.read().strip()

        # Set the starting value if empty
        if content not in ["blue", "green"]:
            content = "green"  # Default to green
            with open(SERVE_DIRECTORY_STATE_PATH, "w") as file:  # overwrite
                file.write(content)

        # Return the new content as plain text
        return content.strip().lower()


def toggle_current_serve_directory():
    # Read the file to check its contents
    with open(SERVE_DIRECTORY_STATE_PATH, "r") as file:
        content = file.read().strip()

        # Check if the content is 'blue' or 'green' and toggle
        if content == "blue":
            new_content = "green"
        elif content == "green":
            new_content = "blue"
        else:
            new_content = "green"  # Set new default

        # Overwrite the file with the new content
        with open(SERVE_DIRECTORY_STATE_PATH, "w") as file:
            file.write(new_content)

        # Return the new content as plain text
        return new_content.strip().lower()


"""Github password handling for toggle webhook"""


def read_password_file():
    """Reads the password and timestamp from the file if it exists."""
    if not os.path.exists(PASSWORD_FILE):
        ensure_directory_exists(PASSWORD_FILE)
        return None, 0  # File doesn't exist yet

    try:
        with open(PASSWORD_FILE, "r") as f:
            content = f.read().strip()
            if content:
                password, timestamp = content.split(":")
                return password, float(timestamp)
    except Exception as e:
        app.logger.warning(f"Failed to read password file: {e}")
        return None, 0

    return None, 0


def write_password_file(password, timestamp):
    """Writes a new password and timestamp to the password file."""
    try:
        with open(PASSWORD_FILE, "w") as f:
            f.write(f"{password}:{timestamp}")
    except Exception as e:
        app.logger.warning(f"Failed to write password file: {e}")


def generate_or_refresh_password(force=False):
    """Generates a new password if the existing one is stale or if forced."""
    current_time = time.time()
    password, timestamp = read_password_file()

    # Check if password is expired
    if force or current_time - timestamp > PASSWORD_LIFETIME:
        # Add a small jitter before attempting to create the lock file
        time.sleep(random.uniform(0, JITTER_RANGE))

        # Attempt to create lock file exclusively
        # Prevents a race condition between workers
        try:
            with open(LOCK_FILE, "x") as lock:
                # Successfully created lock file; now update password
                app.logger.info("Lock file created; password update proceeding")
                new_password = str(uuid.uuid4())
                write_password_file(new_password, current_time)
                os.remove(LOCK_FILE)  # Remove the lock file after updating
                return new_password, True  # Password updated
        except FileExistsError:
            # Another worker has the lock; let it handle the update
            app.logger.info("Lock file exists; no update required")
            return password, False  # No update needed by this worker

    return password, False  # No update needed, password valid


# Send the password to GitHub Secrets
def update_github_secret(password):
    # Send the password to Github secrets
    secret_updater = GitHubSecretUpdater(
        GITHUB_REPO, GITHUB_SECRETS_TOKEN, debug=app.debug
    )
    secret_updater.update_secret("WORKFLOW_TOKEN", password)


# On Flask app start, ensure password is up-to-date
def initialise_password():
    password, changed = generate_or_refresh_password(force=True)
    if changed:
        update_github_secret(password)


initialise_password()  # Initialise on app start


# Set the HUGO_PATH variable according to the deploy version
def set_hugo_path():
    if app.debug:
        path = os.path.join(MOUNT_PATH, "public")
    else:
        path = os.path.join(MOUNT_PATH, check_current_serve_directory())
    return path


HUGO_PATH = set_hugo_path()  # On app start


# Periodically check whether the HUGO_PATH has been updated
def periodic_state_check():
    global HUGO_PATH
    HUGO_PATH = set_hugo_path()
    app.logger.info(f"Active version set to {HUGO_PATH}")


# Initialize the scheduler
def start_scheduler():
    scheduler = BackgroundScheduler()
    # Add a job that runs every minute (or choose your desired interval)
    scheduler.add_job(func=periodic_state_check, trigger="interval", seconds=60)
    scheduler.start()


# Start on app load
start_scheduler()


@app.route(f"/webhook/{WEBHOOK_CURRENT_SERVE_DIRECTORY}")
def current_state():
    """Returns the current deploy directory as plain text"""
    current_directory = check_current_serve_directory()
    return current_directory, 200


@app.route(f"/webhook/{WEBHOOK_TOGGLE_SERVE_DIRECTORY}", methods=["POST"])
@csrf.exempt
def toggle_state():
    """
    Toggles the deploy directory if the password header matches
    Re-sends the password to github secrets if incorrect (to fix a sync issue if exists)
    Refreshes the password on success if expired
    Returns the final deploy directory as plain text
    """
    request_password = request.headers.get("X-Webhook-Password")
    password, _ = read_password_file()

    if password:
        if password == request_password:
            # Toggle the serve directory
            current_directory = toggle_current_serve_directory()
        else:
            update_github_secret(password)  # Ensure passwords are in sync
            return jsonify({"error": "Invalid Github Workflow token"}), 403

    # Refresh the password
    new_password, changed = generate_or_refresh_password()
    if changed:
        update_github_secret(new_password)

    return current_directory, 200


"""
MSAL Authentication Flow
"""


def load_cache():
    # Load the cache from the server-side session
    cache = msal.SerializableTokenCache()
    if "token_cache" in session:
        cache.deserialize(session["token_cache"])
    return cache


def save_cache(cache):
    # Store the token cache in the session
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()


def build_msal_app():
    # Initialize the MSAL app; calls load_cache to retrieve or initialise the cache
    cache = load_cache()
    msal_app = msal.ConfidentialClientApplication(
        AZURE_CLIENT_ID,
        authority=AZURE_AUTHORITY,
        client_credential=AZURE_CLIENT_SECRET,
        token_cache=cache,  # Pass in the cache
    )

    return msal_app


def validate_next(next_url):
    """Ensure the url passed is safe and is not the landing page
    Defaults to returning the index"""
    if next_url:
        # Ensure the URL is relative
        parsed_url = urlparse(next_url)
        if parsed_url.netloc == request.host:  # Only strip if it's the same host
            next_url = parsed_url.path

        if is_safe_url(next_url) and next_url != url_for("landing"):
            return next_url

    # Return index if none of the conditions are met
    return url_for("index")


@app.route("/login")
def login():
    """
    The first part of the OAuth2 flow
    Returns an authorisation URL provided by MSAL
    Users log in at this URL, which redirects back to this app with:
    - A code that can be exchanged for an authorization token
    - The state set here (to prevent CSRF attacks)
    """
    # Store the original URL in the session (from 'next' parameter or referer)
    next_url = request.args.get("next") or request.referrer or None

    # Validate the next_url
    next_url = validate_next(next_url)  # Returns url_for(index) if not validated
    session["next_url"] = next_url

    msal_app = build_msal_app()  # Includes loading from cache
    nonce = secrets.token_urlsafe(16)  # Generates a URL-safe, random string
    session["state"] = nonce  # Set the state for CSRF protection

    # Retrieves a URL from Entra where the user can login
    auth_url = msal_app.get_authorization_request_url(
        scopes=AZURE_SCOPE, redirect_uri=REDIRECT_URI, state=nonce
    )
    return redirect(auth_url)


@app.route("/login/authorized")
def authorized():
    """
    The second part of the OAuth2 authentication flow
    If login was successful, a code is returned which can be exchanged for an access token
    This token will be stored in cache on the server filesystem
    """

    """Check request parameters"""
    # Check if the state parameter is valid
    if request.args.get("state") != session.get("state"):
        app.logger.warning("State parameter mismatch or missing. Redirecting to login.")

        # Only include 'next' parameter if it has a valid value
        next_url = validate_next(session.get("next_url"))
        return redirect(url_for("login", next=next_url))

    if "error" in request.args:
        return f"Error: {request.args.get('error_description')}", 400

    code = request.args.get("code")
    if not code:
        abort(400, description="Authorization code not found.")

    """Get the access token using the code returned by the first part of the flow"""
    # Get the MSAL app and acquire the token
    msal_app = build_msal_app()
    token_response = msal_app.acquire_token_by_authorization_code(
        code, scopes=AZURE_SCOPE, redirect_uri=REDIRECT_URI
    )

    """Check the access token"""
    if "error" in token_response:
        return f"Error: {token_response.get('error_description')}", 400

    id_token = token_response.get("id_token")
    if not id_token:
        return "Authentication failed: ID token not found.", 400

    # Access decoded claims from the ID token
    id_token_claims = token_response.get("id_token_claims")

    """Verify additional claims"""
    if (
        id_token_claims.get("iss")
        != f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/v2.0"
    ):
        return "Invalid token issuer.", 403

    if id_token_claims.get("tid") != AZURE_TENANT_ID:
        return "Unauthorized tenant.", 403

    # UPN often contains the user email in Entra
    user_email = id_token_claims.get("email") or id_token_claims.get("upn")
    domain_allowed = check_email_domain(user_email)
    if not user_email or not domain_allowed:
        return "Unauthorized user.", 403

    user_groups = id_token_claims.get("groups", [])
    allowed_group_ids = [group_id for group_id in ALLOWED_GROUP_IDS if group_id]
    if allowed_group_ids and not any(
        group_id in allowed_group_ids for group_id in user_groups
    ):
        return "User does not belong to an authorized group.", 403

    # If checks are passed, save the token and details to the session
    session["token_cache"] = msal_app.token_cache.serialize()
    session["user"] = {"name": id_token_claims.get("name"), "email": user_email}

    # Redirect to the stored 'next_url' or the index
    next_url = validate_next(session.pop("next_url", None))
    return redirect(next_url)


@app.route("/logout")
def logout():
    # Check if the user is logged in by verifying if the 'user' key is in session
    if is_authenticated():
        # Remove the token and details from the session
        session.clear()

        # Access the MSAL app and clear cached accounts
        msal_app = build_msal_app()
        accounts = msal_app.get_accounts()

        # Remove each account from the cache
        for account in accounts:
            msal_app.remove_account(account)

        # Prevent browser caching of pages after logout
        logout_url = f"{AZURE_AUTHORITY}/oauth2/v2.0/logout?post_logout_redirect_uri={url_for('landing', _external=True)}&logout_hint={session.get('user', {}).get('email')}"

        response = make_response(redirect(logout_url))
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    # If the user is not logged in, redirect to the landing page
    return redirect(url_for("landing", _external=True))


"""
Azure Container Routes
"""


# Azure container apps health check
@app.route("/liveness")
def health_check():
    return "OK", 200


"""
Decap CMS
"""


@app.route("/cms/config.yml")
def decap_config():
    response = send_from_directory(HUGO_PATH, "admin/config.yml")
    response.headers["Content-Type"] = "text/yaml"  # Set correct content type for YAML
    return response


@app.route("/cms/preview.css")
def decap_css():
    response = send_from_directory(HUGO_PATH, "admin/preview.css")
    response.headers["Content-Type"] = "text/css"  # Set correct content type for CSS
    return response


def get_auth_message(succeed=False):
    if succeed:
        content = json.dumps({"token": "", "provider": "github"})
        message = "success"
    else:
        content = "Error: you are not authorised to access the CMS"
        message = "error"
    return message, content


@app.route("/cms/auth", methods=["GET", "POST"])
def cms_auth():
    # Determine whether authentication succeeds
    succeed = app.debug or cms_is_authenticated()

    # Structure message for Decap CMS
    message, content = get_auth_message(succeed=succeed)
    data = f"authorization:github:{message}:{content}"
    token = generate_csrf() if succeed else None
    token_json = {"csrf": token}
    return render_template("cms_authenticate.html", data=data, token=token_json)


@app.route("/cms/proxy", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def proxy_request():
    if not app.debug and not cms_is_authenticated():
        return abort(403)  # Block unauthenticated users

    token = request.headers.get(
        "X-CSRFToken"
    )  # Assuming the CSRF token is sent in the header

    if not token:
        abort(400, description="Missing CSRF token")
    try:
        validate_csrf(token)  # Validate the token
    except CSRFError:
        abort(400, description="Invalid CSRF token")

    # Get the proxied URL
    original_url = request.args.get("url")  # Undo encodeURIComponent
    decoded_url = unquote(original_url)

    # Ensure the scheme is HTTPS and the domain is api.github.com
    parsed_url = urlparse(decoded_url)
    if not parsed_url.scheme == "https" and parsed_url.netloc == "api.github.com":
        return jsonify({"error": "Invalid URL"}), 400

    # Prepare headers and add the GitHub Authorization token
    headers = dict(request.headers)
    headers["Authorization"] = f"token {CMS_GITHUB_TOKEN}"
    headers["Accept"] = "application/vnd.github+json"
    headers["X-GitHub-Api-Version"] = "2022-11-28"
    headers["Referer"] = request.url_root

    # Remove problematic headers
    headers.pop("Host", None)
    headers.pop("Content-Length", None)
    headers.pop("Connection", None)
    headers.pop("Cookie", None)
    headers.pop("X-CSRFToken", None)

    # Handle body for non-GET methods (uploads)
    data = None
    if request.method != "GET":
        if request.is_json:
            data = request.get_json()
        else:
            data = request.get_data() or None  # For binary uploads

    # Forward the request to GitHub
    response = requests.request(
        method=request.method,
        url=decoded_url,
        headers=headers,
        json=data if request.is_json else None,  # Use json for JSON bodies
        data=data if not request.is_json else None,  # Use data for non-JSON bodies
        params=(
            request.args if request.method == "GET" else None
        ),  # Only pass params for GET requests
    )

    # Debugging for non-200 responses
    if response.status_code != 200:
        print(f"Error: {response.status_code}, {response.text}")

    # Decoded by Flask; remove inaccurate headers
    headers = dict(response.headers)
    headers.pop("content-encoding", None)
    headers.pop("content-length", None)

    # Generate a new CSRF token
    new_csrf_token = generate_csrf()

    # Handle the content based on its type
    content_type = response.headers.get("Content-Type", "application/octet-stream")

    if "application/json" in content_type or "text" in content_type:
        # Modify URLs for text-based content (e.g., JSON)
        content = response.text.replace(
            "https://api.github.com",
            request.url_root + "cms/proxy?url=https://api.github.com",
        )
        return Response(
            content,
            status=response.status_code,
            headers={"Content-Type": content_type, "X-CSRFToken": new_csrf_token},
        )
    else:
        # Return raw binary content (e.g., images)
        return Response(
            response.content,
            status=response.status_code,
            headers={"Content-Type": content_type, "X-CSRFToken": new_csrf_token},
        )


# Serve DecapCMS routes without auth
@app.route("/cms")
def decap_admin():
    # Ensure logged in
    if not app.debug and not is_authenticated():
        return redirect(url_for("login", next=request.url))

    if not app.debug and not cms_is_authenticated():
        # If not on CMS authorised users list
        return abort(
            403, "Please contact an administrator if you require CMS access"
        )  # Block unauthenticated users

    # Get the admin template for rendering
    admin_template_path = os.path.join(HUGO_PATH, "admin/index.html")
    with open(admin_template_path, "r") as file:
        template_content = file.read()

    # Render the content (including CSRF + CMS)
    return render_template_string(template_content)


"""
Static Web App Routes
"""


@app.route("/favicon.ico")
@app.route("/robots.txt")
@app.route("/android-chrome-192x192.png")
@app.route("/android-chrome-512x512.png")
@app.route("/apple-touch-icon.png")
@app.route("/favicon-16x16.png")
@app.route("/favicon-32x32.png")
@app.route("/site.webmanifest")
@app.route("/sitemap.xml")
def serve_public_static_files():
    return send_from_directory(
        HUGO_PATH, request.path[1:]
    )  # Removes the leading '/' from the path


@app.route("/landing")
def landing():
    return render_template("landing.html", welcome_message=LANDING_PAGE_MESSAGE)


@app.route("/")
def index():
    if app.debug or is_authenticated():
        return send_from_directory(HUGO_PATH, "index.html")
    else:
        # For unauthenticated users
        return redirect(url_for("landing"))


@app.route("/<path:path>")
def serve_static(path):
    """
    Safely serves the Hugo site from the public/ directory

    Protected from directory traversal attacks by Flask's send_from_directory()
    """

    # Ensure logged in
    if not app.debug and not is_authenticated():
        return redirect(url_for("login", next=request.url))

    full_path = os.path.join(HUGO_PATH, path)

    # Serve assets directly (e.g., CSS, JS, images)
    if any(
        path.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".gif", ".svg"]
    ):
        try:
            return send_from_directory(HUGO_PATH, path)
        except NotFound:
            app.logger.warning(f"Asset not found: {path}")
            abort(404)

    # If the path is a directory
    if os.path.isdir(full_path):
        # Ensure URL ends with a trailing slash
        if not request.path.endswith("/"):
            return redirect(request.path + "/")
        # Serve 'index.html' from the directory
        return send_from_directory(full_path, "index.html")

    # Try to serve the file directly (images and other static files)
    try:
        return send_from_directory(HUGO_PATH, path)
    except NotFound:
        pass  # File not found, proceed to try adding '.html'

    # Try adding '.html' extension
    html_file = f"{path}.html"
    try:
        return send_from_directory(HUGO_PATH, html_file)
    except NotFound:
        abort(404)


# Custom 404 Error Page
@app.errorhandler(404)
def page_not_found(e):
    try:
        return send_from_directory(HUGO_PATH, "404.html"), 404
    except:
        return "404 Not Found", 404


if __name__ == "__main__":
    app.run(port=8000)
