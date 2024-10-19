import os
import sys
import logging
import base64
import requests
import json
import msal
import jwt
from flask import (
    Flask,
    redirect,
    url_for,
    session,
    request,
    abort,
    send_from_directory,
    render_template,
    jsonify,
    render_template_string,
    Response,
)
from flask_session import Session
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, validate_csrf, generate_csrf
from urllib.parse import urlparse, urljoin, unquote
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from jwt import InvalidSignatureError, ExpiredSignatureError, InvalidTokenError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from werkzeug.exceptions import NotFound

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

# Load .env only in development
load_dotenv(".env")

# Initialize the Flask app
app = Flask(__name__)

app.logger.setLevel(logging.INFO)

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
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
        hours=1
    )  # Set session expiration

# Load configurations from environment variables
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_SCOPE = os.getenv("AZURE_SCOPE", "").split()
REDIRECT_URI = os.getenv("REDIRECT_URI")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
ALLOWED_EMAIL_DOMAIN = os.getenv("ALLOWED_EMAIL_DOMAIN")
ALLOWED_GROUP_IDS = os.getenv("ALLOWED_GROUP_IDS", "").split(",")
CMS_ALLOWED_EMAILS = os.getenv("CMS_ALLOWED_EMAILS", "").split(",")
CMS_GITHUB_TOKEN = os.getenv("CMS_GITHUB_TOKEN")

# Set other variables
AZURE_AUTHORITY = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
MOUNT_PATH = "" if app.debug else os.getenv("MOUNT_PATH", "/mnt")
SERVE_DIRECTORY = os.getenv(
    "SERVE_DIRECTORY", "public"
)  # Switch to temp/ for zero-downtime deploy
if SERVE_DIRECTORY not in ["public", "temp"]:
    raise RuntimeError(f"Invalid SERVE_DIRECTORY: {SERVE_DIRECTORY} - exiting.")
HUGO_PATH = os.path.join(MOUNT_PATH, SERVE_DIRECTORY)
SESSION_PATH = os.path.join(MOUNT_PATH, "flask_sessions")

# Configure Flask-Session to use the file system
app.config["SESSION_TYPE"] = "filesystem"  # Use file system for sessions
app.config["SESSION_FILE_DIR"] = SESSION_PATH  # Directory for session files
app.config["SESSION_PERMANENT"] = True  # Permanent session
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)  # Session lasts 7 days

# Ensure the public/ and temp/ directories exist
PUBLIC_DIR = os.path.join(MOUNT_PATH, "public")
TEMP_DIR = os.path.join(MOUNT_PATH, "temp")


def create_directories():
    try:
        # Create /public and /temp directories if they don't exist
        os.makedirs(PUBLIC_DIR, exist_ok=True)
        os.makedirs(TEMP_DIR, exist_ok=True)
        print(f"Directories '/public' and '/temp' created or already exist.")
    except Exception as e:
        print(f"Error creating directories: {e}")


create_directories()  # Call on app start

# Initialize Flask-Session
Session(app)

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Initialize MSAL Confidential Client
msal_app = msal.ConfidentialClientApplication(
    AZURE_CLIENT_ID,
    authority=AZURE_AUTHORITY,
    client_credential=AZURE_CLIENT_SECRET,
    token_cache=None,  # Configure token cache as needed
)


# Helper Functions
def is_authenticated():
    token = session.get("azure_token")
    expires_at = session.get("expires_at")

    # Check that both token and expiration exist and expiration hasn't passed
    if token and expires_at:
        if datetime.now(tz=timezone.utc) < expires_at:
            return True

    # If token is missing or expired, clear the session
    session.clear()
    return False


def cms_is_authenticated():
    # Check if the user is authenticated by verifying their email in the session
    user_email = session.get("user", {}).get("email")
    return user_email in CMS_ALLOWED_EMAILS and is_authenticated()


def is_safe_url(target):
    """
    Check if the target URL is safe by ensuring it is either a relative URL or matches the app's domain.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def base64url_to_int(val):
    """Decodes a base64url-encoded string to an integer."""
    # Add padding if necessary
    val = val + "=" * (4 - len(val) % 4)
    decoded = base64.urlsafe_b64decode(val)
    return int.from_bytes(decoded, "big")


def get_public_key(jwks, kid):
    for key in jwks["keys"]:
        if key["kid"] == kid:
            n = base64url_to_int(
                key["n"]
            )  # Convert the base64url-encoded modulus to an integer
            e = base64url_to_int(
                key["e"]
            )  # Convert the base64url-encoded exponent to an integer
            public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())

            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
    raise ValueError("Public key not found.")


# Enforce HTTPS
@app.before_request
def check_https():
    if not app.debug:
        # Allow HTTP for internal health check requests
        if request.path == "/liveness":
            return None  # Bypass HTTPS enforcement for the probe
        elif request.headers.get("X-Forwarded-Proto", "http") != "https":
            return redirect(request.url.replace("http://", "https://"))


@app.after_request
def set_security_headers(response):
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
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    return response


@app.after_request
def add_cache_headers(response):
    # Apply long cache duration for static assets (CSS, JS, images)
    if request.path.startswith("/static") or any(
        request.path.endswith(ext)
        for ext in [".css", ".js", ".png", ".jpg", ".gif", ".svg"]
    ):
        response.headers["Cache-Control"] = (
            "public, max-age=31536000"  # Cache static assets for 1 year
        )
    else:
        response.headers["Cache-Control"] = (
            "public, max-age=3600"  # 1 hour for other content
        )
    return response


"""Routes"""


# Azure container apps health check
@app.route("/liveness")
def health_check():
    return "OK", 200


@app.route("/login")
def login():
    app.logger.info(f"Login attempt for URL: {request.url}")

    # Store the original URL in the session (from 'next' parameter or referer)
    next_url = request.args.get("next") or request.referrer or url_for("index")

    # Ensure the next_url is safe before proceeding
    if not is_safe_url(next_url):
        next_url = url_for("index")  # Default to index if the URL is unsafe

    session["next_url"] = next_url

    session["state"] = os.urandom(24).hex()
    auth_url = msal_app.get_authorization_request_url(
        scopes=AZURE_SCOPE, redirect_uri=REDIRECT_URI, state=session["state"]
    )
    return redirect(auth_url)


@app.route("/logout")
def logout():
    session.clear()
    logout_url = f"{AZURE_AUTHORITY}/oauth2/v2.0/logout?post_logout_redirect_uri={url_for('index', _external=True)}"
    return redirect(logout_url)


@app.route("/login/authorized")
def authorized():
    # Check if the state parameter is valid
    if request.args.get("state") != session.get("state"):
        app.logger.warning("State parameter mismatch or missing. Redirecting to login.")
        return redirect(
            url_for("login", next=session.get("next_url", url_for("index")))
        )

    if "error" in request.args:
        return f"Error: {request.args.get('error_description')}", 400

    code = request.args.get("code")
    if not code:
        abort(400, description="Authorization code not found.")

    result = msal_app.acquire_token_by_authorization_code(
        code, scopes=AZURE_SCOPE, redirect_uri=REDIRECT_URI
    )

    if "error" in result:
        return f"Error: {result.get('error_description')}", 400

    id_token = result.get("id_token")
    if not id_token:
        return "Authentication failed: ID token not found.", 400

    # Get public keys from Azure AD
    jwks_url = (
        f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/discovery/v2.0/keys"
    )
    jwks = requests.get(jwks_url).json()

    # Extract the key ID (kid) from the token header
    unverified_header = jwt.get_unverified_header(id_token)
    kid = unverified_header["kid"]

    try:
        # Get the PEM-formatted public key
        public_key = get_public_key(jwks, kid)

        # Decode the JWT
        claims = jwt.decode(
            id_token, public_key, algorithms=["RS256"], audience=AZURE_CLIENT_ID
        )
    except ExpiredSignatureError:
        return "Token has expired.", 401
    except InvalidSignatureError:
        return "Invalid token signature.", 401
    except InvalidTokenError:
        return "Invalid token.", 401
    except Exception as e:
        return str(e), 400

    # Verify additional claims
    if claims.get("iss") != f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/v2.0":
        return "Invalid token issuer.", 403

    if claims.get("tid") != AZURE_TENANT_ID:
        return "Unauthorized tenant.", 403

    user_email = claims.get("email") or claims.get("upn")
    if not user_email or not user_email.endswith(ALLOWED_EMAIL_DOMAIN):
        return "Unauthorized user.", 403

    user_groups = claims.get("groups", [])
    allowed_group_ids = [group_id for group_id in ALLOWED_GROUP_IDS if group_id]
    if allowed_group_ids and not any(
        group_id in allowed_group_ids for group_id in user_groups
    ):
        return "User does not belong to an authorized group.", 403

    # Store token and session data
    session["azure_token"] = result
    session["expires_at"] = datetime.now(tz=timezone.utc) + timedelta(
        seconds=result["expires_in"]
    )
    session["user"] = {
        "name": claims.get("name"),
        "email": user_email,
    }

    # Redirect to the stored 'next_url' or the index
    return redirect(session.pop("next_url", url_for("index")))


@app.route("/favicon.ico")
@app.route("/robots.txt")
@app.route("/android-chrome-192x192.png")
@app.route("/android-chrome-512x512.png")
@app.route("/apple-touch-icon.png")
@app.route("/favicon-16x16.png")
@app.route("/favicon-32x32.png")
def serve_public_static_files():
    return send_from_directory(
        HUGO_PATH, request.path[1:]
    )  # Removes the leading '/' from the path


"""Decap CMS"""


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
        content = json.dumps({"token": "2", "provider": "github"})
        message = "success"
    else:
        content = "Error: you are not authorised to access the CMS"
        message = "error"

    print(message, content)
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
        "X-CSRF-Token"
    )  # Assuming the CSRF token is sent in the header
    print(f"Received Token: {token}")
    print(f"Session Token: {session.get('csrf_token')}")
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

    # Remove problematic headers
    headers.pop("Host", None)
    headers.pop("Content-Length", None)
    headers.pop("Connection", None)
    headers.pop("Cookie", None)
    headers.pop("X-CSRF-Token", None)

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
            headers={"Content-Type": content_type, "X-CSRF-Token": new_csrf_token},
        )
    else:
        # Return raw binary content (e.g., images)
        return Response(
            response.content,
            status=response.status_code,
            headers={"Content-Type": content_type, "X-CSRF-Token": new_csrf_token},
        )


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


@app.route("/")
def index():
    if app.debug or is_authenticated():
        return send_from_directory(HUGO_PATH, "index.html")
    # Render the landing page if not authenticated
    return render_template("landing.html")


# Custom 404 Error Page
@app.errorhandler(404)
def page_not_found(e):
    try:
        return send_from_directory(HUGO_PATH, "404.html"), 404
    except:
        return "404 Not Found", 404


if __name__ == "__main__":
    app.run(port=8000)
