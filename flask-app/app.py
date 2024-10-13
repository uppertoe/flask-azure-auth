from flask import Flask, redirect, url_for, session, request, abort, send_from_directory, render_template
from flask_session import Session
from flask_wtf import CSRFProtect
import os
import sys
import logging
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from jose import jwt
import msal
from werkzeug.exceptions import NotFound

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


# Set default environment (production) and load .env
FLASK_ENV = os.getenv('FLASK_ENV', 'production')

# Load .env only in development
if os.getenv('FLASK_ENV') == 'development' and os.path.exists('../.env'):
    load_dotenv('../.env')

# Initialize the Flask app
app = Flask(__name__)

app.logger.setLevel(logging.INFO)

# Set secret key from environment variable or a default value
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# Load configurations from environment variables
AZURE_CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
AZURE_CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')
AZURE_SCOPE = os.getenv('AZURE_SCOPE', '').split()
REDIRECT_URI = os.getenv('REDIRECT_URI')
AZURE_TENANT_ID = os.getenv('AZURE_TENANT_ID')
ALLOWED_EMAIL_DOMAIN = os.getenv('ALLOWED_EMAIL_DOMAIN')
ALLOWED_GROUP_IDS = os.getenv('ALLOWED_GROUP_IDS', '').split(',')
app.config['DEBUG'] = os.getenv('DEBUG', False)  # Defaults to False if not set

app.config['SESSION_COOKIE_SECURE'] = not app.debug  # Secure for production

if not app.debug:
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Helps mitigate XSS attacks by making cookies inaccessible to JavaScript
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Prevents CSRF attacks during third-party contexts
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Set session expiration

# Configure Flask-Session to use the file system
app.config['SESSION_TYPE'] = 'filesystem'  # Use file system for sessions
app.config['SESSION_FILE_DIR'] = './flask_sessions'  # Directory for session files
app.config['SESSION_PERMANENT'] = False  # Session expires when the browser is closed

# Set other variables
AZURE_AUTHORITY = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
MOUNT_PATH = '' if app.debug else os.getenv('MOUNT_PATH', '/mnt')
SERVE_DIRECTORY = os.getenv('SERVE_DIRECTORY', 'public')  # Switch to temp/ for zero-downtime deploy
if SERVE_DIRECTORY not in ['public', 'temp']:
    raise RuntimeError(f'Invalid SERVE_DIRECTORY: {SERVE_DIRECTORY} - exiting.')
HUGO_PATH = os.path.join(MOUNT_PATH, SERVE_DIRECTORY)

app.logger.info(f"Hugo path: {HUGO_PATH}")

# Initialize Flask-Session
Session(app)

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Initialize MSAL Confidential Client
msal_app = msal.ConfidentialClientApplication(
    AZURE_CLIENT_ID,
    authority=AZURE_AUTHORITY,
    client_credential=AZURE_CLIENT_SECRET,
    token_cache=None  # Configure token cache as needed
)

# Helper Functions
def is_authenticated():
    token = session.get('azure_token')
    expires_at = session.get('expires_at')

    # Check that both token and expiration exist and expiration hasn't passed
    if token and expires_at:
        if datetime.now(tz=timezone.utc) < expires_at:
            return True

    # If token is missing or expired, clear the session
    session.clear()
    return False

# Enforce HTTPS
@app.before_request
def check_https():
    if not app.debug:
        if request.headers.get('X-Forwarded-Proto', 'http') != 'https':
            return redirect(request.url.replace("http://", "https://"))

@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "  # Allow inline styles
        "script-src 'self' 'unsafe-inline'; "  # Allow inline scripts and event handlers
        "img-src 'self'; "
        "font-src 'self'; "
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Routes

@app.route('/')
def index():
    if app.debug or is_authenticated():
        return send_from_directory(HUGO_PATH, 'index.html')
    # Render the landing page if not authenticated
    return render_template('landing.html')

@app.route('/login')
def login():
    session["state"] = os.urandom(24).hex()
    auth_url = msal_app.get_authorization_request_url(
        scopes=AZURE_SCOPE,
        redirect_uri=REDIRECT_URI,
        state=session["state"]
    )
    return redirect(auth_url)

@app.route('/logout')
def logout():
    session.clear()
    logout_url = f"{AZURE_AUTHORITY}/oauth2/v2.0/logout?post_logout_redirect_uri={url_for('index', _external=True)}"
    return redirect(logout_url)

@app.route('/login/authorized')
def authorized():
    if request.args.get('state') != session.get('state'):
        abort(400, description="Invalid state parameter.")

    if 'error' in request.args:
        return f"Error: {request.args.get('error_description')}", 400
    code = request.args.get('code')

    if not code:
        abort(400, description="Authorization code not found.")
    result = msal_app.acquire_token_by_authorization_code(
        code,
        scopes=AZURE_SCOPE,
        redirect_uri=REDIRECT_URI
    )
    if "error" in result:
        return f"Error: {result.get('error_description')}", 400
    
    id_token = result.get('id_token')
    access_token = result.get('access_token')
    if not id_token or not access_token:
        return "Authentication failed: ID token or access token not found.", 400
    
    claims = jwt.get_unverified_claims(id_token)
    if claims.get('tid') != AZURE_TENANT_ID:
        return "Unauthorized tenant.", 403
    
    user_email = claims.get('email') or claims.get('upn')
    if not user_email or not user_email.endswith(ALLOWED_EMAIL_DOMAIN):
        return "Unauthorized user.", 403
    
    user_groups = claims.get('groups', [])
    allowed_group_ids = [group_id for group_id in ALLOWED_GROUP_IDS if group_id]  # Remove empty strings
    if allowed_group_ids and not any(group_id in allowed_group_ids for group_id in user_groups):
        return "User does not belong to an authorized group.", 403

    session['azure_token'] = result
    session['expires_at'] = datetime.now(tz=timezone.utc) + timedelta(seconds=result['expires_in'])
    session['user'] = {
        'name': claims.get('name'),
        'email': user_email,
    }

    return redirect(url_for('index'))

@app.route('/<path:path>')
def serve_static(path):
    '''
    Safely serves the Hugo site from the public/ directory

    Protected from directory traversal attacks by Flask's send_from_directory()
    '''

    # Ensure logged in
    if not app.debug and not is_authenticated():
        return redirect(url_for('login'))

    full_path = os.path.join(HUGO_PATH, path)

    # If the path is a directory
    if os.path.isdir(full_path):
        # Ensure URL ends with a trailing slash
        if not request.path.endswith('/'):
            return redirect(request.path + '/')
        # Serve 'index.html' from the directory
        return send_from_directory(full_path, 'index.html')

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
        return send_from_directory(HUGO_PATH, '404.html'), 404
    except:
        return "404 Not Found", 404

if __name__ == '__main__':
    app.run(port=8000)
