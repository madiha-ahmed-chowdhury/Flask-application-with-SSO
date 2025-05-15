import os
import json
import secrets
import logging
import datetime
from flask import Flask, redirect, request, url_for, session, render_template, jsonify, make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from functools import wraps
import requests
from urllib.parse import urlencode
from dotenv import load_dotenv
from flask_session import Session

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(16))

# More robust session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)

# Initialize Flask-Session
from flask_session import Session
Session(app)

# Print debug information about template paths
print(f"Current working directory: {os.getcwd()}")
print(f"Template folder: {app.template_folder}")
print(f"Template folder exists: {os.path.exists(app.template_folder)}")
print(f"Templates in folder: {os.listdir(app.template_folder) if os.path.exists(app.template_folder) else 'Folder not found'}")

# Authentik configuration
AUTHENTIK_URL = os.getenv('AUTHENTIK_URL')
CLIENT_ID = os.getenv('AUTHENTIK_CLIENT_ID')
CLIENT_SECRET = os.getenv('AUTHENTIK_CLIENT_SECRET')
REDIRECT_URI = 'http://localhost:5000/auth/callback'

# Authentik endpoints
AUTHORIZATION_ENDPOINT = f"{AUTHENTIK_URL}/application/o/authorize/"
TOKEN_ENDPOINT = f"{AUTHENTIK_URL}/application/o/token/"
USERINFO_ENDPOINT = f"{AUTHENTIK_URL}/application/o/userinfo/"

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_info):
        self.id = user_info.get('sub')
        self.email = user_info.get('email')
        self.name = user_info.get('name')
        self.groups = user_info.get('groups', [])
        self.roles = user_info.get('roles', [])
        self.user_info = user_info

    def has_role(self, role):
        """Check if user has a specific role"""
        if not self.roles:
            return False
        return role in self.roles

    def has_any_role(self, roles):
        """Check if user has any of the specified roles"""
        if not self.roles:
            return False
        return any(role in self.roles for role in roles)

    def has_group(self, group):
        """Check if user belongs to a specific group"""
        if not self.groups:
            return False
        return group in self.groups

@login_manager.user_loader
def load_user(user_id):
    """Load user from session"""
    if 'user_info' in session:
        return User(session['user_info'])
    return None

# Context processor to add variables to all templates
@app.context_processor
def inject_now():
    return {'now': datetime.datetime.now()}

# Role-based access control decorator
def role_required(role):
    """Decorator to require specific role to access a route"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if not current_user.has_role(role):
                return render_template('auth/unauthorized.html', role=role), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Group-based access control decorator
def group_required(group):
    """Decorator to require specific group to access a route"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if not current_user.has_group(group):
                return render_template('auth/unauthorized.html', group=group), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Any of the roles required decorator
def any_role_required(roles):
    """Decorator to require any of the specified roles to access a route"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if not current_user.has_any_role(roles):
                return render_template('auth/unauthorized.html', roles=roles), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/login')
def login():
    """Initiate SSO login process"""
    # Generate a unique state parameter to prevent CSRF attacks
    state = secrets.token_hex(16)
    session['oauth_state'] = state
    session.modified = True  # Ensure the session is saved
    
    # Build authorization URL
    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'openid email profile groups',
        'state': state
    }
    
    auth_url = f"{AUTHORIZATION_ENDPOINT}?{urlencode(params)}"
    logger.info(f"Redirecting to auth URL with state: {state}")
    logger.info(f"Session contains state: {session.get('oauth_state')}")
    
    # Create response with proper cookie settings
    response = make_response(redirect(auth_url))
    return response

@app.route('/auth/callback')
def callback():
    """Handle SSO callback"""
    # Log received state parameters for debugging
    received_state = request.args.get('state')
    session_state = session.get('oauth_state')
    logger.info(f"Callback received - State in request: {received_state}, State in session: {session_state}")
    logger.info(f"Session contains: {session.items()}")
    
    # Verify state parameter - with fallback for development
    if 'oauth_state' not in session:
        logger.error("No oauth_state found in session")
        # For development only - bypass state check if needed
        development_mode = os.getenv('FLASK_ENV') == 'development'
        if development_mode and os.getenv('BYPASS_STATE_CHECK', 'False').lower() == 'true':
            logger.warning("DEVELOPMENT MODE: Bypassing state check (NOT SECURE FOR PRODUCTION)")
        else:
            return 'Session expired or invalid session state. Please try logging in again.', 400
    elif received_state != session_state and not (os.getenv('FLASK_ENV') == 'development' and 
                                                os.getenv('BYPASS_STATE_CHECK', 'False').lower() == 'true'):
        logger.error(f"State mismatch: received {received_state}, expected {session_state}")
        return 'Invalid state parameter. This could be a CSRF attack or your session may have expired.', 400
    
    # Exchange authorization code for tokens
    if 'code' not in request.args:
        logger.error("No authorization code received")
        return 'No authorization code received', 400
    
    code = request.args.get('code')
    logger.info(f"Authorization code received: {code[:5]}...")
    
    # Exchange code for tokens
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    
    try:
        # Request tokens
        logger.info(f"Requesting tokens from {TOKEN_ENDPOINT}")
        token_response = requests.post(TOKEN_ENDPOINT, data=token_data)
        token_response.raise_for_status()
        token_info = token_response.json()
        
        # Get access token
        access_token = token_info.get('access_token')
        if not access_token:
            logger.error("No access token received")
            return 'Authentication failed', 401
        
        logger.info("Access token received successfully")
        
        # Get user information
        headers = {'Authorization': f"Bearer {access_token}"}
        logger.info(f"Requesting user info from {USERINFO_ENDPOINT}")
        userinfo_response = requests.get(USERINFO_ENDPOINT, headers=headers)
        userinfo_response.raise_for_status()
        user_info = userinfo_response.json()
        
        logger.info(f"User info received for: {user_info.get('email', 'unknown')}")
        
        # Extract groups/roles from user info
        # The actual attribute names might differ based on your Authentik configuration
        groups = user_info.get('groups', [])
        
        # Create custom roles based on groups if needed
        roles = []
        if 'admin' in groups or 'authentik Admins' in groups:
            roles.append('admin')
        if 'manager' in groups:
            roles.append('manager')
        # Default role for all authenticated users
        roles.append('user')
        
        # Add roles to user info
        user_info['roles'] = roles
        
        # Store user info in session
        session['user_info'] = user_info
        
        # Log in the user
        user = User(user_info)
        login_user(user)
        
        logger.info(f"User logged in successfully: {user.email}")
        
        # Clean up the state
        if 'oauth_state' in session:
            del session['oauth_state']
        
        # Redirect to the dashboard
        return redirect(url_for('dashboard'))
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during token exchange: {str(e)}")
        # More detailed error handling
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response status: {e.response.status_code}")
            logger.error(f"Response content: {e.response.text}")
        return f'Authentication failed: {str(e)}', 401

@app.route('/logout')
def logout():
    """Log out the user"""
    logout_user()
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page - accessible to all authenticated users"""
    if current_user.has_role('admin'):
        return render_template('dashboard/admin.html')
    else:
        return render_template('dashboard/user.html')

@app.route('/admin')
@role_required('admin')
def admin():
    """Admin page - accessible only to users with admin role"""
    return render_template('dashboard/admin.html')

@app.route('/manager')
@role_required('manager')
def manager():
    """Manager page - accessible only to users with manager role"""
    # Create a basic manager template since it's missing from your structure
    return render_template('dashboard/admin.html')  # Fallback to admin template

@app.route('/user-profile')
@login_required
def user_profile():
    """User profile page - accessible to all authenticated users"""
    return render_template('profile.html')

@app.route('/api/user-info')
@login_required
def api_user_info():
    """API endpoint to get user information"""
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify({
        'id': current_user.id,
        'email': current_user.email,
        'name': current_user.name,
        'roles': current_user.roles,
        'groups': current_user.groups
    })

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    # Try to use base.html since 404.html is missing
    return render_template('base.html', error_message="Page not found", error_code=404), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('auth/unauthorized.html'), 403

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true', host='0.0.0.0', port=5000)