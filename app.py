import os
import json
import secrets
import logging
import datetime
from flask import Flask, redirect, request, url_for, session, render_template, jsonify, make_response, Response
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
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') != 'development'  # True in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=1)

# Initialize Flask-Session
Session(app)

# Try to set up Redis for state backup - but don't rely on it for critical functionality
try:
    import redis
    redis_client = redis.Redis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        db=0,
        socket_timeout=1
    )
    # Test the connection
    redis_client.ping()
    REDIS_AVAILABLE = True
    logger.info("Redis connection established - using for state backup")
except Exception as e:
    REDIS_AVAILABLE = False
    logger.warning(f"Redis not available - falling back to session-only state storage: {str(e)}")

# Debug information about template paths
if os.getenv('FLASK_DEBUG', 'False').lower() == 'true':
    print(f"Current working directory: {os.getcwd()}")
    print(f"Template folder: {app.template_folder}")
    print(f"Template folder exists: {os.path.exists(app.template_folder)}")
    print(f"Templates in folder: {os.listdir(app.template_folder) if os.path.exists(app.template_folder) else 'Folder not found'}")

# Authentik configuration - ensure all required variables are present
AUTHENTIK_URL = os.getenv('AUTHENTIK_URL')
CLIENT_ID = os.getenv('AUTHENTIK_CLIENT_ID')
CLIENT_SECRET = os.getenv('AUTHENTIK_CLIENT_SECRET')
REDIRECT_URI = os.getenv('REDIRECT_URI', 'http://localhost:5000/auth/callback')

# Check for required configuration
if not all([AUTHENTIK_URL, CLIENT_ID, CLIENT_SECRET]):
    logger.error("Missing required OAuth configuration. Check AUTHENTIK_URL, CLIENT_ID, CLIENT_SECRET environment variables.")

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

# Debug middleware to log session information in debug mode only
@app.before_request
def before_request():
    """Log session information before each request"""
    if os.getenv('FLASK_DEBUG', 'False').lower() == 'true':
        logger.debug(f"Session before request: {dict(session)}")
        logger.debug(f"Request path: {request.path}")
        logger.debug(f"Request cookies: {request.cookies}")

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

def generate_random_state(length=32):
    """Generate a secure random state string for OAuth"""
    return secrets.token_urlsafe(length)

# Helper function to store state in session only
def store_oauth_state(state):
    """Store OAuth state primarily in session with Redis backup"""
    # Store in session
    session['oauth_state'] = state
    session.modified = True
    
    # Also store in Redis if available (as backup only)
    if REDIS_AVAILABLE:
        try:
            redis_client.setex(f"oauth_state:{state}", 600, "1")  # Expire after 10 minutes
            logger.debug(f"State {state} stored in Redis as backup")
        except Exception as e:
            logger.error(f"Failed to store state in Redis: {str(e)}")
    
    logger.info(f"OAuth state stored: {state[:5]}...")  # Only log first few chars for security

# Helper function to verify state
def verify_oauth_state(received_state):
    """Verify OAuth state from session with Redis fallback"""
    if not received_state:
        logger.error("No state received in callback")
        return False
        
    session_state = session.get('oauth_state')
    # Log partial state info for debugging without exposing full tokens
    logger.info(f"Verifying state - Received: {received_state[:5]}..., Session: {session_state[:5] if session_state else 'None'}...")
    
    # Check session state (primary method)
    if session_state and received_state == session_state:
        logger.info("State verified from session")
        return True
    
    # If session state check failed, try Redis backup
    if REDIS_AVAILABLE and received_state:
        try:
            redis_key = f"oauth_state:{received_state}"
            if redis_client.exists(redis_key):
                logger.info("State verified from Redis backup")
                redis_client.delete(redis_key)  # Clean up after use
                return True
        except Exception as e:
            logger.error(f"Redis state verification failed: {str(e)}")
    
    # Development bypass - ONLY if explicitly enabled AND in development mode
    if (os.getenv('FLASK_ENV') == 'development' and 
        os.getenv('BYPASS_STATE_CHECK', 'False').lower() == 'true'):
        logger.warning("DEVELOPMENT MODE: Bypassing state check (NOT SECURE FOR PRODUCTION)")
        return True
    
    logger.error("State verification failed")
    return False

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/login')
def login():
    """Initiate SSO login process"""
    return redirect(url_for('login_secure'))

@app.route('/login/secure')
def login_secure():
    """Start secure OAuth flow with proper state management"""
    # Validate required configuration is present
    if not all([AUTHENTIK_URL, CLIENT_ID, CLIENT_SECRET]):
        logger.error("OAuth configuration missing")
        return render_template('base.html', 
                            error_message="Authentication system is not properly configured. Please contact administrators.", 
                            error_code=500), 500
    
    # Generate and store state
    state = generate_random_state()
    store_oauth_state(state)
    
    # Build authorization URL with correct parameters
    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'state': state,
        'scope': 'openid email profile'
    }
    
    auth_url = f"{AUTHORIZATION_ENDPOINT}?{urlencode(params)}"
    logger.info(f"Redirecting to authorization endpoint: {AUTHORIZATION_ENDPOINT}")
    
    return redirect(auth_url)

# Consolidated callback route
@app.route('/auth/callback')
def callback():
    """Handle OAuth callback with proper state verification"""
    received_state = request.args.get('state')
    code = request.args.get('code')
    
    # Validate we received both state and code
    if not code:
        logger.error("No authorization code received")
        return render_template('base.html', error_message="Authentication failed: No authorization code received", error_code=400), 400
    
    # Verify state to prevent CSRF
    if not verify_oauth_state(received_state):
        logger.error("State verification failed")
        return render_template('base.html', 
                            error_message="Authentication failed: Invalid state parameter. Please try logging in again.", 
                            error_code=400), 400
    
    # Exchange authorization code for tokens
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    
    try:
        # Request tokens
        logger.info(f"Exchanging code for token at: {TOKEN_ENDPOINT}")
        token_response = requests.post(TOKEN_ENDPOINT, data=token_data)
        token_response.raise_for_status()
        token_info = token_response.json()
        
        # Get access token
        access_token = token_info.get('access_token')
        if not access_token:
            logger.error("No access token received")
            return render_template('base.html', error_message="Authentication failed: No access token received", error_code=401), 401
        
        # Get user information
        headers = {'Authorization': f"Bearer {access_token}"}
        logger.info(f"Fetching user info from: {USERINFO_ENDPOINT}")
        userinfo_response = requests.get(USERINFO_ENDPOINT, headers=headers)
        userinfo_response.raise_for_status()
        user_info = userinfo_response.json()
        
        # Process user info and assign roles
        groups = user_info.get('groups', [])
        roles = []
        
        # Assign roles based on groups
        if isinstance(groups, list):
            if any(g in groups for g in ['admin', 'authentik Admins']):
                roles.append('admin')
            if 'manager' in groups:
                roles.append('manager')
        # Always add basic user role
        roles.append('user')
        
        user_info['roles'] = roles
        session['user_info'] = user_info
        
        # Log in the user
        user = User(user_info)
        login_user(user)
        logger.info(f"User authenticated: {user.email}")
        
        # Redirect to dashboard or a requested page
        next_page = session.get('next', None)
        if next_page:
            del session['next']
            return redirect(next_page)
        return redirect(url_for('dashboard'))
        
    except requests.RequestException as e:
        logger.error(f"OAuth request error: {str(e)}")
        return render_template('base.html', 
                             error_message="Authentication failed: Error communicating with authentication server", 
                             error_code=401), 401
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return render_template('base.html', error_message="Authentication failed", error_code=401), 401

@app.route('/logout')
def logout():
    """Log out the user"""
    if current_user.is_authenticated:
        logger.info(f"User logged out: {current_user.email}")
    logout_user()
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page - accessible to all authenticated users"""
    if current_user.has_role('admin'):
        return render_template('dashboard/admin.html')
    elif current_user.has_role('manager'):
        return render_template('dashboard/admin.html')  # Fallback to admin template for managers
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

# Development-only routes
if os.getenv('FLASK_ENV') == 'development':
    # Route to test session functionality
    @app.route('/test-session')
    def test_session():
        """Test route to verify session functionality"""
        count = session.get('count', 0)
        count += 1
        session['count'] = count
        session.modified = True
        
        return jsonify({
            'count': count,
            'session_id': session.sid if hasattr(session, 'sid') else 'No SID',
            'session_data': dict(session)
        })

    # Add a debug route to show safe environment variables
    @app.route('/debug/env')
    def debug_env():
        """Debug route to show environment variables (only in development)"""
        # Only show a subset of environment variables for security
        safe_env = {
            'FLASK_ENV': os.getenv('FLASK_ENV'),
            'FLASK_DEBUG': os.getenv('FLASK_DEBUG'),
            'REDIRECT_URI': REDIRECT_URI,
            'SESSION_TYPE': app.config.get('SESSION_TYPE'),
            'REDIS_AVAILABLE': REDIS_AVAILABLE
        }
        
        return jsonify(safe_env)

# Add a route to check auth state
@app.route('/auth-status')
def auth_status():
    """Check authentication status"""
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'user': {
                'email': current_user.email,
                'name': current_user.name,
                'roles': current_user.roles
            }
        })
    else:
        return jsonify({
            'authenticated': False
        })

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    # Try to use base.html since 404.html is missing
    return render_template('base.html', error_message="Page not found", error_code=404), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('auth/unauthorized.html'), 403

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}")
    return render_template('base.html', error_message="Internal server error", error_code=500), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Make sure we're not using debug mode in production
    if os.getenv('FLASK_ENV') == 'production' and debug:
        logger.warning("Debug mode enabled in production environment! This is a security risk.")
        debug = False
    
    app.run(debug=debug, host='0.0.0.0', port=port)