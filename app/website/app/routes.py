"""
Flask Routes Module
===================

SECURITY FIXES APPLIED:
-----------------------
1. REMOVED DANGEROUS IMPORTS: Removed render_template_string (SSTI vulnerability)
   and subprocess (command injection risk)

2. INPUT VALIDATION: Added sanitize_input() and is_valid_username() functions
   - Prevents SQL injection, XSS, and other injection attacks
   - Enforces input length limits and format validation

3. SESSION SECURITY: 
   - Session fixation prevention (clear session on login)
   - Complete session clearing on logout
   - Proper session validation with user verification

4. AUTHORIZATION: Added admin check for admin_panel route
   - Prevents privilege escalation attacks

5. SECURITY HEADERS: Added comprehensive security headers
   - X-Content-Type-Options: nosniff (prevents MIME sniffing)
   - X-Frame-Options: SAMEORIGIN (prevents clickjacking)
   - X-XSS-Protection: 1; mode=block (XSS filter)
   - Referrer-Policy: strict-origin-when-cross-origin
   - Cache-Control: no-store (prevents sensitive data caching)

6. ERROR HANDLING: Generic error messages prevent user enumeration

7. PARAMETER NAMING BUG: Fixed @after_request parameter (was 'request', now 'response')
"""

from flask import render_template, redirect, url_for, request, session
from app import app
from app.db import db
from app.models import User
from werkzeug.security import check_password_hash
import re


# =============================================================================
# SECURITY FIX #5: Security Headers
# =============================================================================
# Added comprehensive security headers to all responses
@app.after_request
def add_security_headers(response):
    """
    Add security headers to all HTTP responses.
    
    FIXES APPLIED:
    - Parameter naming bug: Changed from 'request' to 'response'
    - Cache-Control conflict: Removed duplicate header that was overwriting
    - Added missing security headers
    """
    # ---------------------------------------------------------------------
    # Cache Control Headers
    # ---------------------------------------------------------------------
    # VULNERABILITY: Sensitive data could be cached by browsers/proxies
    # FIX: Prevent all caching of responses
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'  # HTTP/1.0 compatibility
    response.headers['Expires'] = '0'
    
    # ---------------------------------------------------------------------
    # Security Headers
    # ---------------------------------------------------------------------
    # X-Content-Type-Options: Prevents MIME type sniffing attacks
    # Without this, browsers might execute files as different content types
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # X-Frame-Options: Prevents clickjacking attacks
    # SAMEORIGIN allows framing only from same origin
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # X-XSS-Protection: Enables browser's XSS filter
    # mode=block stops page rendering if attack detected
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer-Policy: Controls referrer information sent with requests
    # strict-origin-when-cross-origin: Full URL for same-origin, origin only for cross-origin
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response


# =============================================================================
# SESSION ERROR HANDLING
# =============================================================================
class SessionError(Exception):
    """Custom exception for session-related errors."""
    def __init__(self, message='Session verification failed.'):
        self.message = message
        super().__init__(self.message)


# =============================================================================
# SECURITY FIX #3: Session Verification
# =============================================================================
def verify_session():
    """
    Verify that the current session is valid and user exists.
    
    SECURITY MEASURES:
    - Checks authentication flag
    - Validates username exists in session
    - Verifies user exists in database
    - Clears invalid sessions (prevents session fixation)
    
    Returns:
        User: The authenticated user object
        
    Raises:
        SessionError: If session is invalid or user not found
    """
    # Check if user is authenticated
    if not session.get('authenticated'):
        raise SessionError(message='Not authenticated.')
    
    # Validate username exists in session
    username = session.get('username')
    if not username:
        raise SessionError(message='Invalid session.')
    
    # Verify user exists in database
    user = User.query.filter_by(username=username).first()
    if user:
        session['user_id'] = user.id
        return user
    else:
        # SECURITY: Clear invalid session to prevent session fixation
        session.clear()
        raise SessionError(message='Invalid session.')


# =============================================================================
# SECURITY FIX #2: Input Validation Functions
# =============================================================================
def sanitize_input(value, max_length=100):
    """
    Sanitize user input to prevent injection attacks.
    
    SECURITY MEASURES:
    - Strips leading/trailing whitespace
    - Enforces maximum length limit
    - Converts to string to prevent type confusion
    
    Args:
        value: The input value to sanitize
        max_length: Maximum allowed length (default: 100)
        
    Returns:
        str: Sanitized string
    """
    if not value:
        return ''
    # Convert to string, strip whitespace, enforce length limit
    value = str(value).strip()[:max_length]
    return value


def is_valid_username(username):
    """
    Validate username format to prevent injection attacks.
    
    SECURITY MEASURES:
    - Only allows alphanumeric characters and underscores
    - Enforces length between 3-50 characters
    - Prevents SQL injection and XSS via username field
    
    Args:
        username: The username to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not username:
        return False
    # Only allow alphanumeric and underscore, 3-50 characters
    return bool(re.match(r'^[a-zA-Z0-9_]{3,50}$', username))


# =============================================================================
# ROUTES
# =============================================================================

@app.route('/')
def index():
    """Redirect root URL to login page."""
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle user login.
    
    SECURITY FIXES APPLIED:
    1. Input validation and sanitization
    2. Session fixation prevention (clear session before setting new values)
    3. Generic error messages (prevents user enumeration)
    4. Removed debug functionality that exposed sensitive information
    """
    # If already authenticated, redirect to dashboard
    if session.get('authenticated'):
        return redirect(url_for('dashboard'))
    
    if request.method == 'GET':
        return render_template('login.html')
    
    elif request.method == 'POST':
        # -----------------------------------------------------------------
        # SECURITY FIX #2: Input Validation
        # -----------------------------------------------------------------
        # Get and sanitize input to prevent injection attacks
        username = sanitize_input(request.form.get('username', ''), max_length=50)
        password = request.form.get('password', '')
        
        # Validate required fields
        if not username or not password:
            return render_template('login.html', error='Username and password are required.')
        
        # Validate username format (alphanumeric only)
        if not is_valid_username(username):
            return render_template('login.html', error='Invalid username format.')
        
        # -----------------------------------------------------------------
        # Authentication
        # -----------------------------------------------------------------
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # SECURITY FIX #3: Session Fixation Prevention
            # Clear existing session before creating new one
            session.clear()
            
            # Set new session values
            session['username'] = username
            session['authenticated'] = True
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            # SECURITY FIX #6: Generic error message
            # Don't reveal whether username exists (prevents enumeration)
            return render_template('login.html', error='Invalid username or password.')


@app.route('/logout')
def logout():
    """
    Handle user logout.
    
    SECURITY FIX: Complete Session Clearing
    VULNERABILITY: Previously only removed 'user_id', leaving session partially valid
    FIX: Clear ALL session data to fully invalidate the session
    """
    session.clear()
    return redirect(url_for('login'))


@app.route('/admin_panel')
def admin_panel():
    """
    Admin panel - requires administrator privileges.
    
    SECURITY FIX #4: Authorization Check
    VULNERABILITY: No admin check - any authenticated user could access admin panel
    RISK: Privilege escalation - regular users gain admin access
    FIX: Verify user.is_admin before granting access
    """
    # Verify session is valid
    try:
        user = verify_session()
    except SessionError as e:
        return render_template('login.html', error=e.message)

    # -----------------------------------------------------------------
    # SECURITY FIX #4: Admin Authorization Check
    # -----------------------------------------------------------------
    # Verify user has admin privileges
    if not user or not user.is_admin:
        return render_template('dashboard.html', 
                             error_message='Access denied. Administrator privileges required.'), 403
    
    # Only render admin panel for verified administrators
    return render_template('admin_panel.html')


@app.route('/dashboard')
def dashboard():
    """
    User dashboard - requires authentication.
    
    SECURITY FIXES:
    - Removed debug functionality that exposed session information
    - Removed undefined get_session() function calls
    """
    try:
        verify_session()
    except SessionError as e:
        return render_template('login.html', error=e.message)

    return render_template('dashboard.html')


@app.route('/wifi_settings', methods=['GET', 'POST'])
def wifi_settings():
    """
    WiFi settings page - requires authentication.
    
    SECURITY FIXES:
    1. Removed subprocess/curl command that exposed internal service information
    2. Added input validation for WiFi settings
    3. SSID format validation (prevents injection)
    """
    try:
        verify_session()
    except SessionError as e:
        return render_template('login.html', error=e.message)

    if request.method == 'GET':
        return render_template('wifi_settings.html')
    
    elif request.method == 'POST':
        # -----------------------------------------------------------------
        # SECURITY: Input Validation for WiFi Settings
        # -----------------------------------------------------------------
        ssid = sanitize_input(request.form.get('ssid', ''), max_length=32)
        security = sanitize_input(request.form.get('security', ''), max_length=50)
        
        # Validate SSID format (alphanumeric, spaces, hyphens only)
        if ssid and not re.match(r'^[\w\s\-]{1,32}$', ssid):
            return render_template('wifi_settings.html', 
                                 error_message='Invalid SSID format.')
        
        # NOTE: Actual WiFi configuration is disabled (chipset booting)
        return render_template('wifi_settings.html', 
                             error_message='Settings cannot be changed, the WiFi chipset is still booting.')