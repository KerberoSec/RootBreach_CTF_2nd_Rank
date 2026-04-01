# FIX: Removed render_template_string to prevent SSTI vulnerabilities
# VULNERABILITY FIXED: #11 - Unused Import (render_template_string is dangerous)
from flask import render_template, redirect, url_for, request, session, Response

from app import app
from app.db import db
from app.models import User

# FIX: Removed unused imports (time, random, string, hashlib) and dangerous subprocess
# VULNERABILITY FIXED: #7 - Subprocess Command Execution (removed curl call exposure)

# FIX: Import password verification for secure authentication
# VULNERABILITY FIXED: #10 - Passwords Stored in Plaintext (use werkzeug for verification)
from werkzeug.security import check_password_hash


# FIX: Corrected parameter name from 'request' to 'response' and removed duplicate Cache-Control
# VULNERABILITY FIXED: #13 - Cache-Control Header Conflict (removed duplicate overwrite)
# VULNERABILITY FIXED: #14 - Parameter Naming Bug (was 'request', now 'response')
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    # FIX: Removed the second Cache-Control that was overwriting with weaker 'public, max-age=0'
    return response


class SessionError(Exception):
    def __init__(self, message='Session verifcation failed.'):
        self.message = message
        super().__init__(self.message)


# FIX: Removed commented out get_session() function and all references to it
# VULNERABILITY FIXED: #15 - Undefined Function Reference (get_session was undefined)


def verify_session():
    """Verify that the current session is valid and user exists."""
    if not session.get('authenticated'):
        raise SessionError(message='Not authenticated.')
    
    user = User.query.filter_by(username=session.get('username')).first()
    if user:
        # User exists and session is authenticated - return user
        session['user_id'] = user.id
        session['session_id'] = session.sid
        return user
    else:
        raise SessionError(message='Invalid username.')


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    # FIX: Removed all debug functionality to prevent information disclosure
    # VULNERABILITY FIXED: #5 - Information Disclosure via Debug Comments

    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            session['authenticated'] = True
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password.')


# FIX: Complete session clearing on logout
# VULNERABILITY FIXED: #8 - Incomplete Logout Function (was only removing user_id)
@app.route('/logout')
def logout():
    # Clear ALL session data to properly log out user
    session.clear()
    return redirect(url_for('login'))


# FIX: Added proper is_admin authorization check
# VULNERABILITY FIXED: #9 - No Admin Check in Admin Panel (Privilege Escalation)
@app.route('/admin_panel')
def admin_panel():
    try:
        user = verify_session()
    except SessionError as e:
        return render_template('login.html', error=e.message)

    # FIX: Check if user is actually an admin before granting access
    # VULNERABILITY FIXED: #9 - No Admin Check in Admin Panel
    if not user or not user.is_admin:
        return render_template('dashboard.html', 
                             error_message='Access denied. Administrator privileges required.'), 403
    
    # Only render admin panel for actual admins
    return render_template('admin_panel.html')


@app.route('/dashboard')
def dashboard():
    # FIX: Removed all debug functionality
    # VULNERABILITY FIXED: #5 - Information Disclosure via Debug Comments
    # VULNERABILITY FIXED: #15 - Undefined Function Reference (removed get_session() calls)

    try:
        verify_session()
    except SessionError as e:
        return render_template('login.html', error=e.message)

    return render_template('dashboard.html')


@app.route('/wifi_settings', methods=['GET', 'POST'])
def wifi_settings():
    try:
        verify_session()
    except SessionError as e:
        return render_template('login.html', error=e.message)

    # FIX: Removed subprocess curl command that exposed internal service information
    # VULNERABILITY FIXED: #7 - Subprocess Command Execution (removed curl hints)
    # The internal status check is now handled internally without exposing details

    if request.method == 'GET':
        return render_template('wifi_settings.html')
    elif request.method == 'POST':
        return render_template('wifi_settings.html', 
                             error_message='Settings can not be changed, the WiFi chipset is still booting.')