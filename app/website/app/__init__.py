"""
Flask Application Initialization
================================

SECURITY FIXES APPLIED:
-----------------------
1. SECRET_KEY: Changed from hardcoded 'your_secret_key' to cryptographically secure random key
   - Vulnerability: Weak/predictable secret key allows session forgery
   - Fix: Using secrets.token_hex(32) for 256-bit entropy

2. SESSION CONFIGURATION: Implemented server-side sessions with SQLAlchemy
   - Vulnerability: Client-side sessions can be tampered with
   - Fix: Store sessions in database, use signed cookies
   - Added: HTTPOnly, SameSite cookie attributes for XSS/CSRF protection

3. CSRF PROTECTION: Enabled Flask-WTF CSRF protection globally
   - Vulnerability: Cross-Site Request Forgery attacks
   - Fix: CSRFProtect validates tokens on all POST requests
   - Added: 1-hour token validity limit

4. PASSWORD STORAGE: Using Werkzeug's password hashing
   - Vulnerability: Plaintext password storage
   - Fix: generate_password_hash() with PBKDF2-SHA256

5. DATABASE ISOLATION: Changed to READ COMMITTED isolation level
   - Vulnerability: READ UNCOMMITTED allows dirty reads
   - Fix: READ COMMITTED prevents reading uncommitted transactions

6. INITIALIZATION ORDER: Fixed extension initialization sequence
   - Bug: CSRF was initialized before Session, causing token errors
   - Fix: Database -> Session -> CSRF (correct order)
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from app.db import db
from app.models import User

from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash

import secrets
import os


app = Flask(__name__)

# =============================================================================
# SECURITY FIX #1: Secure Secret Key
# =============================================================================
# VULNERABILITY: Hardcoded secret key 'your_secret_key' is predictable
# RISK: Attackers can forge session cookies and bypass authentication
# FIX: Use cryptographically secure random key (256-bit entropy)
# PRODUCTION: Set SECRET_KEY environment variable
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:hrs_admin_router@localhost/database'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SECURITY FIX #5: Database Isolation Level
# VULNERABILITY: READ UNCOMMITTED allows dirty reads (reading uncommitted data)
# RISK: Data inconsistency, potential information disclosure
# FIX: READ COMMITTED ensures only committed data is readable
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'isolation_level': 'READ COMMITTED'}

# Initialize database
db.init_app(app)

# =============================================================================
# SECURITY FIX #2: Server-Side Session Configuration
# =============================================================================
# VULNERABILITY: Default Flask sessions store data client-side (can be tampered)
# FIX: Store sessions server-side in database
# 
# SESSION_TYPE: 'sqlalchemy' - Store in database
# SESSION_COOKIE_HTTPONLY: True - Prevents JavaScript access (XSS protection)
# SESSION_COOKIE_SAMESITE: 'Lax' - CSRF protection for cross-site requests
# SESSION_USE_SIGNER: True - Cryptographically sign session ID
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_SQLALCHEMY_TABLE'] = 'sessions'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent XSS access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
# NOTE: In production with HTTPS, also set: SESSION_COOKIE_SECURE = True

# =============================================================================
# SECURITY FIX #3: CSRF Protection Configuration
# =============================================================================
# VULNERABILITY: Missing CSRF protection allows cross-site request forgery
# RISK: Attackers can trick users into performing unwanted actions
# FIX: Enable WTF-Forms CSRF protection with time-limited tokens
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # Token valid for 1 hour

# =============================================================================
# SECURITY FIX #6: Correct Extension Initialization Order
# =============================================================================
# BUG: CSRF was initialized before Session, causing "CSRF session token missing"
# FIX: Initialize in correct order: Database -> Tables -> Session -> CSRF
with app.app_context():
    db.create_all()  # Create database tables first
    Session(app)     # Initialize session (must be before CSRF)

# Initialize CSRF protection AFTER session is configured
csrf = CSRFProtect(app)

# =============================================================================
# DEFAULT USER CREATION
# =============================================================================
# SECURITY FIX #4: Password Hashing
# VULNERABILITY: Passwords were stored in plaintext
# FIX: Use Werkzeug's generate_password_hash (PBKDF2-SHA256 by default)
#
# NOTE: These are TEST credentials. In production:
# - Use strong, unique passwords
# - Store credentials securely (not in code)
# - Consider environment variables or secrets management
with app.app_context():
    # Create admin user if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            password=generate_password_hash('admin123'),  # Hashed, not plaintext
            name='Administrator',
            lastname='',
            email='admin@example.com',
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

    # Create regular test user if not exists
    test_user = User.query.filter_by(username='user').first()
    if not test_user:
        test_user = User(
            username='user',
            password=generate_password_hash('user123'),  # Hashed, not plaintext
            name='Test',
            lastname='User',
            email='user@example.com',
            is_admin=False
        )
        db.session.add(test_user)
        db.session.commit()

# Import routes (must be at end to avoid circular imports)
from app import routes