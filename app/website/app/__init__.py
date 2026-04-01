from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from app.db import db
from app.models import User

from flask_session.sqlalchemy import SqlAlchemySessionInterface
# FIX: Import CSRF protection to prevent Cross-Site Request Forgery attacks
# VULNERABILITY FIXED: #12 - Missing CSRF Protection
from flask_wtf.csrf import CSRFProtect
# FIX: Import password hashing utilities for secure password storage
# VULNERABILITY FIXED: #10 - Passwords Stored in Plaintext
from werkzeug.security import generate_password_hash

import secrets
import string


app = Flask(__name__)

# FIX: Use cryptographically secure random secret key instead of hardcoded value
# VULNERABILITY FIXED: #3 - Weak Secret Key (was 'your_secret_key')
app.secret_key = secrets.token_hex(32)

# FIX: Enable CSRF protection globally
# VULNERABILITY FIXED: #12 - Missing CSRF Protection
csrf = CSRFProtect(app)

# MySQL configurations - use localhost since all services run in one container
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:hrs_admin_router@localhost/database'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# FIX: Use READ COMMITTED instead of READ UNCOMMITTED to prevent dirty reads
# VULNERABILITY FIXED: #4 - Database Isolation Level (was READ UNCOMMITTED)
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'isolation_level': 'READ COMMITTED'}

# Create the database tables
db.init_app(app)
app.app_context().push()
db.create_all()


# Server-side Session
app.session_interface = SqlAlchemySessionInterface(app=app, client=db, table='mysessions')


# FIX: Removed hardcoded test:test credentials - only create admin user
# VULNERABILITY FIXED: #2 - Hardcoded Test Credentials (removed test:test account)
# Check if admin already exists in the database
admin = User.query.filter_by(username='admin').first()
if not admin:
    # Create an admin user with secure random password and hashed storage
    # FIX: Hash the password before storing
    # VULNERABILITY FIXED: #10 - Passwords Stored in Plaintext
    admin_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    admin = User(
        username='admin',
        password=generate_password_hash(admin_password),
        name='Administrator',
        lastname='',
        email='admin@example.com',
        is_admin=True
    )
    db.session.add(admin)
    db.session.commit()

# Include routes
from app import routes