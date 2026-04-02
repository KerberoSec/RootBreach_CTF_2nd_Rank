"""
User Model
==========

Defines the User database model for authentication and authorization.

SECURITY CONSIDERATIONS:
------------------------
1. PASSWORD FIELD: Stores hashed passwords (not plaintext)
   - Use werkzeug.security.generate_password_hash() to hash
   - Use werkzeug.security.check_password_hash() to verify
   - Field size 255 to accommodate hash output

2. IS_ADMIN FLAG: Used for authorization checks
   - Default is False (principle of least privilege)
   - Must explicitly set True for admin users
"""

from flask_sqlalchemy import SQLAlchemy
from app.db import db


class User(db.Model):
    """
    User model for authentication and authorization.
    
    Attributes:
        id: Primary key
        username: Unique username (3-50 alphanumeric chars)
        password: Hashed password (NEVER store plaintext)
        name: User's first name
        lastname: User's last name
        email: User's email address
        is_admin: Boolean flag for admin privileges (default: False)
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    # Password field stores HASHED password, not plaintext
    # Size 255 to accommodate bcrypt/PBKDF2 hash output
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    # SECURITY: Default to False (principle of least privilege)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)