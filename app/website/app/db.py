"""
Database Configuration Module
=============================

This module initializes the SQLAlchemy database instance.
The instance is configured in __init__.py with proper security settings.

SECURITY CONFIGURATION (applied in __init__.py):
------------------------------------------------
1. DATABASE ISOLATION LEVEL: READ COMMITTED
   - Prevents dirty reads (reading uncommitted transactions)
   - Default was READ UNCOMMITTED which is insecure

2. CONNECTION SECURITY:
   - Uses localhost connection (services in same container)
   - Credentials stored in config (should use env vars in production)
"""

from flask_sqlalchemy import SQLAlchemy

# SQLAlchemy instance - configured with app in __init__.py
db = SQLAlchemy()