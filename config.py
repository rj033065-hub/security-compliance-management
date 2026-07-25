import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Flask Secret Key - change in production
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'security-compliance-secret-key-2026-enterprise-secure'
    
    # Database: defaults to SQLite, supports MySQL via DATABASE_URL env var
    # MySQL example: mysql+pymysql://root:password@localhost/security_compliance_db
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f"sqlite:///{os.path.join(BASE_DIR, 'security_compliance.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1-hour inactivity timeout
    
    # File uploads
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'docx', 'doc', 'txt'}

    # Default Super Admin credentials (change after first login!)
    DEFAULT_SUPERADMIN_EMAIL = 'superadmin@compliance.com'
    DEFAULT_SUPERADMIN_PASSWORD = 'Admin@123'
    DEFAULT_SUPERADMIN_NAME = 'Super Administrator'
