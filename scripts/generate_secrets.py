#!/usr/bin/env python3
"""
Secret generation utility for DevSecureX deployment
Generates secure random keys for production deployment
"""

import secrets
import base64
from cryptography.fernet import Fernet

def generate_secret_key(length: int = 32) -> str:
    """Generate a secure random secret key"""
    return secrets.token_hex(length)

def generate_encryption_key() -> str:
    """Generate a Fernet encryption key"""
    return Fernet.generate_key().decode()

def generate_jwt_secret() -> str:
    """Generate a JWT secret key"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()

def main():
    print("🔐 DevSecureX Secret Generator")
    print("=" * 40)
    print()
    
    print("📝 Copy these values to your Render environment variables:")
    print()
    
    # Generate SECRET_KEY
    secret_key = generate_secret_key()
    print(f"SECRET_KEY={secret_key}")
    
    # Generate ENCRYPTION_KEY
    encryption_key = generate_encryption_key()
    print(f"ENCRYPTION_KEY={encryption_key}")
    
    # Generate additional JWT secret (if needed)
    jwt_secret = generate_jwt_secret()
    print(f"JWT_SECRET={jwt_secret}")
    
    print()
    print("🔒 Security Notes:")
    print("- Store these keys securely in Render environment variables")  
    print("- Never commit these keys to version control")
    print("- Rotate keys periodically for security")
    print("- Each environment (staging/prod) should have different keys")
    
    print()
    print("📋 Render Setup Instructions:")
    print("1. Go to https://dashboard.render.com")
    print("2. Select your service")
    print("3. Go to Environment tab")
    print("4. Add each key as a new environment variable")
    print("5. Click 'Save Changes' to redeploy")

if __name__ == "__main__":
    main()