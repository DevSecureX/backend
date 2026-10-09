#!/bin/bash

# Test secrets creation script for DevSecureX
# This script creates various test secrets that should trigger CRITICAL severity issues

echo "Creating test secrets for DevSecureX severity testing..."

# Create test directory
mkdir -p test-secrets
cd test-secrets

# Create JavaScript file with JWT token
cat > test.js << 'EOF'
const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const stripeKey = "sk_test_26PHem9AhJZvU623DfE1x4sd";
const apiKey = "AKIAIOSFODNN7EXAMPLE";
console.log("Application started");
EOF

# Create Python file with secrets
cat > config.py << 'EOF'
# Configuration file with various secrets
DATABASE_PASSWORD = "super_secret_password_123"
API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz123"
STRIPE_SECRET = "sk_live_1234567890abcdefghijklmnopqrstu"
GOOGLE_API_KEY = "AIzaSyBVWqvtg7Uev9z7wRXj8xE3G2A0B4zC5tD"
OAUTH_CLIENT_SECRET = "oauth_client_secret_abcdefghijklmnopqrstuvwxyz"
SESSION_SECRET = "my-super-secret-session-key-12345"
MONGODB_URI = "mongodb://admin:password123@localhost:27017/mydb"
JWT_SECRET = "jwt-secret-key-for-application-security"
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7yTKQJWKHy2GGGGHOPzSqEWXcZZz8zfnWz+abc123...
-----END RSA PRIVATE KEY-----"""
EOF

# Create .env file with environment variables
cat > .env << 'EOF'
DATABASE_URL=postgres://user:password123@localhost:5432/myapp
REDIS_PASSWORD=redis_secret_password_456
AWS_ACCESS_KEY_ID=AKIAI44QH8DHBEXAMPLE
AWS_SECRET_ACCESS_KEY=je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
STRIPE_PUBLISHABLE_KEY=pk_test_TYooMQauvdEDq54NiTphI7jx
STRIPE_SECRET_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc
GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456789
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
PAYPAL_CLIENT_SECRET=paypal_secret_abcdefghijklmnopqrstuvwxyz123
TWITTER_BEARER_TOKEN=twitter_bearer_token_1234567890abcdefghijklmnop
DISCORD_BOT_TOKEN=ODcxMjM0NTY3ODkwMTIzNDU2.YHabcd.1234567890abcdefghijklmnopqrstuvwxyz
EOF

# Create Docker file with secrets
cat > Dockerfile << 'EOF'
FROM node:14
WORKDIR /app
COPY . .

# Bad practice - secrets in Dockerfile
ENV API_KEY=sk_live_abcdefghijklmnopqrstuvwxyz123456
ENV DATABASE_PASSWORD=prod_password_12345
ENV JWT_SECRET=super-secret-jwt-key-production

RUN npm install
EXPOSE 3000
CMD ["npm", "start"]
EOF

# Create shell script with secrets
cat > deploy.sh << 'EOF'
#!/bin/bash
export DEPLOYMENT_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ..."
export ADMIN_PASSWORD="admin_secret_password_2023"
export ENCRYPTION_KEY="aes-256-encryption-key-abcdefghijklmnopqrstuvwxyz"

echo "Deploying application..."
EOF

# Create YAML config with secrets
cat > config.yaml << 'EOF'
database:
  host: localhost
  username: admin
  password: "yaml_secret_password_789"
  
api:
  key: "api_key_abcdefghijklmnopqrstuvwxyz123"
  secret: "api_secret_1234567890abcdefghijklmnopqrstu"
  
auth:
  jwt_secret: "jwt_secret_for_yaml_config_file"
  session_key: "session_secret_key_yaml_config"
  
third_party:
  stripe_key: "sk_test_yaml_stripe_key_example"
  google_client_secret: "google_oauth_client_secret_yaml"
EOF

# Create JSON config with secrets
cat > secrets.json << 'EOF'
{
  "database": {
    "password": "json_database_password_456",
    "connection_string": "Server=localhost;Database=myDB;User Id=sa;Password=json_secret_123;"
  },
  "api": {
    "key": "json_api_key_abcdefghijklmnopqrstuvwxyz",
    "token": "json_bearer_token_1234567890abcdef"
  },
  "secrets": {
    "encryption_key": "json_encryption_key_aes256_example",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7..."
  }
}
EOF

echo "✓ Test secrets created successfully!"
echo ""
echo "Files created with various critical secrets:"
echo "- test.js (JWT, Stripe, AWS keys)"
echo "- config.py (passwords, tokens, private keys)"
echo "- .env (environment variables with secrets)"
echo "- Dockerfile (hardcoded secrets)"
echo "- deploy.sh (deployment secrets)"
echo "- config.yaml (YAML configuration secrets)"
echo "- secrets.json (JSON configuration secrets)"
echo ""
echo "These files contain secrets that should trigger CRITICAL severity issues:"
echo "- JWT tokens"
echo "- API keys (Stripe, Google, GitHub, etc.)"
echo "- Database passwords"
echo "- Private keys"
echo "- OAuth secrets"
echo "- Bearer tokens"
echo ""
echo "Copy these files to your test repository and run a scan to verify critical issue detection."