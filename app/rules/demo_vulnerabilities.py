#!/usr/bin/env python3
"""
Demo script showing vulnerabilities that our enhanced rules can detect
This file intentionally contains security vulnerabilities for testing
DO NOT USE THIS CODE IN PRODUCTION
"""

# AI/ML Vulnerabilities
import torch
import numpy as np
from transformers import AutoModel

# 1. Unsafe model loading (ai.yaml: insecure-model-loading)
model = torch.load('model.pth')  # Vulnerable to arbitrary code execution

# 2. Pickle vulnerability (ai.yaml: pickles-in-numpy)
data = np.load('data.npy', allow_pickle=True)  # Dangerous pickle loading

# 3. Unsafe transformers (ai_enhanced.yaml: unsafe-transformers-deserialization)
model = AutoModel.from_pretrained("bert-base", trust_remote_code=True)  # Remote code execution

# 4. LLM API key exposure (ai_enhanced.yaml: wandb-api-key-exposure)
import os
os.environ["WANDB_API_KEY"] = "secret123"  # API key in code

# Web3 Vulnerabilities
from web3 import Web3

# 5. Private key in frontend (web3.yaml: private-key-in-frontend)
private_key = "0x1234567890abcdef"  # Never do this!

# 6. Missing chain ID validation (web3.yaml: missing-chain-id-validation)
def send_transaction(provider, tx):
    provider.send("eth_sendTransaction", tx)  # No chain validation

# API Security Vulnerabilities

# 7. SQL Injection (api_security.yaml: sql-injection-api)
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id  # SQL injection
    return query

# 8. JWT with weak secret (api_security.yaml: jwt-weak-secret)
import jwt
token = jwt.encode({"user": "admin"}, "secret123", algorithm="HS256")  # Weak secret

# 9. GraphQL without depth limit (api_security.yaml: graphql-depth-limit-missing)
from graphql import GraphQLSchema
schema = GraphQLSchema(
    query=None  # No depth limiting
)

# Cloud Native Vulnerabilities

# 10. Hardcoded AWS credentials (cloud_native.yaml would detect in YAML)
aws_config = {
    "access_key": "AKIAIOSFODNN7EXAMPLE",  # Hardcoded credentials
    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# IoT/Embedded Vulnerabilities (C code example)
c_code_example = """
// 11. Buffer overflow (iot.yaml: insecure-strcpy)
void vulnerable_function(char* input) {
    char buffer[100];
    strcpy(buffer, input);  // Buffer overflow vulnerability
}

// 12. Format string (iot_enhanced.yaml: format-string-vulnerability)
void log_message(char* msg) {
    printf(msg);  // Format string vulnerability
}
"""

# Blockchain Vulnerabilities (Solidity example)
solidity_example = """
// 13. Reentrancy (blockchain.yaml: compound-borrowfresh-reentrancy)
function borrowFresh(uint amount) external {
    msg.sender.call{value: amount}("");  // External call
    totalBorrows = totalBorrows + amount;  // State change after
}

// 14. Unprotected selfdestruct (blockchain_enhanced.yaml: unprotected-selfdestruct)
function destroy() public {
    selfdestruct(payable(msg.sender));  // No access control
}
"""

# More AI vulnerabilities

# 15. Differential privacy leak (ai_enhanced.yaml: differential-privacy-leak)
from opacus import PrivacyEngine
privacy_engine = PrivacyEngine()
model = privacy_engine.make_private(
    model,
    target_epsilon=15.0,  # Too high! Should be < 10
    target_delta=1e-5
)

# 16. Federated learning without robustness (ai_enhanced.yaml: federated-learning-poisoning)
def fedavg(gradients):
    return sum(gradients) / len(gradients)  # No Byzantine robustness

# 17. Shadow AI usage (ai.yaml: unauthorized-llm-usage)
import openai
openai.ChatCompletion.create(model="gpt-4", messages=[])  # Unauthorized AI

# API Security

# 18. NoSQL Injection (api_security.yaml: nosql-injection)
def find_user(user_input):
    return collection.find({"$where": user_input})  # NoSQL injection

# 19. CORS wildcard (api_security.yaml: cors-allow-all-origins)
from flask_cors import CORS
CORS(app, origins="*")  # Allows any origin

# 20. Missing rate limiting (api_security.yaml: missing-rate-limiting)
@app.route("/api/data")
def get_data():
    return {"data": "sensitive"}  # No rate limiting

print("This file contains 20+ vulnerabilities that DevSecureX can detect!")
print("Our rules cover:")
print("- AI/ML security (model poisoning, privacy attacks)")
print("- Blockchain vulnerabilities (reentrancy, access control)")
print("- Web3 frontend issues (key exposure, transaction security)")
print("- API security (injection, authentication)")
print("- Cloud native (secrets, misconfigurations)")
print("- IoT/Embedded (memory corruption, firmware security)")