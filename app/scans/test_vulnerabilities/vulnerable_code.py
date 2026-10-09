# Vulnerable Python Code for Bandit Testing
# This file contains intentional security vulnerabilities for testing purposes
# DO NOT USE IN PRODUCTION

import os
import pickle
import subprocess
import hashlib
import random
import tempfile
import yaml

# B105: hardcoded_password_string
PASSWORD = "admin123"
SECRET_KEY = "sk-1234567890abcdef"
API_TOKEN = "token_abc123xyz789"

# B108: hardcoded_bind_all_interfaces
def start_server():
    # Binding to all interfaces - security risk
    host = "0.0.0.0"
    return host

# B102: exec_used
def execute_code(user_input):
    # Direct execution of user input - code injection
    exec(user_input)

# B301: pickle usage
def load_data(data):
    # Unsafe deserialization
    return pickle.loads(data)

# B602: subprocess_popen_with_shell_equals_true
def run_command(command):
    # Shell injection vulnerability
    subprocess.Popen(command, shell=True)

# B608: possible_sql_injection
def get_user(username):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return query

# B303: md5_insecure_hash
def hash_password(password):
    # Using insecure MD5 hash
    return hashlib.md5(password.encode()).hexdigest()

# B311: random_module_for_security
def generate_token():
    # Using insecure random for security purposes
    return str(random.randint(100000, 999999))

# B107: hardcoded_password_default
def connect_db(password="defaultpassword"):
    return f"Connected with {password}"

# B506: yaml_load_unsafe
def load_config(config_data):
    # Unsafe YAML loading
    return yaml.load(config_data)

# B608: hardcoded_sql_expressions
def delete_user():
    sql = "DELETE FROM users WHERE admin = 1"
    return sql

# B324: hashlib_new_insecure_functions
def weak_hash(data):
    # Using weak hash function
    return hashlib.new('md5', data.encode()).hexdigest()

# B322: input_function_usage (Python 2 style)
def get_user_input():
    # This would be flagged in Python 2 context
    return input("Enter command: ")

# B201: flask_debug_true (if Flask was imported)
# DEBUG = True

# B601: paramiko_calls (if paramiko was imported)
# client.exec_command(user_command)

# B504: ssl_with_bad_defaults (if ssl was imported)
# ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1)

# B609: linux_commands_wildcard_injection
def backup_files(path):
    cmd = f"tar -czf backup.tar.gz {path}/*"
    os.system(cmd)

# B110: try_except_pass
def risky_operation():
    try:
        # Some risky operation
        1 / 0
    except:
        pass  # Silent failure

# B112: try_except_continue
def process_items(items):
    for item in items:
        try:
            process_item(item)
        except:
            continue  # Silent failure

def process_item(item):
    pass

# B313: xml_bad_cElementTree (if xml was imported)
# import xml.etree.cElementTree as ET
# ET.parse(untrusted_xml)

# B320: xml_bad_expatreader (if xml.sax was imported)
# from xml.sax import expatreader
# expatreader.create_parser()

# B405: import_xml_etree (if imported)
# import xml.etree.ElementTree

# B406: import_xml_sax (if imported)  
# import xml.sax

# B407: import_xml_expat (if imported)
# import xml.expat

# B408: import_xml_xmlrpc (if imported)
# import xmlrpclib

# B409: import_xml_expatreader (if imported)
# import xml.sax.expatreader

# B410: import_xml_expatbuilder (if imported)
# import xml.dom.expatbuilder

# Temporary file creation without secure permissions
def create_temp_file():
    # B108: hardcoded temp file usage
    temp_file = "/tmp/sensitive_data.txt"
    with open(temp_file, 'w') as f:
        f.write(SECRET_KEY)
    return temp_file

# B506: yaml_load_unsafe - more examples
def parse_yaml_config(yaml_string):
    # Unsafe YAML parsing
    config = yaml.load(yaml_string)
    return config

# B703: django_mark_safe (if Django was imported)
# from django.utils.safestring import mark_safe
# def render_template(user_data):
#     return mark_safe(user_data)

if __name__ == "__main__":
    # Test functions with vulnerable code
    print("Testing vulnerable functions...")
    
    # These would trigger various Bandit warnings
    server_host = start_server()
    token = generate_token()
    hashed = hash_password("test123")
    
    print(f"Server: {server_host}, Token: {token}, Hash: {hashed}")