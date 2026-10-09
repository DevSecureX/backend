# Vulnerable Ruby Code for Brakeman Testing
# This file contains intentional security vulnerabilities for testing purposes
# DO NOT USE IN PRODUCTION

require 'digest'
require 'yaml'
require 'open3'
require 'fileutils'
require 'net/http'
require 'json'
require 'erb'
require 'cgi'

# Hardcoded credentials - should be detected by Brakeman
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
DATABASE_PASSWORD = "admin123"
JWT_SECRET = "my-super-secret-jwt-key-12345"
ENCRYPTION_KEY = "1234567890abcdef"

class VulnerableRubyApp
  attr_accessor :users
  
  def initialize
    @users = {}
  end

  # SQL injection vulnerability
  def get_user_by_name(username)
    # Direct string interpolation in SQL - SQL injection vulnerability
    query = "SELECT * FROM users WHERE username = '#{username}'"  # VULNERABILITY: SQL injection
    # This would be executed against a database
    puts "Executing query: #{query}"
    query
  end

  # Command injection vulnerability
  def execute_user_command(user_input)
    # Direct execution of user input - command injection
    system("ls #{user_input}")  # VULNERABILITY: Command injection
  end

  # Another command injection pattern
  def backup_directory(directory)
    # Using backticks with user input
    result = `tar -czf backup.tar.gz #{directory}/*`  # VULNERABILITY: Command injection
    puts result
  end

  # Code injection via eval
  def execute_user_code(user_code)
    # Using eval with user input - code injection
    eval(user_code)  # VULNERABILITY: Code injection
  end

  # YAML deserialization vulnerability
  def load_user_config(yaml_data)
    # Unsafe YAML loading
    config = YAML.load(yaml_data)  # VULNERABILITY: Unsafe deserialization
    config
  end

  # File path injection
  def read_user_file(filename)
    # Reading files without path validation
    file_path = File.join("/uploads", filename)
    File.read(file_path)  # VULNERABILITY: Path traversal
  end

  # Mass assignment vulnerability
  def update_user_attributes(params)
    user = User.new
    # Mass assignment without protection
    params.each do |key, value|
      user.send("#{key}=", value)  # VULNERABILITY: Mass assignment
    end
    user
  end

  # XSS vulnerability through ERB template
  def render_user_content(user_content)
    # Direct rendering of user content without escaping
    template = ERB.new("<html><body>Content: <%= content %></body></html>")
    template.result(binding { content = user_content })  # VULNERABILITY: XSS
  end

  # Weak cryptographic hash
  def hash_password(password)
    # Using MD5 for password hashing - weak cryptography
    Digest::MD5.hexdigest(password)  # VULNERABILITY: Weak hash function
  end

  # Insecure random number generation for security purposes
  def generate_session_id
    # Using predictable random for session IDs
    "session_#{rand(999999)}"  # VULNERABILITY: Weak randomness
  end

  # Open redirect vulnerability
  def redirect_user(url)
    # Redirecting without URL validation
    redirect_to url  # VULNERABILITY: Open redirect (in Rails context)
  end

  # Cross-site scripting via JSON
  def render_user_data_as_json(user_data)
    # Rendering user data without proper escaping
    "<script>var userData = #{user_data.to_json};</script>"  # VULNERABILITY: XSS
  end

  # File inclusion vulnerability
  def include_user_template(template_name)
    # Including files based on user input
    require "./templates/#{template_name}"  # VULNERABILITY: File inclusion
  end

  # Insecure direct object reference
  def get_user_profile(user_id)
    # Direct access without authorization check
    @users[user_id]  # VULNERABILITY: Insecure direct object reference
  end

  # LDAP injection vulnerability
  def authenticate_ldap_user(username, password)
    # LDAP query without proper escaping
    filter = "(&(uid=#{username})(userPassword=#{password}))"  # VULNERABILITY: LDAP injection
    puts "LDAP Filter: #{filter}"
  end

  # Regular expression DoS (ReDoS)
  def validate_input_with_regex(input)
    # Vulnerable regex pattern
    regex = /^(a+)+$/
    input.match?(regex)  # VULNERABILITY: ReDoS
  end

  # Information disclosure through error messages
  def process_sensitive_file(filename)
    File.read("/etc/secrets/#{filename}")  # VULNERABILITY: Information disclosure
  rescue => e
    raise "Error processing #{filename}: #{e.message}"  # Exposing internal paths
  end

  # Timing attack vulnerability
  def compare_secrets(user_secret, actual_secret)
    # Vulnerable to timing attacks
    user_secret == actual_secret  # VULNERABILITY: Timing attack
  end

  # Insecure cookie handling (Rails context)
  def set_user_cookie(value)
    # Cookie without secure flags
    cookies[:user_id] = value  # VULNERABILITY: Insecure cookie
  end

  # Dynamic method calls
  def call_user_method(method_name, *args)
    # Calling methods based on user input
    self.send(method_name, *args)  # VULNERABILITY: Dynamic method call
  end

  # Unsafe file operations
  def create_user_file(filename, content)
    # Creating files with user-controlled names
    File.open("/tmp/#{filename}", 'w') do |f|  # VULNERABILITY: Path traversal
      f.write(content)
    end
    File.chmod(0777, "/tmp/#{filename}")  # VULNERABILITY: Insecure file permissions
  end

  # HTTP parameter pollution
  def process_http_params(params)
    # Not handling parameter arrays properly
    user_id = params[:user_id]  # Could be an array - HPP vulnerability
    "Processing user: #{user_id}"
  end

  # Unsafe reflection
  def create_object_from_class_name(class_name)
    # Creating objects from user input
    Object.const_get(class_name).new  # VULNERABILITY: Unsafe reflection
  end

  # Format string vulnerability (in logging)
  def log_user_action(user_action)
    # Using user input in format string
    sprintf(user_action)  # VULNERABILITY: Format string attack
  end

  # Race condition vulnerability
  @@counter = 0
  
  def increment_counter
    # Non-atomic operation
    @@counter += 1  # VULNERABILITY: Race condition
  end

  # Insecure deserialization with Marshal
  def deserialize_user_data(data)
    # Unsafe deserialization
    Marshal.load(data)  # VULNERABILITY: Unsafe deserialization
  end

  # Network request without SSL verification
  def make_api_call(url)
    uri = URI(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = false  # VULNERABILITY: Insecure HTTP
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE  # VULNERABILITY: SSL verification disabled
    
    request = Net::HTTP::Get.new(uri)
    response = http.request(request)
    response.body
  end

  # Hardcoded secret in code
  def encrypt_data(data)
    # Hardcoded encryption key
    key = "hardcoded_secret_key_123"  # VULNERABILITY: Hardcoded secret
    # Simple XOR encryption (weak)
    encrypted = data.bytes.map.with_index { |b, i| b ^ key[i % key.length].ord }
    encrypted.pack('C*')
  end
end

# Rails-specific vulnerabilities (if in Rails context)
class UsersController < ApplicationController
  # Mass assignment vulnerability
  def create
    # Vulnerable to mass assignment
    @user = User.new(params[:user])  # VULNERABILITY: Mass assignment
    @user.save
  end

  # SQL injection in find_by
  def show
    # SQL injection through find_by
    @user = User.find_by("name = '#{params[:name]}'")  # VULNERABILITY: SQL injection
  end

  # XSS through render
  def display_message
    # Rendering user input without escaping
    render text: params[:message]  # VULNERABILITY: XSS
  end

  # CSRF token bypass
  protect_from_forgery except: [:create, :update]  # VULNERABILITY: CSRF protection disabled

  # Unsafe redirect
  def redirect_after_login
    redirect_to params[:return_to]  # VULNERABILITY: Open redirect
  end
end

# User model with vulnerabilities
class User
  attr_accessor :name, :email, :role, :admin

  def initialize(attributes = {})
    attributes.each do |key, value|
      send("#{key}=", value) if respond_to?("#{key}=")  # VULNERABILITY: Mass assignment
    end
  end

  # Weak validation
  def valid_email?
    # Weak email validation
    email.include?('@')  # VULNERABILITY: Weak validation
  end
end

# Main execution with vulnerable patterns
if __FILE__ == $0
  puts "Testing vulnerable Ruby functions..."
  
  app = VulnerableRubyApp.new
  
  # Test various vulnerabilities
  puts "Testing SQL injection..."
  query = app.get_user_by_name("admin'; DROP TABLE users; --")
  
  puts "Testing weak cryptography..."
  hash = app.hash_password("password123")
  puts "MD5 Hash: #{hash}"
  
  puts "Testing command injection..."
  app.execute_user_command("; rm -rf /")
  
  puts "Testing YAML deserialization..."
  yaml_data = "--- !ruby/object:Object {}"
  config = app.load_user_config(yaml_data)
  
  puts "Testing path traversal..."
  begin
    content = app.read_user_file("../../../etc/passwd")
  rescue => e
    puts "File read error: #{e.message}"
  end
  
  puts "Testing regex DoS..."
  result = app.validate_input_with_regex("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
  puts "Regex result: #{result}"
  
  puts "Application completed with multiple security vulnerabilities"
end