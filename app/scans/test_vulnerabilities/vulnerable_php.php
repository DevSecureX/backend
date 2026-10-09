<?php
/**
 * Vulnerable PHP Code for Psalm Testing
 * This file contains intentional security vulnerabilities for testing purposes
 * DO NOT USE IN PRODUCTION
 */

// Hardcoded credentials - should be detected by security scanners
const API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz";
const DATABASE_PASSWORD = "admin123";
const JWT_SECRET = "my-super-secret-jwt-key-12345";
const ENCRYPTION_KEY = "1234567890abcdef";

class VulnerablePhpApp {
    private $connection;
    private $users = [];
    
    public function __construct() {
        // Hardcoded database connection
        $this->connection = new PDO("mysql:host=localhost;dbname=app", "admin", "admin123");  // VULNERABILITY: Hardcoded credentials
    }

    // SQL injection vulnerability
    public function getUserByName($username) {
        // Direct string concatenation in SQL - SQL injection vulnerability
        $query = "SELECT * FROM users WHERE username = '" . $username . "'";  // VULNERABILITY: SQL injection
        return $this->connection->query($query);
    }

    // Another SQL injection pattern
    public function getUserById($userId) {
        // SQL injection through interpolation
        $sql = "SELECT * FROM users WHERE id = $userId";  // VULNERABILITY: SQL injection
        return $this->connection->query($sql);
    }

    // Command injection vulnerability
    public function executeUserCommand($userInput) {
        // Direct execution of user input - command injection
        $output = shell_exec("ls " . $userInput);  // VULNERABILITY: Command injection
        return $output;
    }

    // Another command injection pattern
    public function backupDirectory($directory) {
        // Using system() with user input
        system("tar -czf backup.tar.gz " . $directory . "/*");  // VULNERABILITY: Command injection
    }

    // Code injection via eval
    public function executeUserCode($userCode) {
        // Using eval with user input - code injection
        eval($userCode);  // VULNERABILITY: Code injection
    }

    // File inclusion vulnerability
    public function includeUserTemplate($templateName) {
        // Including files based on user input
        include("/templates/" . $templateName . ".php");  // VULNERABILITY: File inclusion
    }

    // Path traversal vulnerability
    public function readUserFile($filename) {
        // Reading files without path validation
        $filepath = "/uploads/" . $filename;
        return file_get_contents($filepath);  // VULNERABILITY: Path traversal
    }

    // XSS vulnerability
    public function displayUserContent($userContent) {
        // Direct output of user content without escaping
        echo "<html><body>User content: " . $userContent . "</body></html>";  // VULNERABILITY: XSS
    }

    // Weak cryptographic hash
    public function hashPassword($password) {
        // Using MD5 for password hashing - weak cryptography
        return md5($password);  // VULNERABILITY: Weak hash function
    }

    // Insecure random number generation
    public function generateSessionId() {
        // Using predictable random for session IDs
        return "session_" . rand(100000, 999999);  // VULNERABILITY: Weak randomness
    }

    // Unsafe deserialization
    public function loadUserData($serializedData) {
        // Unsafe deserialization
        return unserialize($serializedData);  // VULNERABILITY: Unsafe deserialization
    }

    // LDAP injection vulnerability
    public function authenticateLdapUser($username, $password) {
        // LDAP query without proper escaping
        $filter = "(&(uid=" . $username . ")(userPassword=" . $password . "))";  // VULNERABILITY: LDAP injection
        echo "LDAP Filter: " . $filter;
    }

    // Regular expression DoS (ReDoS)
    public function validateInputWithRegex($input) {
        // Vulnerable regex pattern
        $pattern = '/^(a+)+$/';
        return preg_match($pattern, $input);  // VULNERABILITY: ReDoS
    }

    // Information disclosure through error messages
    public function processSensitiveFile($filename) {
        $filepath = "/etc/secrets/" . $filename;
        $content = file_get_contents($filepath);  // VULNERABILITY: Information disclosure
        if ($content === false) {
            throw new Exception("Error reading file: " . $filepath);  // Exposing internal paths
        }
        return $content;
    }

    // Timing attack vulnerability
    public function compareSecrets($userSecret, $actualSecret) {
        // Vulnerable to timing attacks
        return $userSecret === $actualSecret;  // VULNERABILITY: Timing attack
    }

    // Insecure cookie handling
    public function setUserCookie($value) {
        // Cookie without secure flags
        setcookie("user_id", $value);  // VULNERABILITY: Insecure cookie
    }

    // Dynamic function calls
    public function callUserFunction($functionName, $args) {
        // Calling functions based on user input
        return call_user_func($functionName, $args);  // VULNERABILITY: Dynamic function call
    }

    // Unsafe file operations
    public function createUserFile($filename, $content) {
        // Creating files with user-controlled names
        $filepath = "/tmp/" . $filename;
        file_put_contents($filepath, $content);  // VULNERABILITY: Path traversal
        chmod($filepath, 0777);  // VULNERABILITY: Insecure file permissions
    }

    // HTTP parameter pollution
    public function processHttpParams() {
        // Not handling parameter arrays properly
        $userId = $_GET['user_id'];  // Could be an array - HPP vulnerability
        echo "Processing user: " . $userId;
    }

    // Unsafe reflection
    public function createObjectFromClassName($className) {
        // Creating objects from user input
        return new $className();  // VULNERABILITY: Unsafe reflection
    }

    // Open redirect vulnerability
    public function redirectUser($url) {
        // Redirecting without URL validation
        header("Location: " . $url);  // VULNERABILITY: Open redirect
        exit;
    }

    // XML External Entity (XXE) vulnerability
    public function parseXmlData($xmlData) {
        // Parsing XML without disabling external entities
        $dom = new DOMDocument();
        $dom->loadXML($xmlData);  // VULNERABILITY: XXE
        return $dom;
    }

    // Insecure direct object reference
    public function getUserProfile($userId) {
        // Direct access without authorization check
        return $this->users[$userId];  // VULNERABILITY: Insecure direct object reference
    }

    // Race condition vulnerability
    private static $counter = 0;
    
    public function incrementCounter() {
        // Non-atomic operation
        self::$counter++;  // VULNERABILITY: Race condition
    }

    // Network request without SSL verification
    public function makeApiCall($url) {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => 'User-Agent: VulnerableApp/1.0'
            ],
            'ssl' => [
                'verify_peer' => false,  // VULNERABILITY: SSL verification disabled
                'verify_peer_name' => false
            ]
        ]);
        
        return file_get_contents($url, false, $context);  // VULNERABILITY: Insecure HTTP request
    }

    // Hardcoded secret in encryption
    public function encryptData($data) {
        // Hardcoded encryption key
        $key = "hardcoded_secret_key_123";  // VULNERABILITY: Hardcoded secret
        
        // Weak encryption method
        $encrypted = "";
        for ($i = 0; $i < strlen($data); $i++) {
            $encrypted .= chr(ord($data[$i]) ^ ord($key[$i % strlen($key)]));
        }
        return base64_encode($encrypted);
    }

    // Mass assignment vulnerability
    public function updateUserAttributes($attributes) {
        foreach ($attributes as $key => $value) {
            $this->$key = $value;  // VULNERABILITY: Mass assignment
        }
    }

    // SQL injection in prepared statement (incorrect usage)
    public function getUser($table, $column, $value) {
        // Incorrect use of prepared statements
        $stmt = $this->connection->prepare("SELECT * FROM $table WHERE $column = ?");  // VULNERABILITY: SQL injection in table/column names
        $stmt->execute([$value]);
        return $stmt->fetchAll();
    }

    // Type juggling vulnerability
    public function authenticateUser($userId, $providedHash) {
        $storedHash = $this->getUserHash($userId);
        // PHP type juggling vulnerability
        if ($storedHash == $providedHash) {  // VULNERABILITY: Type juggling (should use ===)
            return true;
        }
        return false;
    }

    // Session fixation vulnerability
    public function startUserSession($userId) {
        // Not regenerating session ID
        $_SESSION['user_id'] = $userId;  // VULNERABILITY: Session fixation
    }

    // Insecure cryptographic storage
    public function storePassword($password) {
        // Storing password with weak hash and no salt
        $hash = sha1($password);  // VULNERABILITY: Weak hash, no salt
        return $hash;
    }

    // CSRF vulnerability (missing token validation)
    public function processUserAction() {
        // Processing sensitive action without CSRF protection
        if ($_POST['action'] === 'delete_account') {  // VULNERABILITY: No CSRF token validation
            $this->deleteUserAccount($_POST['user_id']);
        }
    }

    // Private helper methods
    private function getUserHash($userId) {
        return "5d41402abc4b2a76b9719d911017c592";  // MD5 of "hello"
    }

    private function deleteUserAccount($userId) {
        echo "Deleting user account: " . $userId;
    }
}

// Global functions with vulnerabilities
function globalSqlQuery($username) {
    global $connection;
    // SQL injection in global function
    $query = "SELECT * FROM users WHERE username = '$username'";  // VULNERABILITY: SQL injection
    return $query;
}

function globalCommandExecution($cmd) {
    // Command injection in global function
    return exec($cmd);  // VULNERABILITY: Command injection
}

// WordPress-style vulnerabilities (if in WordPress context)
function vulnerable_shortcode($atts) {
    // Unsafe attribute handling
    extract($atts);  // VULNERABILITY: Variable extraction without validation
    
    // Direct output without escaping
    return "<div>User input: $content</div>";  // VULNERABILITY: XSS
}

// Main execution
if (__FILE__ == __FILE__) {  // This condition is always true, just for demo structure
    echo "Testing vulnerable PHP functions...\n";
    
    $app = new VulnerablePhpApp();
    
    // Test various vulnerabilities
    echo "Testing SQL injection...\n";
    $result = $app->getUserByName("admin'; DROP TABLE users; --");
    
    echo "Testing weak cryptography...\n";
    $hash = $app->hashPassword("password123");
    echo "MD5 Hash: " . $hash . "\n";
    
    echo "Testing command injection...\n";
    $output = $app->executeUserCommand("; rm -rf /");
    
    echo "Testing XSS...\n";
    $app->displayUserContent("<script>alert('XSS')</script>");
    
    echo "Testing path traversal...\n";
    try {
        $content = $app->readUserFile("../../../etc/passwd");
    } catch (Exception $e) {
        echo "File read error: " . $e->getMessage() . "\n";
    }
    
    echo "Testing regex DoS...\n";
    $result = $app->validateInputWithRegex("aaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    echo "Regex result: " . ($result ? "match" : "no match") . "\n";
    
    echo "Testing unsafe deserialization...\n";
    $serialized = 'O:8:"stdClass":1:{s:4:"data";s:4:"test";}';
    $object = $app->loadUserData($serialized);
    
    echo "Application completed with multiple security vulnerabilities\n";
}
?>