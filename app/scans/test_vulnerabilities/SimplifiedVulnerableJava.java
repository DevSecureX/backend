import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;
import java.util.regex.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Simplified Vulnerable Java Code for SpotBugs Testing
 * This class contains intentional security vulnerabilities for testing purposes
 * DO NOT USE IN PRODUCTION
 */
public class SimplifiedVulnerableJava {
    
    // Hardcoded credentials - should be detected by SpotBugs
    private static final String API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz";
    private static final String DATABASE_PASSWORD = "admin123";
    private static final String JWT_SECRET = "my-super-secret-jwt-key-12345";
    private static final String ENCRYPTION_KEY = "1234567890123456"; // 16 bytes for AES
    
    // SQL injection vulnerability
    public List<User> getUsersByName(Connection conn, String username) throws SQLException {
        // Direct string concatenation in SQL - SQL injection vulnerability
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);  // VULNERABILITY: SQL injection
        
        List<User> users = new ArrayList<>();
        while (rs.next()) {
            users.add(new User(rs.getString("username"), rs.getString("email")));
        }
        return users;
    }
    
    // Command injection vulnerability
    public void executeUserCommand(String userInput) {
        try {
            // Direct execution of user input - command injection
            Runtime.getRuntime().exec(userInput);  // VULNERABILITY: Command injection
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // Path traversal vulnerability
    public String readUserFile(String filename) {
        try {
            // Reading files without path validation
            File file = new File("/uploads/" + filename);  // VULNERABILITY: Path traversal
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            return new String(data);
        } catch (IOException e) {
            return "Error reading file";
        }
    }
    
    // Weak cryptographic hash
    public String hashPassword(String password) {
        try {
            // Using MD5 for password hashing - weak cryptography
            MessageDigest md = MessageDigest.getInstance("MD5");  // VULNERABILITY: Weak hash
            byte[] hash = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return null;
        }
    }
    
    // Insecure random number generation
    public String generateSessionId() {
        // Using Math.random() for security purposes - weak randomness
        double random = Math.random();  // VULNERABILITY: Weak randomness
        return "session_" + (long)(random * 1000000);
    }
    
    // Insecure deserialization
    public Object deserializeUserData(byte[] data) {
        try {
            // Deserializing without validation
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            return ois.readObject();  // VULNERABILITY: Unsafe deserialization
        } catch (Exception e) {
            return null;
        }
    }
    
    // Weak encryption
    public String encryptData(String data) {
        try {
            // Using weak cipher without proper key management
            Cipher cipher = Cipher.getInstance("DES");  // VULNERABILITY: Weak cipher
            SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY.substring(0, 8).getBytes(), "DES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            return null;
        }
    }
    
    // Information disclosure through exception
    public void processUserFile(String filename) throws Exception {
        try {
            FileInputStream fis = new FileInputStream(filename);
            // Process file
            fis.close();
        } catch (FileNotFoundException e) {
            // Exposing internal file paths
            throw new Exception("File not found: " + filename);  // VULNERABILITY: Information disclosure
        }
    }
    
    // LDAP injection vulnerability
    public void authenticateUser(String username, String password) {
        try {
            // LDAP query without proper escaping
            String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";  // VULNERABILITY: LDAP injection
            // Would use this filter in LDAP search
            System.out.println("LDAP Filter: " + filter);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Race condition vulnerability
    private static int counter = 0;
    
    public void incrementCounter() {
        // Non-atomic operation on shared variable
        counter++;  // VULNERABILITY: Race condition
    }
    
    // Null pointer dereference
    public String getUserEmail(User user) {
        // Not checking for null before method call
        return user.getEmail().toLowerCase();  // VULNERABILITY: Potential null pointer dereference
    }
    
    // Resource leak
    public String readFileWithoutClosing(String filename) {
        try {
            FileInputStream fis = new FileInputStream(filename);
            byte[] data = new byte[1024];
            fis.read(data);
            // FileInputStream not closed - resource leak
            return new String(data);  // VULNERABILITY: Resource leak
        } catch (IOException e) {
            return null;
        }
    }
    
    // Regular expression DoS (ReDoS)
    public boolean validateInput(String input) {
        // Vulnerable regex pattern
        Pattern pattern = Pattern.compile("^(a+)+$");  // VULNERABILITY: ReDoS
        return pattern.matcher(input).matches();
    }
    
    // Hardcoded database connection
    public Connection getDatabaseConnection() {
        try {
            // Hardcoded connection string with credentials
            String url = "jdbc:mysql://localhost:3306/app?user=admin&password=admin123";  // VULNERABILITY: Hardcoded credentials
            return DriverManager.getConnection(url);
        } catch (SQLException e) {
            return null;
        }
    }
    
    // Format string vulnerability
    public void logUserAction(String userAction) {
        // Using user input directly in format string
        System.out.printf(userAction);  // VULNERABILITY: Format string attack
    }
    
    // Integer overflow
    public int calculateBufferSize(int userSize) {
        // Potential integer overflow
        return userSize * 1024 * 1024;  // VULNERABILITY: Integer overflow
    }
    
    // Main method for testing
    public static void main(String[] args) {
        System.out.println("Vulnerable Java application for SpotBugs testing");
        
        SimplifiedVulnerableJava app = new SimplifiedVulnerableJava();
        
        // Test vulnerable methods
        String hashedPassword = app.hashPassword("password123");
        String sessionId = app.generateSessionId();
        
        System.out.println("Hash: " + hashedPassword);
        System.out.println("Session ID: " + sessionId);
        
        // Test regex vulnerability
        boolean isValid = app.validateInput("aaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        System.out.println("Input valid: " + isValid);
        
        System.out.println("Application started with multiple security vulnerabilities");
    }
}

// Helper classes
class User {
    private String username;
    private String email;
    
    public User(String username, String email) {
        this.username = username;
        this.email = email;
    }
    
    public String getUsername() {
        return username;
    }
    
    public String getEmail() {
        return email;
    }
}