#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <memory>
#include <openssl/md5.h>
#include <sqlite3.h>
#include <unistd.h>
#include <sys/stat.h>

/**
 * Vulnerable C++ Code for Cppcheck Testing
 * This file contains intentional security vulnerabilities for testing purposes
 * DO NOT USE IN PRODUCTION
 */

// Global hardcoded credentials - should be detected
const char* API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz";
const char* DATABASE_PASSWORD = "admin123";
const char* JWT_SECRET = "my-super-secret-jwt-key-12345";

class VulnerableCppApp {
private:
    char* buffer;
    int buffer_size;

public:
    VulnerableCppApp() : buffer_size(1024) {
        buffer = new char[buffer_size];
    }
    
    // Buffer overflow vulnerability
    void copyUserInput(const char* userInput) {
        // No bounds checking - buffer overflow
        strcpy(buffer, userInput);  // VULNERABILITY: Buffer overflow
        std::cout << "Copied: " << buffer << std::endl;
    }
    
    // Buffer overflow with sprintf
    void formatString(const char* format, const char* data) {
        char output[256];
        // Potential buffer overflow with sprintf
        sprintf(output, format, data);  // VULNERABILITY: Format string + buffer overflow
        std::cout << output << std::endl;
    }
    
    // Use after free vulnerability
    void useAfterFree() {
        char* ptr = new char[100];
        strcpy(ptr, "test data");
        delete ptr;
        
        // Using pointer after free
        std::cout << "Data: " << ptr << std::endl;  // VULNERABILITY: Use after free
    }
    
    // Memory leak
    void memoryLeak(int size) {
        for (int i = 0; i < 10; i++) {
            char* leaked_memory = new char[size];
            strcpy(leaked_memory, "This memory will leak");
            // Memory not freed - memory leak
        }  // VULNERABILITY: Memory leak
    }
    
    // Double free vulnerability
    void doubleFree() {
        char* ptr = new char[100];
        strcpy(ptr, "test");
        delete ptr;
        delete ptr;  // VULNERABILITY: Double free
    }
    
    // Array bounds violation
    void arrayBoundsViolation(int index) {
        int array[10] = {0};
        // No bounds checking
        array[index] = 42;  // VULNERABILITY: Array bounds violation
        std::cout << "Set array[" << index << "] = 42" << std::endl;
    }
    
    // Null pointer dereference
    void nullPointerDereference(char* ptr) {
        // Not checking for null pointer
        strcpy(ptr, "test");  // VULNERABILITY: Potential null pointer dereference
    }
    
    // Integer overflow
    int calculateBufferSize(int userSize) {
        // Potential integer overflow
        return userSize * 1024 * 1024;  // VULNERABILITY: Integer overflow
    }
    
    // Uninitialized variable usage
    void useUninitializedVariable() {
        int uninitialized;
        int result = uninitialized + 10;  // VULNERABILITY: Use of uninitialized variable
        std::cout << "Result: " << result << std::endl;
    }
    
    // Resource leak (file handle)
    void fileHandleLeak(const char* filename) {
        FILE* file = fopen(filename, "r");
        if (file) {
            char data[1024];
            fgets(data, sizeof(data), file);
            std::cout << "Read: " << data << std::endl;
            // File not closed - resource leak
        }  // VULNERABILITY: Resource leak
    }
    
    // SQL injection (C-style)
    void executeSQLQuery(const char* username) {
        char query[512];
        // String concatenation without sanitization
        sprintf(query, "SELECT * FROM users WHERE username = '%s'", username);  // VULNERABILITY: SQL injection
        std::cout << "Executing: " << query << std::endl;
    }
    
    // Command injection
    void executeSystemCommand(const char* userInput) {
        char command[256];
        // Direct user input in system command
        sprintf(command, "ls %s", userInput);  // VULNERABILITY: Command injection
        system(command);
    }
    
    // Path traversal
    void readUserFile(const char* filename) {
        char filepath[256];
        // Path traversal vulnerability
        sprintf(filepath, "/uploads/%s", filename);  // VULNERABILITY: Path traversal
        
        std::ifstream file(filepath);
        if (file.is_open()) {
            std::string content;
            std::getline(file, content);
            std::cout << "File content: " << content << std::endl;
            file.close();
        }
    }
    
    // Weak cryptographic hash
    std::string hashPassword(const std::string& password) {
        // Using MD5 for password hashing
        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5_CTX ctx;
        MD5_Init(&ctx);
        MD5_Update(&ctx, password.c_str(), password.length());
        MD5_Final(digest, &ctx);  // VULNERABILITY: Weak hash function
        
        char hash[33];
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            sprintf(&hash[i*2], "%02x", digest[i]);
        }
        hash[32] = '\0';
        
        return std::string(hash);
    }
    
    // Insecure random number generation
    int generateRandomNumber() {
        // Using rand() without proper seeding for security purposes
        return rand();  // VULNERABILITY: Weak randomness
    }
    
    // Race condition vulnerability
    static int shared_counter;
    void incrementCounter() {
        // Non-atomic increment - race condition
        shared_counter++;  // VULNERABILITY: Race condition
    }
    
    // Insecure temporary file creation
    void createTempFile() {
        // Creating temp file with predictable name
        char tempfile[] = "/tmp/app_temp_XXXXXX";  // Predictable pattern
        int fd = mkstemp(tempfile);
        
        if (fd != -1) {
            // Setting insecure permissions
            chmod(tempfile, 0777);  // VULNERABILITY: Insecure file permissions
            write(fd, JWT_SECRET, strlen(JWT_SECRET));
            close(fd);
        }
    }
    
    // Stack buffer overflow
    void stackBufferOverflow(const char* data) {
        char stack_buffer[64];
        // No bounds checking on stack buffer
        strcpy(stack_buffer, data);  // VULNERABILITY: Stack buffer overflow
        std::cout << "Stack data: " << stack_buffer << std::endl;
    }
    
    // Signed/unsigned conversion
    void signedUnsignedIssue(int size) {
        if (size < 0) {
            std::cout << "Invalid size" << std::endl;
            return;
        }
        
        unsigned int usize = size;  // VULNERABILITY: Signed to unsigned conversion
        char* buffer = new char[usize];  // Could be huge if size was negative
        delete[] buffer;
    }
    
    // Division by zero
    int divideNumbers(int a, int b) {
        // No check for division by zero
        return a / b;  // VULNERABILITY: Division by zero
    }
    
    // Format string vulnerability
    void logMessage(const char* userMessage) {
        // User input directly in printf format string
        printf(userMessage);  // VULNERABILITY: Format string attack
        printf("\n");
    }
    
    // Destructor with potential issues
    ~VulnerableCppApp() {
        if (buffer) {
            delete buffer;  // Should use delete[] for arrays
        }  // VULNERABILITY: Wrong delete operator
    }
};

// Static member definition
int VulnerableCppApp::shared_counter = 0;

// Global function with vulnerabilities
void globalBufferOverflow(const char* input) {
    char global_buffer[256];
    // No bounds checking
    strcpy(global_buffer, input);  // VULNERABILITY: Buffer overflow
}

// Unsafe C string functions
void unsafeCStringFunctions(const char* src) {
    char dest[100];
    
    // Multiple unsafe functions
    strcpy(dest, src);           // VULNERABILITY: No bounds checking
    strcat(dest, "_suffix");     // VULNERABILITY: No bounds checking
    gets(dest);                  // VULNERABILITY: Deprecated unsafe function
    
    std::cout << "Result: " << dest << std::endl;
}

// Pointer arithmetic vulnerabilities
void pointerArithmetic(char* buffer, int offset) {
    // Unchecked pointer arithmetic
    char* ptr = buffer + offset;  // VULNERABILITY: Unchecked pointer arithmetic
    *ptr = 'X';  // Could write outside buffer bounds
}

// Main function demonstrating vulnerabilities
int main() {
    std::cout << "Vulnerable C++ application for Cppcheck testing" << std::endl;
    
    VulnerableCppApp app;
    
    // Test various vulnerabilities
    std::cout << "Testing buffer overflow..." << std::endl;
    app.copyUserInput("This is a test input that might be too long for the buffer and cause overflow");
    
    std::cout << "Testing memory leak..." << std::endl;
    app.memoryLeak(1024);
    
    std::cout << "Testing weak cryptography..." << std::endl;
    std::string hash = app.hashPassword("password123");
    std::cout << "MD5 Hash: " << hash << std::endl;
    
    std::cout << "Testing array bounds..." << std::endl;
    app.arrayBoundsViolation(15);  // Index out of bounds
    
    std::cout << "Testing SQL injection..." << std::endl;
    app.executeSQLQuery("admin'; DROP TABLE users; --");
    
    std::cout << "Testing command injection..." << std::endl;
    app.executeSystemCommand("; rm -rf /");
    
    std::cout << "Testing division by zero..." << std::endl;
    int result = app.divideNumbers(10, 0);  // Will cause division by zero
    
    std::cout << "Testing format string vulnerability..." << std::endl;
    app.logMessage("%s%s%s%s%s");  // Format string attack
    
    std::cout << "Application completed with multiple security vulnerabilities" << std::endl;
    
    return 0;
}