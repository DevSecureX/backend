/**
 * COMPREHENSIVE C/C++ SECURITY VULNERABILITY TEST FILE
 * 
 * This file contains ALL major vulnerability categories for maximum Cppcheck detection testing.
 * Each vulnerability is labeled with expected CWE and detection comments.
 * 
 * DO NOT USE IN PRODUCTION - FOR SECURITY TESTING ONLY
 * 
 * Categories Covered:
 * 1. Buffer Overflows & Memory Corruption
 * 2. Memory Management Issues
 * 3. Null Pointer Dereferences
 * 4. Uninitialized Variables
 * 5. Integer Overflow/Underflow
 * 6. Format String Vulnerabilities
 * 7. Dangerous Function Usage
 * 8. Array Bounds Violations
 * 9. Resource Management Issues
 * 10. Type Safety Issues
 * 11. Logic Errors
 * 12. Cryptographic Weaknesses
 * 13. Race Conditions
 * 14. Input Validation Issues
 * 15. Additional Modern C++ Issues
 */

#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <random>
#include <algorithm>
#include <functional>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

// =============================================================================
// 1. BUFFER OVERFLOWS & MEMORY CORRUPTION
// =============================================================================

class BufferOverflowVulns {
public:
    // CWE-120: Buffer Copy without Checking Size
    void strcpy_overflow(const char* src) {
        char dest[10];
        strcpy(dest, src);  // VULN: No bounds checking
    }
    
    // CWE-120: Buffer overflow with strncpy misuse
    void strncpy_misuse(const char* src) {
        char dest[10];
        strncpy(dest, src, 20);  // VULN: Size larger than buffer
    }
    
    // CWE-120: sprintf buffer overflow
    void sprintf_overflow(const char* format, const char* data) {
        char buffer[50];
        sprintf(buffer, format, data);  // VULN: No size checking
    }
    
    // CWE-120: gets() buffer overflow
    void gets_overflow() {
        char buffer[100];
        gets(buffer);  // VULN: Deprecated unsafe function
    }
    
    // CWE-120: memcpy overflow
    void memcpy_overflow(const char* src, size_t len) {
        char dest[50];
        memcpy(dest, src, len);  // VULN: No bounds checking on len
    }
    
    // CWE-787: Out-of-bounds write
    void heap_overflow(size_t size) {
        char* buffer = new char[10];
        memset(buffer, 'A', size);  // VULN: size could be > 10
        delete[] buffer;
    }
    
    // CWE-125: Out-of-bounds read
    void buffer_read_overflow(char* buffer, int index) {
        char data = buffer[index];  // VULN: index not validated
        std::cout << "Data: " << data << std::endl;
    }
    
    // CWE-120: Stack smashing
    void stack_smashing(const char* input) {
        char local_buffer[64];
        strcpy(local_buffer, input);  // VULN: Classic stack smash
        return;
    }
};

// =============================================================================
// 2. MEMORY MANAGEMENT ISSUES
// =============================================================================

class MemoryManagementVulns {
public:
    // CWE-401: Memory leak
    void memory_leak_basic() {
        for (int i = 0; i < 100; i++) {
            char* ptr = new char[1024];
            // VULN: Never deleted - memory leak
        }
    }
    
    // CWE-416: Use after free
    void use_after_free() {
        char* ptr = new char[100];
        strcpy(ptr, "test");
        delete ptr;
        
        // VULN: Using freed memory
        std::cout << "Value: " << ptr[0] << std::endl;
    }
    
    // CWE-415: Double free
    void double_free() {
        char* ptr = new char[100];
        delete ptr;
        delete ptr;  // VULN: Double free
    }
    
    // CWE-762: Mismatched allocation/deallocation
    void mismatched_alloc_dealloc() {
        char* ptr = (char*)malloc(100);
        delete ptr;  // VULN: malloc/delete mismatch
        
        char* ptr2 = new char[100];
        free(ptr2);  // VULN: new[]/free mismatch
    }
    
    // CWE-401: Memory leak on exception
    void memory_leak_exception() {
        char* ptr = new char[1000];
        
        // VULN: If exception thrown, memory leaks
        if (rand() % 2) {
            throw std::runtime_error("Error");
        }
        
        delete ptr;
    }
    
    // CWE-401: Realloc memory leak
    void realloc_leak() {
        char* ptr = (char*)malloc(100);
        ptr = (char*)realloc(ptr, 200);  // VULN: Original ptr lost if realloc fails
        free(ptr);
    }
    
    // CWE-416: Dangling pointer
    char* return_dangling_pointer() {
        char local_buffer[100] = "test";
        return local_buffer;  // VULN: Returns address of local variable
    }
    
    // CWE-401: Resource leak with smart pointers misuse
    void smart_pointer_leak() {
        std::shared_ptr<char> ptr1(new char[100]);  // VULN: Should use make_shared
        std::unique_ptr<char> ptr2(new char[50]);   // VULN: Should use make_unique
        
        // VULN: Raw new with shared_ptr can cause issues
        std::shared_ptr<char> ptr3(new char[200]);
    }
};

// =============================================================================
// 3. NULL POINTER DEREFERENCES
// =============================================================================

class NullPointerVulns {
public:
    // CWE-476: NULL pointer dereference
    void null_deref_direct(char* ptr) {
        *ptr = 'A';  // VULN: ptr could be null
    }
    
    // CWE-476: NULL pointer dereference conditional
    void null_deref_conditional(char* ptr) {
        if (ptr != NULL) {
            // Some code...
        }
        *ptr = 'B';  // VULN: ptr could still be null
    }
    
    // CWE-476: Function call on null pointer
    void null_function_call(std::string* str) {
        str->length();  // VULN: str could be null
    }
    
    // CWE-476: Array access on null pointer
    void null_array_access(int* arr) {
        arr[0] = 10;  // VULN: arr could be null
    }
    
    // CWE-476: Null pointer arithmetic
    void null_pointer_arithmetic(char* base) {
        char* ptr = base + 10;  // VULN: base could be null
        *ptr = 'X';
    }
    
    // CWE-476: Null check after use
    void null_check_after_use(char* ptr) {
        strcpy(ptr, "test");  // VULN: Use before null check
        if (ptr == NULL) {
            return;
        }
    }
    
    // CWE-476: Double null check
    void redundant_null_check(char* ptr) {
        if (ptr != NULL) {
            if (ptr != NULL) {  // VULN: Redundant check
                *ptr = 'A';
            }
        }
    }
};

// =============================================================================
// 4. UNINITIALIZED VARIABLES
// =============================================================================

class UninitializedVulns {
public:
    // CWE-457: Use of uninitialized variable
    void uninitialized_primitive() {
        int x;
        int y = x + 5;  // VULN: x not initialized
        std::cout << y << std::endl;
    }
    
    // CWE-457: Uninitialized pointer
    void uninitialized_pointer() {
        char* ptr;
        strcpy(ptr, "test");  // VULN: ptr not initialized
    }
    
    // CWE-457: Uninitialized array element
    void uninitialized_array() {
        int arr[10];
        std::cout << arr[5] << std::endl;  // VULN: Array not initialized
    }
    
    // CWE-457: Uninitialized struct member
    struct Data {
        int value;
        char* name;
    };
    
    void uninitialized_struct() {
        Data data;
        std::cout << data.value << std::endl;  // VULN: Member not initialized
    }
    
    // CWE-457: Conditional uninitialized use
    void conditional_uninitialized(bool flag) {
        int result;
        if (flag) {
            result = 10;
        }
        // VULN: result may be uninitialized if flag is false
        std::cout << result << std::endl;
    }
    
    // CWE-457: Uninitialized string
    void uninitialized_string() {
        char str[100];
        strcat(str, "suffix");  // VULN: str not initialized before strcat
    }
    
    // CWE-457: Loop with uninitialized variable
    void loop_uninitialized() {
        int sum;  // VULN: Not initialized
        for (int i = 0; i < 10; i++) {
            sum += i;
        }
        std::cout << sum << std::endl;
    }
};

// =============================================================================
// 5. INTEGER OVERFLOW/UNDERFLOW ISSUES
// =============================================================================

class IntegerVulns {
public:
    // CWE-190: Integer overflow
    void integer_overflow_add(int a, int b) {
        int result = a + b;  // VULN: Could overflow
        char* buffer = new char[result];  // Dangerous if result overflowed
        delete[] buffer;
    }
    
    // CWE-190: Integer overflow multiplication
    void integer_overflow_mult(int size) {
        int total_size = size * 1024 * 1024;  // VULN: Could overflow
        malloc(total_size);
    }
    
    // CWE-191: Integer underflow
    void integer_underflow(unsigned int a, unsigned int b) {
        unsigned int result = a - b;  // VULN: Could underflow if b > a
        char buffer[result];  // Dangerous array size
    }
    
    // CWE-195: Signed to unsigned conversion
    void signed_unsigned_conversion(int size) {
        if (size < 0) {
            std::cout << "Invalid size" << std::endl;
            return;
        }
        unsigned int usize = size;  // VULN: Still dangerous if size was negative
        char* buffer = new char[usize];
        delete[] buffer;
    }
    
    // CWE-197: Numeric truncation
    void numeric_truncation(long long big_value) {
        int small_value = big_value;  // VULN: Truncation possible
        char buffer[small_value];
    }
    
    // CWE-369: Division by zero
    void division_by_zero(int dividend, int divisor) {
        int result = dividend / divisor;  // VULN: divisor could be 0
        std::cout << result << std::endl;
    }
    
    // CWE-190: Array index overflow
    void array_index_overflow(int index) {
        char array[100];
        array[index] = 'X';  // VULN: index could be >= 100
    }
    
    // CWE-190: Buffer size calculation overflow
    size_t calculate_buffer_size(size_t count, size_t size) {
        return count * size;  // VULN: Could overflow
    }
};

// =============================================================================
// 6. FORMAT STRING VULNERABILITIES
// =============================================================================

class FormatStringVulns {
public:
    // CWE-134: Format string attack
    void printf_format_string(const char* user_input) {
        printf(user_input);  // VULN: User controls format string
    }
    
    // CWE-134: sprintf format string
    void sprintf_format_string(char* output, const char* user_format, const char* data) {
        sprintf(output, user_format, data);  // VULN: User controls format
    }
    
    // CWE-685: Wrong number of arguments
    void printf_wrong_args() {
        printf("%s %d %f", "test");  // VULN: Missing arguments
    }
    
    // CWE-686: Wrong argument type
    void printf_wrong_type() {
        int num = 42;
        printf("%s", num);  // VULN: %s expects string, got int
    }
    
    // CWE-134: snprintf format string
    void snprintf_format_vuln(char* output, size_t size, const char* user_format) {
        snprintf(output, size, user_format, "data");  // VULN: User format
    }
    
    // CWE-134: fprintf format string
    void fprintf_format_vuln(FILE* file, const char* user_input) {
        fprintf(file, user_input);  // VULN: User controls format
    }
    
    // CWE-685: scanf wrong args
    void scanf_wrong_args() {
        int a, b;
        scanf("%d %d %d", &a, &b);  // VULN: Only 2 vars for 3 format specs
    }
};

// =============================================================================
// 7. DANGEROUS FUNCTION USAGE
// =============================================================================

class DangerousFunctionsVulns {
public:
    // CWE-242: Use of inherently dangerous function
    void dangerous_gets() {
        char buffer[100];
        gets(buffer);  // VULN: Buffer overflow prone
    }
    
    // CWE-676: Use of potentially dangerous function  
    void dangerous_system(const char* command) {
        system(command);  // VULN: Command injection possible
    }
    
    // CWE-676: Dangerous temp file functions
    void dangerous_temp_functions() {
        char* filename = tmpnam(NULL);  // VULN: Race condition prone
        FILE* file = fopen(filename, "w");
        fclose(file);
        
        // Alternative dangerous version
        tempnam("/tmp", "app");  // VULN: Also race condition prone
    }
    
    // CWE-676: Signal handler issues
    void dangerous_signal_handler() {
        signal(SIGINT, SIG_DFL);  // VULN: Non-reentrant
        // Should use sigaction instead
    }
    
    // CWE-242: Dangerous string functions
    void dangerous_string_ops(const char* src) {
        char dest[50];
        strcpy(dest, src);     // VULN: No bounds checking
        strcat(dest, "_end");  // VULN: No bounds checking
        sprintf(dest, "%s_formatted", src);  // VULN: No bounds checking
    }
    
    // CWE-676: Dangerous file operations
    void dangerous_file_ops() {
        // Creating file with predictable name
        FILE* file = fopen("/tmp/app_temp_12345", "w");  // VULN: Predictable name
        if (file) {
            fputs("sensitive data", file);
            fclose(file);
        }
        
        // Dangerous permissions
        chmod("/tmp/app_temp_12345", 0777);  // VULN: World writable
    }
    
    // CWE-676: Deprecated functions
    void deprecated_functions() {
        char buffer[100] = "test";
        
        // Various deprecated/dangerous functions
        char* result1 = index(buffer, 't');        // VULN: Use strchr instead
        char* result2 = rindex(buffer, 't');       // VULN: Use strrchr instead
        bcopy(buffer, buffer + 10, 4);             // VULN: Use memmove instead
        bzero(buffer, sizeof(buffer));             // VULN: Use memset instead
    }
};

// =============================================================================
// 8. ARRAY BOUNDS VIOLATIONS
// =============================================================================

class ArrayBoundsVulns {
public:
    // CWE-129: Improper validation of array index
    void array_bounds_no_check(int index) {
        int array[10];
        array[index] = 42;  // VULN: index not validated
    }
    
    // CWE-787: Out-of-bounds write
    void array_write_overflow() {
        char buffer[10];
        for (int i = 0; i <= 10; i++) {  // VULN: i=10 is out of bounds
            buffer[i] = 'A';
        }
    }
    
    // CWE-125: Out-of-bounds read
    void array_read_overflow() {
        int array[5] = {1, 2, 3, 4, 5};
        for (int i = 0; i < 10; i++) {  // VULN: Reading past array end
            std::cout << array[i] << std::endl;
        }
    }
    
    // CWE-129: Negative array index
    void negative_array_index(int index) {
        char buffer[100];
        if (index >= 0) {
            // Some validation...
        }
        buffer[index] = 'X';  // VULN: index could still be negative
    }
    
    // CWE-787: Multi-dimensional array bounds
    void multidim_array_bounds(int row, int col) {
        int matrix[5][5];
        matrix[row][col] = 10;  // VULN: row/col not validated
    }
    
    // CWE-129: Array index then check
    void array_index_then_check(int index) {
        int array[10];
        int value = array[index];  // VULN: Use before validation
        
        if (index < 0 || index >= 10) {
            return;
        }
        
        std::cout << value << std::endl;
    }
    
    // CWE-787: String array bounds
    void string_array_bounds() {
        char str[10] = "test";
        str[15] = '\0';  // VULN: Writing past array end
    }
    
    // CWE-125: Vector bounds without checking
    void vector_bounds_no_check(std::vector<int>& vec, size_t index) {
        int value = vec[index];  // VULN: Should use .at() for bounds checking
        std::cout << value << std::endl;
    }
};

// =============================================================================
// 9. RESOURCE MANAGEMENT ISSUES
// =============================================================================

class ResourceLeakVulns {
public:
    // CWE-404: Improper resource shutdown - File handles
    void file_handle_leak() {
        FILE* file = fopen("test.txt", "r");
        if (file) {
            char buffer[100];
            fgets(buffer, sizeof(buffer), file);
            // VULN: File never closed
        }
    }
    
    // CWE-404: Multiple file operations
    void multiple_file_operations() {
        FILE* file1 = fopen("file1.txt", "r");  // VULN: Never closed
        FILE* file2 = fopen("file2.txt", "w");  // VULN: Never closed
        
        if (file1 && file2) {
            char data[100];
            fgets(data, sizeof(data), file1);
            fputs(data, file2);
            // Both files leak
        }
    }
    
    // CWE-404: Socket resource leak
    void socket_resource_leak() {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd > 0) {
            // Some socket operations
            // VULN: Socket never closed
        }
    }
    
    // CWE-675: Multiple operations on resource
    void file_opened_twice() {
        const char* filename = "test.txt";
        FILE* file1 = fopen(filename, "r");
        FILE* file2 = fopen(filename, "r");  // VULN: Same file opened twice
        
        if (file1) fclose(file1);
        if (file2) fclose(file2);
    }
    
    // CWE-404: Directory resource leak
    void directory_leak() {
        DIR* dir = opendir("/tmp");
        if (dir) {
            struct dirent* entry;
            while ((entry = readdir(dir)) != NULL) {
                // Process entries
            }
            // VULN: Directory never closed
        }
    }
    
    // CWE-252: Unchecked return value
    void unchecked_return_values() {
        FILE* file = fopen("config.txt", "r");
        fclose(file);  // VULN: Not checking if fopen succeeded
        
        malloc(100);   // VULN: Not checking return value
        
        int result = system("ls");  // VULN: Not checking system() result
    }
    
    // CWE-404: Thread resource leak
    void thread_resource_leak() {
        std::thread t([]() {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        });
        // VULN: Thread not joined or detached
    }
};

// =============================================================================
// 10. TYPE SAFETY ISSUES
// =============================================================================

class TypeSafetyVulns {
public:
    // CWE-704: Incorrect type conversion
    void dangerous_cast() {
        int* int_ptr = new int(42);
        char* char_ptr = (char*)int_ptr;  // VULN: Dangerous cast
        strcpy(char_ptr, "test");  // Will corrupt memory
        delete int_ptr;
    }
    
    // CWE-704: Function pointer cast
    void function_pointer_cast() {
        void (*func_ptr)(int) = [](int x) { std::cout << x << std::endl; };
        void (*bad_func)(char*) = (void(*)(char*))func_ptr;  // VULN: Wrong signature
        bad_func("test");  // Undefined behavior
    }
    
    // CWE-843: Type confusion
    void type_confusion() {
        union {
            int i;
            float f;
            char* p;
        } data;
        
        data.i = 42;
        char* ptr = data.p;  // VULN: Type confusion
        strcpy(ptr, "test");  // Will likely crash
    }
    
    // CWE-704: Void pointer misuse
    void void_pointer_misuse(void* ptr) {
        // Assuming ptr is int* without checking
        int* int_ptr = (int*)ptr;  // VULN: Unchecked cast
        *int_ptr = 100;  // Could be wrong type
    }
    
    // CWE-195: Signed/unsigned mismatch
    void signed_unsigned_mismatch() {
        int signed_val = -1;
        unsigned int unsigned_val = signed_val;  // VULN: -1 becomes large positive
        
        char* buffer = new char[unsigned_val];  // Huge allocation
        delete[] buffer;
    }
    
    // CWE-704: Enum misuse
    enum Color { RED = 1, GREEN = 2, BLUE = 3 };
    
    void enum_misuse() {
        Color color = (Color)10;  // VULN: Invalid enum value
        
        switch (color) {
            case RED: std::cout << "Red" << std::endl; break;
            case GREEN: std::cout << "Green" << std::endl; break;
            case BLUE: std::cout << "Blue" << std::endl; break;
            // No default case for invalid enum
        }
    }
    
    // CWE-134: C-style cast dangers
    void cstyle_cast_danger() {
        const char* const_str = "Hello";
        char* mutable_str = (char*)const_str;  // VULN: Casting away const
        mutable_str[0] = 'h';  // Undefined behavior
    }
};

// =============================================================================
// 11. LOGIC ERRORS
// =============================================================================

class LogicErrorVulns {
public:
    // CWE-561: Dead code
    void dead_code_example() {
        int x = 10;
        if (x > 5) {
            std::cout << "x is greater than 5" << std::endl;
            return;
        }
        
        // VULN: Dead code - will never execute
        std::cout << "This will never print" << std::endl;
    }
    
    // CWE-561: Duplicate condition
    void duplicate_condition(int value) {
        if (value > 10) {
            std::cout << "Greater than 10" << std::endl;
        }
        else if (value > 10) {  // VULN: Duplicate condition
            std::cout << "This will never execute" << std::endl;
        }
    }
    
    // CWE-570: Expression always false
    void always_false_condition() {
        unsigned int x = 5;
        if (x < 0) {  // VULN: Unsigned can never be < 0
            std::cout << "This will never execute" << std::endl;
        }
    }
    
    // CWE-571: Expression always true
    void always_true_condition() {
        int* ptr = malloc(100);
        if (ptr || !ptr) {  // VULN: Always true
            std::cout << "This will always execute" << std::endl;
        }
        free(ptr);
    }
    
    // CWE-398: Indicator of poor code quality
    void unused_variables() {
        int unused_var = 42;  // VULN: Variable never used
        int another_unused = 100;  // VULN: Variable never used
        
        std::cout << "Function completed" << std::endl;
    }
    
    // CWE-561: Identical expressions in ternary
    void identical_ternary_expressions(int x) {
        int result = (x > 0) ? x : x;  // VULN: Both branches identical
        std::cout << result << std::endl;
    }
    
    // CWE-563: Assignment without use
    void assignment_without_use() {
        int value = 10;
        value = 20;  // VULN: Previous assignment unused
        value = 30;  // VULN: Previous assignment unused
        std::cout << "Done" << std::endl;  // value never used
    }
    
    // CWE-561: Unreachable code after return
    void unreachable_after_return() {
        std::cout << "Before return" << std::endl;
        return;
        
        // VULN: Unreachable code
        std::cout << "After return" << std::endl;
        int x = 10;
    }
};

// =============================================================================
// 12. CRYPTOGRAPHIC WEAKNESSES
// =============================================================================

class CryptographicVulns {
public:
    // CWE-338: Weak PRNG
    void weak_random_generation() {
        srand(1234);  // VULN: Fixed seed
        int random_val = rand();  // VULN: Not cryptographically secure
        
        // Using for security purposes
        char session_id[16];
        for (int i = 0; i < 15; i++) {
            session_id[i] = 'A' + (rand() % 26);  // VULN: Predictable
        }
        session_id[15] = '\0';
    }
    
    // CWE-335: Incorrect usage of seeds
    void incorrect_seed_usage() {
        // VULN: Using time as seed for security-critical randomness
        srand(time(NULL));
        
        int crypto_key = rand();  // VULN: Predictable for cryptography
        std::cout << "Key: " << crypto_key << std::endl;
    }
    
    // CWE-798: Hard-coded credentials
    void hardcoded_credentials() {
        // VULN: Hard-coded secrets
        const char* API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz";
        const char* PASSWORD = "admin123";
        const char* JWT_SECRET = "my-super-secret-jwt-key";
        const char* DB_CONN = "postgresql://user:password123@localhost/db";
        
        std::cout << "Connecting with: " << API_KEY << std::endl;
    }
    
    // CWE-259: Hard-coded password
    bool authenticate_user(const char* username, const char* password) {
        // VULN: Hard-coded password comparison
        return strcmp(password, "admin123") == 0;
    }
    
    // CWE-327: Weak cryptographic hash
    void weak_hash_function() {
        // Simulating MD5 usage (weak for cryptography)
        std::string password = "user_password";
        
        // VULN: Using weak hash for password storage
        size_t weak_hash = std::hash<std::string>{}(password);
        std::cout << "Hash: " << weak_hash << std::endl;
    }
    
    // CWE-330: Insufficient randomness
    void insufficient_randomness() {
        // VULN: Using predictable values for security
        int security_token = time(NULL) + getpid();  // Predictable
        std::cout << "Token: " << security_token << std::endl;
    }
    
    // CWE-326: Weak encryption
    void weak_encryption() {
        // VULN: XOR "encryption" is trivially breakable
        std::string plaintext = "sensitive_data";
        char key = 0x42;  // Single byte key
        
        std::string encrypted;
        for (char c : plaintext) {
            encrypted += c ^ key;  // VULN: Weak XOR encryption
        }
    }
};

// =============================================================================
// 13. RACE CONDITIONS & CONCURRENCY
// =============================================================================

class RaceConditionVulns {
private:
    static int shared_counter;
    static std::mutex counter_mutex;
    static bool initialized;
    
public:
    // CWE-362: Race condition
    void unsafe_counter_increment() {
        // VULN: Non-atomic increment
        shared_counter++;  // Multiple threads can cause race condition
    }
    
    // CWE-367: Time-of-check time-of-use (TOCTOU)
    void toctou_file_access(const char* filename) {
        // VULN: File could be changed between check and use
        if (access(filename, F_OK) == 0) {  // Check
            FILE* file = fopen(filename, "r");  // Use - file might be different now
            if (file) {
                // Process file
                fclose(file);
            }
        }
    }
    
    // CWE-362: Race condition in initialization
    void unsafe_initialization() {
        if (!initialized) {  // VULN: Multiple threads could pass this check
            // Expensive initialization
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            initialized = true;
        }
    }
    
    // CWE-662: Improper synchronization
    void improper_synchronization() {
        static int resource = 0;
        
        // VULN: Reading without synchronization
        if (resource == 0) {
            std::lock_guard<std::mutex> lock(counter_mutex);
            resource = 1;  // Another thread might have set it already
        }
    }
    
    // CWE-404: Double-checked locking anti-pattern
    static std::string* singleton_instance;
    
    std::string* unsafe_singleton() {
        if (singleton_instance == nullptr) {  // First check without lock
            std::lock_guard<std::mutex> lock(counter_mutex);
            if (singleton_instance == nullptr) {  // Second check with lock
                // VULN: Still has issues in C++ without proper memory barriers
                singleton_instance = new std::string("singleton");
            }
        }
        return singleton_instance;
    }
    
    // CWE-366: Race condition within a thread
    void signal_handler_race() {
        // VULN: Signal handlers should be reentrant
        static int signal_count = 0;
        signal_count++;  // Not atomic, problems if signal occurs during increment
    }
    
    // CWE-662: Shared resource without protection
    void unprotected_shared_resource() {
        static std::vector<int> shared_vector;
        
        // VULN: Multiple threads modifying without synchronization
        shared_vector.push_back(42);
        
        if (!shared_vector.empty()) {
            shared_vector.pop_back();  // Could be modified by another thread
        }
    }
};

// Static member definitions
int RaceConditionVulns::shared_counter = 0;
std::mutex RaceConditionVulns::counter_mutex;
bool RaceConditionVulns::initialized = false;
std::string* RaceConditionVulns::singleton_instance = nullptr;

// =============================================================================
// 14. INPUT VALIDATION ISSUES
// =============================================================================

class InputValidationVulns {
public:
    // CWE-129: Improper validation of array index
    void improper_index_validation(int user_index) {
        int array[100];
        
        // VULN: Insufficient validation
        if (user_index >= 0) {  // Missing upper bound check
            array[user_index] = 42;
        }
    }
    
    // CWE-20: Improper input validation
    void no_input_validation(const char* filename) {
        // VULN: No validation of filename
        FILE* file = fopen(filename, "r");  // Could be "../../../etc/passwd"
        if (file) {
            char buffer[1000];
            fgets(buffer, sizeof(buffer), file);
            std::cout << buffer << std::endl;
            fclose(file);
        }
    }
    
    // CWE-606: Unchecked input for loop condition
    void unchecked_loop_input(int user_count) {
        // VULN: user_count not validated, could cause infinite loop or crash
        for (int i = 0; i < user_count; i++) {
            char* buffer = malloc(1000);
            // Process buffer
            free(buffer);
        }
    }
    
    // CWE-789: Memory allocation with excessive size
    void excessive_memory_allocation(size_t user_size) {
        // VULN: No validation of user_size
        char* buffer = (char*)malloc(user_size);  // Could be gigabytes
        if (buffer) {
            memset(buffer, 0, user_size);
            free(buffer);
        }
    }
    
    // CWE-120: Buffer overflow due to insufficient input validation
    void insufficient_length_check(const char* user_input) {
        char buffer[256];
        
        // VULN: strlen check insufficient for strcpy
        if (strlen(user_input) > 0) {  // Should check if < 256
            strcpy(buffer, user_input);
        }
    }
    
    // CWE-88: Command injection through insufficient validation
    void command_injection_insufficient_validation(const char* user_file) {
        char command[512];
        
        // VULN: Basic validation but still vulnerable
        if (strstr(user_file, "..") == NULL) {  // Only checks for ..
            sprintf(command, "cat %s", user_file);  // Still vulnerable to ; commands
            system(command);
        }
    }
    
    // CWE-22: Path traversal due to insufficient validation
    void path_traversal_insufficient_validation(const char* user_path) {
        char full_path[256];
        
        // VULN: Insufficient path validation
        if (user_path[0] != '/') {  // Only prevents absolute paths
            sprintf(full_path, "/safe/directory/%s", user_path);  // Still allows ../
            
            FILE* file = fopen(full_path, "r");
            if (file) {
                fclose(file);
            }
        }
    }
    
    // CWE-190: Integer overflow due to unchecked arithmetic
    void integer_overflow_unchecked_arithmetic(int multiplier) {
        int base = 1000000;
        
        // VULN: No overflow checking
        int result = base * multiplier;  // Could overflow
        
        if (result > 0) {  // Overflow could make this false when it should be true
            char* buffer = malloc(result);
            free(buffer);
        }
    }
};

// =============================================================================
// 15. ADDITIONAL MODERN C++ ISSUES
// =============================================================================

class ModernCppVulns {
public:
    // CWE-416: Iterator invalidation
    void iterator_invalidation() {
        std::vector<int> vec = {1, 2, 3, 4, 5};
        
        for (auto it = vec.begin(); it != vec.end(); ++it) {
            if (*it == 3) {
                vec.erase(it);  // VULN: Iterator becomes invalid
                break;  // This saves us, but without break it would crash
            }
        }
        
        // Another example without break
        auto it = vec.begin();
        while (it != vec.end()) {
            vec.push_back(10);  // VULN: Invalidates iterators
            ++it;  // Undefined behavior
        }
    }
    
    // CWE-762: Exception safety issues
    void exception_safety_issues() {
        char* ptr1 = new char[100];
        char* ptr2 = new char[200];  // VULN: If this throws, ptr1 leaks
        
        // Some operations that might throw
        std::string str("test");
        str.at(100);  // Will throw, causing memory leaks above
        
        delete[] ptr1;
        delete[] ptr2;
    }
    
    // CWE-664: Lambda capture issues
    void lambda_capture_issues() {
        int* ptr = new int(42);
        
        auto lambda = [ptr]() {  // VULN: Captures raw pointer by value
            std::cout << *ptr << std::endl;  // ptr might be deleted
        };
        
        delete ptr;  // ptr is now dangling in lambda
        
        // Later in code...
        lambda();  // VULN: Uses dangling pointer
    }
    
    // CWE-416: RAII violations
    void raii_violations() {
        std::unique_ptr<char[]> smart_ptr(new char[100]);
        char* raw_ptr = smart_ptr.get();
        
        smart_ptr.reset();  // Deallocates memory
        
        // VULN: Using raw pointer after smart pointer released memory
        strcpy(raw_ptr, "test");
    }
    
    // CWE-571: Move semantics misuse
    void move_semantics_misuse() {
        std::string str = "important data";
        
        std::string moved_str = std::move(str);
        
        // VULN: Using moved-from object
        std::cout << "Original string: " << str << std::endl;  // Undefined behavior
    }
    
    // CWE-664: Auto type deduction issues
    void auto_deduction_issues() {
        auto ptr = std::make_unique<int>(42);
        auto raw = ptr.get();
        
        ptr = nullptr;  // VULN: raw is now dangling
        
        std::cout << *raw << std::endl;  // Use after free
    }
    
    // CWE-628: Function call with overlapping memory
    void overlapping_memory_operations() {
        char buffer[100] = "Hello World";
        
        // VULN: Source and destination overlap
        strcpy(buffer + 3, buffer);  // Undefined behavior
        
        // Another example
        memmove(buffer, buffer + 2, 50);  // This is actually safe with memmove
        memcpy(buffer, buffer + 2, 50);   // VULN: This is not safe with memcpy
    }
};

// =============================================================================
// MAIN FUNCTION - DEMONSTRATING ALL VULNERABILITIES
// =============================================================================

int main() {
    std::cout << "=== COMPREHENSIVE C++ SECURITY VULNERABILITY TESTING ===" << std::endl;
    std::cout << "This program contains intentional vulnerabilities for Cppcheck testing" << std::endl;
    std::cout << "DO NOT USE IN PRODUCTION" << std::endl << std::endl;
    
    // Initialize vulnerability test classes
    BufferOverflowVulns buffer_vulns;
    MemoryManagementVulns memory_vulns;
    NullPointerVulns null_vulns;
    UninitializedVulns uninit_vulns;
    IntegerVulns integer_vulns;
    FormatStringVulns format_vulns;
    DangerousFunctionsVulns dangerous_vulns;
    ArrayBoundsVulns array_vulns;
    ResourceLeakVulns resource_vulns;
    TypeSafetyVulns type_vulns;
    LogicErrorVulns logic_vulns;
    CryptographicVulns crypto_vulns;
    RaceConditionVulns race_vulns;
    InputValidationVulns input_vulns;
    ModernCppVulns modern_vulns;
    
    std::cout << "1. Testing Buffer Overflow Vulnerabilities..." << std::endl;
    buffer_vulns.strcpy_overflow("This string is way too long for a 10 character buffer overflow test");
    
    std::cout << "2. Testing Memory Management Vulnerabilities..." << std::endl;
    memory_vulns.memory_leak_basic();
    
    std::cout << "3. Testing Null Pointer Vulnerabilities..." << std::endl;
    null_vulns.null_deref_direct(nullptr);
    
    std::cout << "4. Testing Uninitialized Variable Vulnerabilities..." << std::endl;
    uninit_vulns.uninitialized_primitive();
    
    std::cout << "5. Testing Integer Overflow Vulnerabilities..." << std::endl;
    integer_vulns.integer_overflow_add(INT_MAX, 1);
    
    std::cout << "6. Testing Format String Vulnerabilities..." << std::endl;
    format_vulns.printf_format_string("%s%s%s%s%s");
    
    std::cout << "7. Testing Dangerous Function Usage..." << std::endl;
    dangerous_vulns.dangerous_system("echo 'This could be dangerous'");
    
    std::cout << "8. Testing Array Bounds Violations..." << std::endl;
    array_vulns.array_bounds_no_check(100);
    
    std::cout << "9. Testing Resource Management Issues..." << std::endl;
    resource_vulns.file_handle_leak();
    
    std::cout << "10. Testing Type Safety Issues..." << std::endl;
    type_vulns.dangerous_cast();
    
    std::cout << "11. Testing Logic Errors..." << std::endl;
    logic_vulns.dead_code_example();
    
    std::cout << "12. Testing Cryptographic Weaknesses..." << std::endl;
    crypto_vulns.weak_random_generation();
    
    std::cout << "13. Testing Race Conditions..." << std::endl;
    race_vulns.unsafe_counter_increment();
    
    std::cout << "14. Testing Input Validation Issues..." << std::endl;
    input_vulns.improper_index_validation(-5);
    
    std::cout << "15. Testing Modern C++ Issues..." << std::endl;
    modern_vulns.iterator_invalidation();
    
    std::cout << std::endl << "=== VULNERABILITY TESTING COMPLETE ===" << std::endl;
    std::cout << "Total vulnerability categories tested: 15" << std::endl;
    std::cout << "Expected detections: 100+ individual vulnerabilities" << std::endl;
    
    return 0;
}

/*
 * EXPECTED CPPCHECK DETECTIONS SUMMARY:
 * 
 * 1. Buffer Overflows: strcpy, strncpy, sprintf, gets, memcpy issues
 * 2. Memory Management: leaks, use-after-free, double-free, mismatched alloc/dealloc
 * 3. Null Pointers: direct derefs, conditional issues, redundant checks
 * 4. Uninitialized: variables, pointers, arrays, struct members
 * 5. Integer Issues: overflows, underflows, signed/unsigned, truncation, division by zero
 * 6. Format Strings: printf family vulnerabilities, wrong args/types
 * 7. Dangerous Functions: gets, system, signal, deprecated functions
 * 8. Array Bounds: out-of-bounds read/write, negative indices, multi-dimensional
 * 9. Resource Leaks: files, sockets, directories, threads, unchecked returns
 * 10. Type Safety: dangerous casts, type confusion, void pointer misuse
 * 11. Logic Errors: dead code, duplicate conditions, always true/false, unused vars
 * 12. Crypto Weaknesses: weak PRNG, hard-coded credentials, weak hashing
 * 13. Race Conditions: unsafe counters, TOCTOU, improper synchronization
 * 14. Input Validation: improper bounds checking, excessive allocations
 * 15. Modern C++: iterator invalidation, exception safety, lambda captures, RAII violations
 * 
 * This comprehensive test file should trigger 100+ distinct vulnerability detections
 * across all major CWE categories relevant to C/C++ security analysis.
 */