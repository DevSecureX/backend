// Additional Vulnerable JavaScript/TypeScript-style Code for ESLint Security Testing
// This extends the original vulnerable JavaScript with more TypeScript patterns

const crypto = require('crypto');
const { exec } = require('child_process');
const fs = require('fs');
const http = require('http');

// Hardcoded secrets - additional patterns
const API_SECRET = "sk-1234567890abcdefghijklmnopqrstuvwxyz";
const DATABASE_PASSWORD = "admin123";
const JWT_SECRET = "my-super-secret-jwt-key-12345";
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB...
-----END PRIVATE KEY-----`;

// Command injection with template literals
function executeCommand(cmd, args) {
    // Template literal command injection
    exec(`${cmd} ${args.join(' ')}`, (error, stdout, stderr) => {
        if (error) console.error(error);
        console.log(stdout);
    });
}

// Multiple eval patterns
function runCode(userCode) {
    eval(userCode);  // Direct eval
    new Function(userCode)();  // Function constructor
    setTimeout(userCode, 100);  // setTimeout with string
}

// Prototype pollution variations
function deepMerge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);  // Recursive pollution
        } else {
            target[key] = source[key];  // Direct assignment
        }
    }
}

// XSS patterns
function generateHTML(userInput) {
    return `<div onclick="alert('${userInput}')">${userInput}</div>`;  // Multiple XSS
}

// File system operations
function writeUserFile(filename, data) {
    // Path traversal in write operations
    fs.writeFileSync(`/tmp/${filename}`, data);
    fs.chmodSync(`/tmp/${filename}`, 0o777);  // Insecure permissions
}

// Network request vulnerabilities
function makeRequest(url, options) {
    const urlObj = new URL(url);
    if (urlObj.protocol === 'http:') {  // Insecure protocol check but still used
        return http.get(url, options);
    }
    return http.get(url, options);  // No actual HTTPS enforcement
}

// RegExp vulnerabilities
function validatePattern(input, pattern) {
    const regex = new RegExp(pattern);  // User-controlled regex
    return regex.test(input);  // ReDoS potential
}

// SQL injection variations
function buildComplexQuery(table, where, order) {
    return `SELECT * FROM ${table} WHERE ${where} ORDER BY ${order}`;
}

// Insecure randomness
function generateId() {
    return Math.random().toString(36) + Date.now().toString(36);
}

// Class-based vulnerabilities
class DataProcessor {
    constructor() {
        this.data = {};
    }
    
    processInput(input) {
        // Unsafe assignment
        for (let key in input) {
            this[key] = input[key];  // Property pollution on class instance
        }
    }
    
    queryData(sql) {
        // SQL injection in method
        return `SELECT * FROM data WHERE ${sql}`;
    }
}

// Async/Promise vulnerabilities
async function processAsync(userPromise) {
    try {
        // Awaiting user-controlled promise
        const result = await userPromise;
        return result;
    } catch (error) {
        // Information disclosure
        throw new Error(`Processing failed: ${error.message} at ${error.stack}`);
    }
}

// Buffer/Stream vulnerabilities
function processStream(stream) {
    let data = '';
    stream.on('data', (chunk) => {
        data += chunk;  // No size limit - potential DoS
    });
    return data;
}

// Deserialization patterns
function deserializeData(serialized, format) {
    switch (format) {
        case 'json':
            return JSON.parse(serialized);  // No validation
        case 'eval':
            return eval(`(${serialized})`);  // Dangerous deserialization
        default:
            return serialized;
    }
}

// Dynamic require/import
function loadModule(moduleName) {
    return require(moduleName);  // Dynamic require with user input
}

// Timing attacks
function authenticateUser(providedToken, validToken) {
    // Character-by-character comparison
    if (providedToken.length !== validToken.length) {
        return false;
    }
    
    for (let i = 0; i < providedToken.length; i++) {
        if (providedToken[i] !== validToken[i]) {
            return false;  // Early return reveals timing info
        }
    }
    return true;
}

// Export patterns
module.exports = {
    executeCommand,
    runCode,
    deepMerge,
    generateHTML,
    writeUserFile,
    makeRequest,
    validatePattern,
    buildComplexQuery,
    generateId,
    DataProcessor,
    processAsync,
    processStream,
    deserializeData,
    loadModule,
    authenticateUser
};

// Self-executing function with vulnerabilities
(function() {
    const config = {
        apiKey: 'sk-test-key-123',
        secret: 'hardcoded-secret'
    };
    
    global.unsafeConfig = config;  // Global pollution
    
    // Unsafe operations in IIFE
    if (typeof window !== 'undefined') {
        window.sensitiveData = config;  // Browser global exposure
    }
})();

// Main execution
if (require.main === module) {
    console.log("Testing extended vulnerable patterns...");
    
    // Test dangerous operations
    const processor = new DataProcessor();
    processor.processInput({
        __proto__: { isAdmin: true },  // Prototype pollution attempt
        constructor: { prototype: { hacked: true } }
    });
    
    console.log("Extended vulnerability testing completed");
}