// Vulnerable JavaScript Code for ESLint Security Testing
// This file contains intentional security vulnerabilities

const crypto = require('crypto');
const exec = require('child_process').exec;
const fs = require('fs');

// Hardcoded secrets - should be detected by security scanners
const API_SECRET = "sk-1234567890abcdefghijklmnopqrstuvwxyz";
const DATABASE_PASSWORD = "admin123";
const JWT_SECRET = "my-super-secret-jwt-key-12345";

// Command injection vulnerability
function executeUserCommand(userInput) {
    // Direct execution of user input - command injection
    exec(userInput, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error: ${error}`);
            return;
        }
        console.log(stdout);
    });
}

// Code injection via eval
function executeUserCode(userCode) {
    // Using eval with user input - code injection
    eval(userCode);
}

// Unsafe regular expression - ReDoS vulnerability
function validateInput(input) {
    const unsafeRegex = /^(a+)+$/;
    return unsafeRegex.test(input);  // ReDoS vulnerability
}

// Weak cryptography
function hashPassword(password) {
    // Using MD5 for password hashing - weak cryptography
    return crypto.createHash('md5').update(password).digest('hex');
}

// SQL injection template (for template engines)
function buildQuery(userId) {
    // Template string without sanitization
    return `SELECT * FROM users WHERE id = ${userId}`;
}

// Path traversal vulnerability
function readUserFile(filename) {
    // Reading files without path validation
    const filePath = `/uploads/${filename}`;
    return fs.readFileSync(filePath, 'utf8');
}

// Insecure random number generation for security purposes
function generateSessionId() {
    // Using Math.random() for security tokens
    return Math.random().toString(36).substring(2, 15);
}

// Prototype pollution vulnerability
function merge(target, source) {
    for (let key in source) {
        if (source.hasOwnProperty(key)) {
            target[key] = source[key];  // No prototype pollution protection
        }
    }
    return target;
}

// Insecure deserialization (if using JSON.parse with user input)
function parseUserData(userData) {
    // Parsing JSON without validation
    return JSON.parse(userData);
}

// XSS vulnerability (for web contexts)
function renderUserContent(userContent) {
    // Direct DOM manipulation without sanitization
    document.getElementById('content').innerHTML = userContent;
}

// Insecure cookie settings
function setUserCookie(value) {
    // Cookie without secure flags
    document.cookie = `user=${value}`;
}

// Hardcoded file paths
const CONFIG_FILE = "/etc/passwd";
const LOG_FILE = "/var/log/app.log";

// Weak encryption
function encryptData(data, key) {
    // Using weak cipher
    const cipher = crypto.createCipher('des', key);  // DES is weak
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Insecure HTTP requests
const http = require('http');
function makeApiCall(url) {
    // HTTP instead of HTTPS
    return http.get(url);
}

// Node.js specific vulnerabilities
process.on('uncaughtException', (err) => {
    // Poor error handling
    console.log('Error occurred:', err);
    // Application continues running after uncaught exception
});

// Express.js vulnerabilities (if Express was imported)
// const express = require('express');
// const app = express();

// app.use(express.static('public'));  // Serving static files without restrictions

// app.get('/user/:id', (req, res) => {
//     const userId = req.params.id;
//     // SQL injection via template literal
//     const query = `SELECT * FROM users WHERE id = ${userId}`;
//     res.send(query);
// });

// Timing attack vulnerability
function compareSecrets(userSecret, actualSecret) {
    // Vulnerable to timing attacks
    return userSecret === actualSecret;
}

// Buffer overflow potential
function processBuffer(data) {
    const buffer = Buffer.alloc(10);
    // No bounds checking
    buffer.write(data);
    return buffer;
}

// Insecure randomness for tokens
function generateToken() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token = '';
    // Using Math.random() for cryptographic purposes
    for (let i = 0; i < 32; i++) {
        token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
}

// Export functions for testing
module.exports = {
    executeUserCommand,
    executeUserCode,
    validateInput,
    hashPassword,
    buildQuery,
    readUserFile,
    generateSessionId,
    merge,
    parseUserData,
    renderUserContent,
    setUserCookie,
    encryptData,
    makeApiCall,
    compareSecrets,
    processBuffer,
    generateToken
};

// Main execution with vulnerable patterns
if (require.main === module) {
    console.log("Testing vulnerable JavaScript functions...");
    
    // Test with potentially dangerous inputs
    const userInput = "ls -la";
    const userCode = "console.log('Code injection test')";
    
    // These calls would trigger security warnings
    const hashedPassword = hashPassword("password123");
    const sessionId = generateSessionId();
    const token = generateToken();
    
    console.log(`Hash: ${hashedPassword}, Session: ${sessionId}, Token: ${token}`);
}