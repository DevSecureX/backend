// Vulnerable TypeScript Code for ESLint Security Testing
// This file contains intentional security vulnerabilities for testing purposes

import * as crypto from 'crypto';
import { exec } from 'child_process';
import * as fs from 'fs';
import * as http from 'http';
import { Request, Response } from 'express';

// Hardcoded secrets - should be detected by security scanners
const API_SECRET = "sk-1234567890abcdefghijklmnopqrstuvwxyz";
const DATABASE_PASSWORD = "admin123";
const JWT_SECRET = "my-super-secret-jwt-key-12345";
const ENCRYPTION_KEY = "hardcoded-encryption-key-123";

// Interface for user data
interface User {
    id: number;
    username: string;
    email: string;
    role: string;
}

// Command injection vulnerability
function executeUserCommand(userInput: string): void {
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
function executeUserCode(userCode: string): any {
    // Using eval with user input - code injection
    return eval(userCode);
}

// Unsafe regular expression - ReDoS vulnerability
function validateInput(input: string): boolean {
    const unsafeRegex: RegExp = /^(a+)+$/;
    return unsafeRegex.test(input);  // ReDoS vulnerability
}

// Weak cryptography
function hashPassword(password: string): string {
    // Using MD5 for password hashing - weak cryptography
    return crypto.createHash('md5').update(password).digest('hex');
}

// SQL injection template (for template engines)
function buildQuery(userId: string | number): string {
    // Template string without sanitization
    return `SELECT * FROM users WHERE id = ${userId}`;
}

// Path traversal vulnerability
function readUserFile(filename: string): string {
    // Reading files without path validation
    const filePath: string = `/uploads/${filename}`;
    return fs.readFileSync(filePath, 'utf8');
}

// Insecure random number generation for security purposes
function generateSessionId(): string {
    // Using Math.random() for security tokens
    return Math.random().toString(36).substring(2, 15);
}

// Prototype pollution vulnerability
function merge(target: any, source: any): any {
    for (let key in source) {
        if (source.hasOwnProperty(key)) {
            target[key] = source[key];  // No prototype pollution protection
        }
    }
    return target;
}

// Insecure deserialization (if using JSON.parse with user input)
function parseUserData(userData: string): any {
    // Parsing JSON without validation
    return JSON.parse(userData);
}

// XSS vulnerability (for web contexts)
function renderUserContent(userContent: string): void {
    // Direct DOM manipulation without sanitization - would work in browser context
    if (typeof document !== 'undefined') {
        const element = document.getElementById('content');
        if (element) {
            element.innerHTML = userContent;
        }
    }
}

// Insecure cookie settings (Express.js context)
function setUserCookie(res: Response, value: string): void {
    // Cookie without secure flags
    res.cookie('user', value, {
        // Missing secure, httpOnly, sameSite flags
        maxAge: 900000
    });
}

// Hardcoded file paths
const CONFIG_FILE: string = "/etc/passwd";
const LOG_FILE: string = "/var/log/app.log";
const SECRET_CONFIG: string = "/etc/secrets/app.conf";

// Weak encryption
function encryptData(data: string, key: string): string {
    // Using weak cipher
    const cipher = crypto.createCipher('des', key);  // DES is weak
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Insecure HTTP requests
function makeApiCall(url: string): Promise<any> {
    return new Promise((resolve, reject) => {
        // HTTP instead of HTTPS
        http.get(url, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                resolve(data);
            });
        }).on('error', (err) => {
            reject(err);
        });
    });
}

// Timing attack vulnerability
function compareSecrets(userSecret: string, actualSecret: string): boolean {
    // Vulnerable to timing attacks
    return userSecret === actualSecret;
}

// Buffer overflow potential (Node.js specific)
function processBuffer(data: string): Buffer {
    const buffer = Buffer.alloc(10);
    // No bounds checking
    buffer.write(data);
    return buffer;
}

// Insecure randomness for tokens
function generateToken(): string {
    const chars: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token: string = '';
    // Using Math.random() for cryptographic purposes
    for (let i = 0; i < 32; i++) {
        token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
}

// Type-related vulnerabilities
class UserManager {
    private users: User[] = [];

    // Missing input validation
    addUser(userData: any): void {
        // Type coercion vulnerability - no validation of userData structure
        const user: User = userData as User;
        this.users.push(user);
    }

    // Unsafe array access
    getUserById(id: string): User | undefined {
        // Converting string to number without validation
        const numId: number = parseInt(id);
        return this.users[numId];  // Potential array bounds issue
    }

    // SQL injection in query builder
    findUsersByRole(role: string): string {
        // Direct interpolation without sanitization
        return `SELECT * FROM users WHERE role = '${role}'`;
    }
}

// Express.js specific vulnerabilities
function handleUserInput(req: Request, res: Response): void {
    const userInput: string = req.body.input;
    const userId: string = req.params.id;
    
    // Multiple vulnerabilities in one function
    // 1. XSS through direct output
    res.send(`<html><body>User input: ${userInput}</body></html>`);
    
    // 2. Command injection
    exec(`cat /etc/passwd | grep ${userId}`, (error, stdout) => {
        if (error) {
            // 3. Information disclosure through error messages
            res.status(500).send(`Error: ${error.message}`);
        } else {
            res.send(stdout);
        }
    });
}

// Insecure file operations with TypeScript specifics
async function processUserFile(filename: string): Promise<string> {
    try {
        // Path traversal vulnerability
        const fullPath: string = `./uploads/${filename}`;
        
        // Potential race condition - check then use
        if (fs.existsSync(fullPath)) {
            // File might be deleted between check and read
            const content: string = fs.readFileSync(fullPath, 'utf8');
            return content;
        }
        
        throw new Error("File not found");
    } catch (error) {
        // Information disclosure
        throw new Error(`Error reading file ${filename}: ${(error as Error).message}`);
    }
}

// Regex injection vulnerability
function validateEmail(email: string, pattern?: string): boolean {
    // Using user-supplied regex pattern
    const emailRegex: RegExp = new RegExp(pattern || '^[^@]+@[^@]+\\.[^@]+$');
    return emailRegex.test(email);
}

// Unsafe reflection/dynamic property access
function getPropertyValue(obj: any, propPath: string): any {
    // Dynamic property access without validation
    return propPath.split('.').reduce((current, prop) => current[prop], obj);
}

// Export functions for testing
export {
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
    generateToken,
    UserManager,
    handleUserInput,
    processUserFile,
    validateEmail,
    getPropertyValue
};

// Main execution with vulnerable patterns
if (require.main === module) {
    console.log("Testing vulnerable TypeScript functions...");
    
    // Test with potentially dangerous inputs
    const userInput: string = "ls -la";
    const userCode: string = "console.log('Code injection test')";
    
    // These calls would trigger security warnings
    const hashedPassword: string = hashPassword("password123");
    const sessionId: string = generateSessionId();
    const token: string = generateToken();
    
    console.log(`Hash: ${hashedPassword}, Session: ${sessionId}, Token: ${token}`);
    
    // Test UserManager vulnerabilities
    const userManager = new UserManager();
    userManager.addUser({
        id: 1,
        username: "admin'; DROP TABLE users; --",
        email: "admin@evil.com",
        role: "user"
    });
    
    console.log("TypeScript application completed with multiple security vulnerabilities");
}