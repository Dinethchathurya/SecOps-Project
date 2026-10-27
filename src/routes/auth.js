const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../config/db');

/**
 * ==============================================================================
 * FLAW CATEGORY 2.3: APPLICATION CODE FLAW / SAST (Target: SonarQube / SonarCloud)
 * VULNERABILITY: Insecure Cryptographic Hash Functions (CWE-327, CWE-328, CWE-916)
 * ==============================================================================
 * Scanner Target: SonarCloud / SonarQube (Rules: javascript:S2070, javascript:S4790)
 *
 * Why SonarCloud catches it:
 *   SonarCloud AST rules scan crypto calls and identify broken/weak cryptographic
 *   hashing algorithms like MD5 (`crypto.createHash('md5')`) or SHA-1 (`crypto.createHash('sha1')`)
 *   used for password hashing or security-sensitive token generation without salting.
 *
 * Why Gitleaks ignores it:
 *   Hashing calls do not contain secrets; they are algorithms in source code.
 *
 * Why Snyk SCA ignores it:
 *   `crypto` is a built-in Node.js module, not a vulnerable third-party package.
 *
 * Why Trivy ignores it:
 *   Trivy scans container images and OS binaries, not cryptographic calls inside JavaScript.
 * ==============================================================================
 */

// VULNERABLE ENDPOINT: MD5 password hashing without salt
router.post('/register-insecure', (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // INTENTIONAL FLAW 1: MD5 hashing without salt (Broken cryptographic primitive)
  // SonarCloud Flag: javascript:S2070 ("MD5 and SHA-1 are cryptographically broken and deprecated")
  const md5Hash = crypto.createHash('md5').update(password).digest('hex');

  // INTENTIONAL FLAW 2: Generating verification token using weak SHA-1
  const sha1VerificationToken = crypto.createHash('sha1').update(username + Date.now()).digest('hex');

  db.run(
    `INSERT INTO users (username, email, password_hash, role, bio) VALUES (?, ?, ?, 'user', 'New user registered via insecure endpoint')`,
    [username, email || '', md5Hash],
    function (err) {
      if (err) {
        return res.status(500).json({ status: 'error', message: err.message });
      }

      return res.status(201).json({
        status: 'success',
        vulnerability: 'Weak Cryptographic Hash (MD5 & SHA-1, CWE-327/328)',
        scannerTarget: 'SonarQube / SonarCloud (Rule: javascript:S2070)',
        userId: this.lastID,
        storedHash: md5Hash,
        hashType: 'MD5 (Unsalted, prone to rainbow tables and fast offline brute force)',
        verificationToken: sha1VerificationToken
      });
    }
  );
});

// VULNERABLE ENDPOINT: Insecure JWT token issuance (vulnerable to algorithm confusion)
// Uses vulnerable package `jsonwebtoken@8.5.1` (Target: Snyk SCA & SonarCloud SAST)
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const md5Hash = crypto.createHash('md5').update(password).digest('hex');

  db.get(`SELECT * FROM users WHERE username = ? AND password_hash = ?`, [username, md5Hash], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials or user not found' });
    }

    // INTENTIONAL FLAW 3: Creating JWT with weak static secret and permitting 'none' algorithm
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      'weak_secret_key_123',
      { expiresIn: '1h' }
    );

    return res.json({
      status: 'success',
      token,
      user: { id: user.id, username: user.username, role: user.role }
    });
  });
});

// REMEDIATED HASHING ENDPOINT (Using PBKDF2 with crypto-random salt)
router.post('/register-secure', (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // REMEDIATION: Cryptographically secure random salt + PBKDF2 key derivation (SHA-512, 100,000 iterations)
  const salt = crypto.randomBytes(16).toString('hex');
  const secureHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  const storedValue = `${salt}:${secureHash}`;

  return res.json({
    status: 'success',
    remediation: 'PBKDF2-HMAC-SHA512 with 16-byte random salt and 100,000 iterations',
    storedRepresentation: storedValue
  });
});

module.exports = router;
