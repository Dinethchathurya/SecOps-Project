const express = require('express');
const router = express.Router();
const db = require('../config/db');

/**
 * ==============================================================================
 * FLAW CATEGORY 2.1: APPLICATION CODE FLAW / SAST (Target: SonarQube / SonarCloud)
 * VULNERABILITY: SQL Injection (CWE-89 / OWASP Top 10 A03:2021-Injection)
 * ==============================================================================
 * Scanner Target: SonarCloud / SonarQube (Rules: javascript:S3649, javascript:S2077)
 *
 * Why SonarCloud catches it:
 *   SonarCloud performs Abstract Syntax Tree (AST) Taint Analysis. It tracks the
 *   untrusted data source (`req.query.query`) flowing directly into an SQL execution
 *   sink (`db.all`) via unescaped string concatenation.
 *
 * Why Gitleaks ignores it:
 *   Gitleaks only scans regex patterns for high-entropy secrets and credentials,
 *   having zero visibility into code dataflow or syntax trees.
 *
 * Why Snyk SCA ignores it:
 *   Snyk SCA inspects manifests (`package.json`) for known library CVEs, not custom
 *   application logic flaws (unless using Snyk Code SAST).
 *
 * Why Trivy ignores it:
 *   Trivy scans container OS packages and Dockerfile syntax, not in-memory code paths.
 * ==============================================================================
 */

// VULNERABLE ENDPOINT: Raw SQL string concatenation
router.get('/search', (req, res) => {
  const userQuery = req.query.query || '';

  // INTENTIONAL FLAW: Direct string concatenation of untrusted user input into SQL
  // Exploit Payload: ' OR '1'='1' -- 
  const rawSql = "SELECT id, username, email, role, bio FROM users WHERE username = '" + userQuery + "' OR email = '" + userQuery + "'";

  console.log(`[SQLi Route] Executing raw query: ${rawSql}`);

  db.all(rawSql, [], (err, rows) => {
    if (err) {
      return res.status(500).json({
        status: 'error',
        message: 'Database query execution failed',
        error: err.message,
        executedQuery: rawSql // Extra flaw: Leaking raw SQL error in response
      });
    }

    return res.json({
      status: 'success',
      vulnerability: 'SQL Injection (CWE-89)',
      scannerTarget: 'SonarQube / SonarCloud (Rule: javascript:S3649)',
      queryExecuted: rawSql,
      resultsCount: rows.length,
      data: rows
    });
  });
});

// REMEDIATED ENDPOINT (For benchmark comparison & educational remediation)
router.get('/search-secure', (req, res) => {
  const userQuery = req.query.query || '';

  // REMEDIATION: Using parameterized queries with placeholder bindings
  const secureSql = "SELECT id, username, email, role, bio FROM users WHERE username = ? OR email = ?";

  db.all(secureSql, [userQuery, userQuery], (err, rows) => {
    if (err) {
      return res.status(500).json({ status: 'error', message: 'Internal server error' });
    }
    return res.json({
      status: 'success',
      remediation: 'Parameterized Query (Prepared Statement)',
      data: rows
    });
  });
});

// Listing all users for frontend UI
router.get('/all', (req, res) => {
  db.all("SELECT id, username, email, role, bio FROM users", [], (err, rows) => {
    if (err) {
      return res.status(500).json({ status: 'error', message: err.message });
    }
    return res.json({ users: rows });
  });
});

module.exports = router;
