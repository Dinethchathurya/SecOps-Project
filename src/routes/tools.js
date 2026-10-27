const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * ==============================================================================
 * FLAW CATEGORY 2.4: COMMAND INJECTION & PATH TRAVERSAL (Target: SonarCloud / SAST)
 * ==============================================================================
 * Vulnerabilities:
 * 1. OS Command Injection (CWE-78 / OWASP A03:2021-Injection)
 *    SonarCloud Rule: javascript:S2076 / javascript:S4721
 * 2. Path Traversal / Arbitrary File Read (CWE-22 / OWASP A01:2021)
 *    SonarCloud Rule: javascript:S2083
 * ==============================================================================
 */

// VULNERABLE ENDPOINT 1: OS Command Injection via child_process.exec
// Exploit Payload: 127.0.0.1; whoami; id; ls -la
router.get('/ping', (req, res) => {
  const host = req.query.host || '127.0.0.1';

  // INTENTIONAL FLAW: Unsanitized user input concatenated into shell command string
  const cmd = `ping -c 1 ${host}`;

  console.log(`[Command Injection] Executing shell command: ${cmd}`);

  exec(cmd, (error, stdout, stderr) => {
    return res.json({
      status: 'executed',
      vulnerability: 'OS Command Injection (CWE-78)',
      scannerTarget: 'SonarCloud / SAST (Rule: javascript:S2076)',
      commandExecuted: cmd,
      output: stdout || stderr,
      error: error ? error.message : null
    });
  });
});

// VULNERABLE ENDPOINT 2: Path Traversal / Arbitrary File Read via fs.readFileSync
// Exploit Payload: ../../package.json or ../../.env.example
router.get('/read-log', (req, res) => {
  const fileName = req.query.file || 'audit.log';

  // INTENTIONAL FLAW: Direct path concatenation without normalization or boundary check
  const targetPath = path.join(__dirname, '../../data', fileName);

  try {
    const fileContent = fs.readFileSync(targetPath, 'utf8');
    return res.json({
      status: 'success',
      vulnerability: 'Path Traversal (CWE-22)',
      scannerTarget: 'SonarCloud / SAST (Rule: javascript:S2083)',
      accessedPath: targetPath,
      content: fileContent
    });
  } catch (err) {
    return res.status(404).json({
      status: 'error',
      vulnerability: 'Path Traversal (CWE-22)',
      message: 'Failed to read file',
      attemptedPath: targetPath,
      error: err.message
    });
  }
});

module.exports = router;
