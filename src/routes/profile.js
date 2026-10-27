const express = require('express');
const router = express.Router();

/**
 * ==============================================================================
 * FLAW CATEGORY 2.2: APPLICATION CODE FLAW / SAST (Target: SonarQube / SonarCloud)
 * VULNERABILITY: Reflected Cross-Site Scripting (XSS) (CWE-79 / OWASP Top 10 A03)
 * ==============================================================================
 * Scanner Target: SonarCloud / SonarQube (Rules: javascript:S5131, javascript:S5147)
 *
 * Why SonarCloud catches it:
 *   SonarCloud's taint engine tracks user-controlled input (`req.query.name`) entering
 *   the HTTP response stream (`res.send(...)`) as raw unescaped HTML without context-
 *   aware sanitization or encoding.
 *
 * Why Gitleaks ignores it:
 *   Gitleaks scans git diffs/files for credentials; HTML reflection is not a secret.
 *
 * Why Snyk SCA ignores it:
 *   Reflected XSS here is written in custom Express route code, not in a package vulnerability.
 *
 * Why Trivy ignores it:
 *   Trivy scans container OS layers and IaC manifests, not node runtime responses.
 * ==============================================================================
 */

// VULNERABLE ENDPOINT: Reflected XSS via raw HTML template string concatenation
router.get('/greeting', (req, res) => {
  const name = req.query.name || 'Guest User';

  // INTENTIONAL FLAW: Injecting unsanitized input directly into raw HTML template
  // Exploit Payload: <script>alert('DevSecOps Reflected XSS Exploit!')</script>
  // Exploit Payload: <img src="x" onerror="alert('XSS Attack: ' + document.cookie)">
  const htmlResponse = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Profile Greeting - Vulnerable Page</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 2rem; background: #0f172a; color: #f8fafc; }
        .card { background: #1e293b; border-radius: 8px; padding: 2rem; max-width: 600px; margin: 0 auto; border: 1px solid #ef4444; }
        .tag { display: inline-block; background: #dc2626; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        a { color: #38bdf8; text-decoration: none; }
      </style>
    </head>
    <body>
      <div class="card">
        <span class="tag">VULNERABILITY: REFLECTED XSS (CWE-79)</span>
        <h1>Welcome, ${name}!</h1>
        <p>This page reflects your name query parameter without HTML entity encoding or Content-Security-Policy headers.</p>
        <hr style="border-color: #334155; margin: 1.5rem 0;">
        <p><a href="/">&larr; Return to DevSecOps Lab Portal</a></p>
      </div>
    </body>
    </html>
  `;

  res.setHeader('Content-Type', 'text/html');
  return res.send(htmlResponse);
});

// REMEDIATED ENDPOINT: Escaped HTML response
router.get('/greeting-secure', (req, res) => {
  const name = req.query.name || 'Guest User';

  // Helper function to escape HTML entities
  const escapeHtml = (str) => {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };

  const safeName = escapeHtml(name);
  const htmlResponse = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Profile Greeting - Secure Page</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 2rem; background: #0f172a; color: #f8fafc; }
        .card { background: #1e293b; border-radius: 8px; padding: 2rem; max-width: 600px; margin: 0 auto; border: 1px solid #10b981; }
        .tag { display: inline-block; background: #059669; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        a { color: #38bdf8; text-decoration: none; }
      </style>
    </head>
    <body>
      <div class="card">
        <span class="tag">REMEDIATED: CONTEXT-AWARE ENCODING</span>
        <h1>Welcome, ${safeName}!</h1>
        <p>This page safely sanitizes and encodes user input before injecting it into the DOM.</p>
        <hr style="border-color: #334155; margin: 1.5rem 0;">
        <p><a href="/">&larr; Return to DevSecOps Lab Portal</a></p>
      </div>
    </body>
    </html>
  `;

  res.setHeader('Content-Type', 'text/html');
  return res.send(htmlResponse);
});

module.exports = router;
