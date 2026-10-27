const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

// Initialize database
const db = require('./config/db');

// Import intentionally vulnerable routes
const usersRoutes = require('./routes/users');
const profileRoutes = require('./routes/profile');
const authRoutes = require('./routes/auth');
const dataRoutes = require('./routes/data');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve frontend static assets
app.use(express.static(path.join(__dirname, '../public')));

// Mount vulnerability demonstration routes
app.use('/api/users', usersRoutes);
app.use('/profile', profileRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/data', dataRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    lab: 'DevSecOps Vulnerability Testing Laboratory',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  });
});

// API Info endpoint mapping flaws to scanners
app.get('/api/info', (req, res) => {
  res.json({
    project: "SecOps Vulnerability Benchmark Lab",
    benchmarkMapping: {
      gitleaks: [
        { flaw: "AWS IAM Keys", path: ".env.example", target: "Gitleaks" },
        { flaw: "Private RSA Key", path: "src/config/jwtRS256.key", target: "Gitleaks" },
        { flaw: "Database Connection URI", path: "src/config/secrets.js", target: "Gitleaks" }
      ],
      sonarCloud: [
        { flaw: "SQL Injection", path: "/api/users/search", cwe: "CWE-89", target: "SonarCloud SAST" },
        { flaw: "Reflected XSS", path: "/profile/greeting", cwe: "CWE-79", target: "SonarCloud SAST" },
        { flaw: "Insecure Cryptography (MD5)", path: "/api/auth/register-insecure", cwe: "CWE-327", target: "SonarCloud SAST" }
      ],
      snyk: [
        { flaw: "Prototype Pollution", package: "lodash@4.17.15", cve: "CVE-2019-10744", target: "Snyk SCA" },
        { flaw: "Algorithm Confusion", package: "jsonwebtoken@8.5.1", cve: "CVE-2022-23529", target: "Snyk SCA" },
        { flaw: "SSRF & ReDoS", package: "axios@0.21.1", cve: "CVE-2020-28168", target: "Snyk SCA" }
      ],
      trivy: [
        { flaw: "Outdated Alpine Base OS", detail: "node:14.21.3-alpine3.17 carrying high/critical CVEs", target: "Trivy Container" },
        { flaw: "Container runs as USER root", detail: "Root execution misconfiguration", target: "Trivy Misconfig/IaC" },
        { flaw: "Debugging tools installed", detail: "curl, netcat, telnet inside production image", target: "Trivy Image Scan" }
      ]
    }
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[Application Error]:', err.stack);
  res.status(500).json({
    status: 'error',
    message: err.message || 'Internal Server Error'
  });
});

// Start listening
app.listen(PORT, '0.0.0.0', () => {
  console.log(`================================================================`);
  console.log(`[*] DevSecOps Testing Laboratory is active and listening on port ${PORT}`);
  console.log(`[*] Access Dashboard: http://localhost:${PORT}`);
  console.log(`[*] Target Flaws: Gitleaks (Secrets) | SonarCloud (SAST) | Snyk (SCA) | Trivy (Container)`);
  console.log(`================================================================`);
});

module.exports = app;
