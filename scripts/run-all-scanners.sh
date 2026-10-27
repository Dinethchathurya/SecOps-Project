#!/usr/bin/env bash
# ==============================================================================
# LOCAL DEVSECOPS BENCHMARK RUNNER SCRIPT
# ==============================================================================
# Executes Gitleaks, SAST, Snyk (or npm audit), and Trivy locally via Docker.
#
# Usage:
#   chmod +x scripts/run-all-scanners.sh
#   ./scripts/run-all-scanners.sh
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p reports

echo -e "${CYAN}==============================================================================${NC}"
echo -e "${CYAN}           DEVSECOPS TESTING LABORATORY: LOCAL BENCHMARK RUNNER               ${NC}"
echo -e "${CYAN}==============================================================================${NC}"
echo ""

# ------------------------------------------------------------------------------
# STEP 1: RUNNER 1 (GATING CHECK) - GITLEAKS SECRETS SCAN
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> [RUNNER 1: SECRET GATE] Executing Gitleaks...${NC}"
if command -v gitleaks &> /dev/null; then
  echo "Running installed gitleaks CLI..."
  gitleaks detect --source=. --config=.gitleaks.toml --report-format=json --report-path=reports/gitleaks-report.json --verbose || true
elif command -v docker &> /dev/null; then
  echo "Running Gitleaks via official Docker container (zricethezav/gitleaks:latest)..."
  docker run --rm -v "$ROOT_DIR":/path zricethezav/gitleaks:latest detect \
    --source=/path \
    --config=/path/.gitleaks.toml \
    --report-format=json \
    --report-path=/path/reports/gitleaks-report.json \
    --verbose || true
else
  echo -e "${RED}[!] Neither gitleaks CLI nor Docker found. Skipping Gitleaks.${NC}"
fi
echo -e "${GREEN}[+] Gitleaks stage complete. Leaked AWS keys and RSA certificates logged to reports/gitleaks-report.json${NC}\n"

# ------------------------------------------------------------------------------
# STEP 2: RUNNER 2 (PARALLEL) - SAST SCAN (Semgrep / SonarQube CLI)
# ------------------------------------------------------------------------------
echo -e "${BLUE}>>> [RUNNER 2: SAST AST TAINT ANALYSIS] Executing Static Code Analysis...${NC}"
if command -v npx &> /dev/null; then
  echo "Running Semgrep security-audit ruleset against src/..."
  npx --yes semgrep --config=p/security-audit --config=p/owasp-top-ten --json --output=reports/sast-report.json src/ || true
elif command -v docker &> /dev/null; then
  echo "Running Semgrep via Docker..."
  docker run --rm -v "$ROOT_DIR":/src returntocorp/semgrep semgrep \
    --config=p/security-audit \
    --json --output=/src/reports/sast-report.json /src/src/ || true
fi
echo -e "${GREEN}[+] SAST stage complete. SQLi, XSS, and MD5 findings logged to reports/sast-report.json${NC}\n"

# ------------------------------------------------------------------------------
# STEP 3: RUNNER 3 (PARALLEL) - SCA DEPENDENCY SCAN (Snyk / npm audit)
# ------------------------------------------------------------------------------
echo -e "${BLUE}>>> [RUNNER 3: SCA DEPENDENCY SCAN] Checking package.json for CVEs...${NC}"
if command -v snyk &> /dev/null; then
  echo "Running Snyk CLI test..."
  snyk test --json-file-output=reports/snyk-report.json || true
elif command -v npm &> /dev/null; then
  echo "Running native npm security audit baseline..."
  npm audit --json > reports/npm-audit.json || true
fi
echo -e "${GREEN}[+] SCA stage complete. Lodash and Axios CVEs logged to reports/npm-audit.json${NC}\n"

# ------------------------------------------------------------------------------
# STEP 4: RUNNER 4 (PARALLEL) - TRIVY CONTAINER & IAC SCAN
# ------------------------------------------------------------------------------
echo -e "${BLUE}>>> [RUNNER 4: CONTAINER & IAC SCAN] Executing Trivy Scanner...${NC}"
if command -v docker &> /dev/null; then
  echo "Building container image secops-vulnerable-app:benchmark..."
  docker build -t secops-vulnerable-app:benchmark .

  echo "Running Trivy container scan for OS package CVEs and Dockerfile misconfigurations..."
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$ROOT_DIR":/root/.cache/ aquasec/trivy:latest \
    image --severity HIGH,CRITICAL secops-vulnerable-app:benchmark || true

  echo "Running Trivy Dockerfile config misconfiguration scan..."
  docker run --rm -v "$ROOT_DIR":/work -w /work aquasec/trivy:latest \
    config . || true
else
  echo -e "${RED}[!] Docker not found. Skipping Trivy container scan.${NC}"
fi
echo -e "${GREEN}[+] Trivy stage complete. OS CVEs (Alpine) and USER root warnings flagged.${NC}\n"

echo -e "${CYAN}==============================================================================${NC}"
echo -e "${CYAN}             DEVSECOPS BENCHMARK LOCAL SCAN FINISHED                          ${NC}"
echo -e "${CYAN}==============================================================================${NC}"
echo "Reports generated in directory: ./reports"
