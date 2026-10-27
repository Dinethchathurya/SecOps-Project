# ==============================================================================
# FLAW CATEGORY 4: CONTAINER IMAGE & OS MISCONFIGURATIONS (Target: Trivy)
# ==============================================================================
# Scanner Target: Trivy (Container Image Vulnerabilities & Dockerfile Misconfigurations)
#
# Specific Flaws Introduced for Trivy Benchmarking:
# 1. Outdated Base Image: node:14.21.3-alpine3.17 contains multiple unpatched High
#    and Critical CVEs in musl, openssl, busybox, zlib, and libcrypto.
# 2. Insecure Root Execution: Running as 'USER root' allows container escape vectors
#    and violates principle of least privilege (Trivy Rule: DS002 / AVD-DS-0002).
# 3. Excessive Attack Surface: Installing unnecessary network inspection & debugging
#    tools (curl, netcat, telnet) in production container.
# 4. Sensitive Ports Exposed: Port 22 (SSH) and 8080 exposed alongside app port 3000.
# 5. Missing HEALTHCHECK: Trivy flags containers missing container health monitoring.
# ==============================================================================

# FLAW 1: Outdated, end-of-life base image with known OS CVEs
#FROM node:14.21.3-alpine3.17
FROM node:16.3.0-alpine

# Set working directory
WORKDIR /app

# FLAW 2: Explicitly running as root user (violates least privilege)
#USER root

# FIX 2 & 3: Create a non-root user, set permissions, remove production bloat, and switch users
RUN addgroup -S appgroup && adduser -S appuser -G appgroup && \
    chown -R appuser:appgroup /app

# Switch to the non-root user for all subsequent instructions (like CMD or ENTRYPOINT)
USER appuser

# FLAW 3: Installing unnecessary debugging and network tools in production runtime
# Note: busybox-extras provides telnet; curl and netcat-openbsd provide network extraction
RUN apk update && \
    apk add --no-cache \
    curl \
    netcat-openbsd \
    busybox-extras \
    bash \
    python3 \
    make \
    g++

# Copy package manifest files
COPY package*.json ./

# Install application dependencies (including vulnerable lodash, axios, jsonwebtoken)
# Note: --ignore-scripts or regular install
RUN npm install --legacy-peer-deps

# Copy application source code
COPY . .

# Ensure data directory exists with write permissions
RUN mkdir -p /app/data

# FLAW 4: Exposing sensitive unnecessary administrative ports (SSH port 22, debug port 8080)
#EXPOSE 3000 22 8080
EXPOSE 3000 8080 22

# Environment variables
ENV NODE_ENV=production
ENV PORT=3000

# FLAW 5: No HEALTHCHECK instruction defined (triggers Dockerfile misconfiguration scanner)

# Launch application as root
CMD ["node", "src/server.js"]
