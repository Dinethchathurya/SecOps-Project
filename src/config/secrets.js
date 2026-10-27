/**
 * ==============================================================================
 * FLAW CATEGORY 1: SECRETS & CREDENTIALS (Target: Gitleaks)
 * ==============================================================================
 * This configuration file intentionally embeds hardcoded AWS credentials and API
 * tokens directly into source control to demonstrate secrets detection.
 *
 * Scanner Target: Gitleaks (Regex & Entropy Secret Hunting)
 * Why Ignored by SAST: SAST focuses on code dataflow, AST taint, and injection flaws,
 *                      often ignoring configuration patterns unless custom rules exist.
 * Why Ignored by SCA:  SCA checks third-party package manifests, not repo secrets.
 * Why Ignored by Trivy: Trivy OS container scan inspects installed packages/binaries,
 *                       not commit history or source files.
 * ==============================================================================
 */

module.exports = {
  aws: {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region: "us-east-1",
    s3Bucket: "prod-customer-backups-internal"
  },
  database: {
    // Accidentally hardcoded connection string with admin credentials
    uri: "postgres://db_master_user:MasterP@ssw0rd2024Secure!@internal-db.secops.local:5432/customer_records"
  },
  payment: {
    stripeApiKey: "sk_live_51HzT99KzL9876543210abcdefgEXAMPLEKEY998877665544"
  },
  jwtSecret: "hardcoded-static-jwt-secret-key-12345"
};
