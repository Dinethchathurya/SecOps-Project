const express = require('express');
const router = express.Router();
const _ = require('lodash'); // vulnerable lodash 4.17.15
const axios = require('axios'); // vulnerable axios 0.21.1

/**
 * ==============================================================================
 * FLAW CATEGORY 3: OUTDATED & COMPROMISED DEPENDENCIES / SCA (Target: Snyk)
 * VULNERABILITY: Prototype Pollution (lodash@4.17.15) & SSRF (axios@0.21.1)
 * ==============================================================================
 * Scanner Target: Snyk SCA (CVE-2019-10744, CVE-2020-8203, CVE-2020-28168)
 *
 * Why Snyk SCA catches it:
 *   Snyk analyzes `package.json` against its comprehensive vulnerability database,
 *   matching exact installed versions of `lodash`, `axios`, and `jsonwebtoken`
 *   to published CVEs and security advisories.
 *
 * Why Gitleaks ignores it:
 *   Package dependencies are public metadata, not high-entropy secrets or private keys.
 *
 * Why SonarCloud SAST (without SCA) ignores it:
 *   Standard SAST scans custom AST syntax. Unless deep SCA or third-party analysis is
 *   enabled, SAST does not correlate dependency versions with public CVE feeds.
 *
 * Why Trivy Container Scan (if scanning only OS) ignores it:
 *   If Trivy is configured only for OS packages, it misses language-specific manifests;
 *   however, Trivy fs scan also flags it, providing a great cross-comparison!
 * ==============================================================================
 */

// VULNERABLE ENDPOINT: Prototype Pollution via lodash.merge (CVE-2019-10744 / CVE-2020-8203)
// Exploit Payload: { "__proto__": { "polluted": "Contaminated!" } } or { "constructor": { "prototype": { "polluted": "Contaminated!" } } }
router.post('/merge', (req, res) => {
  const targetObject = { system: 'secops-lab', status: 'operational' };
  const userInput = req.body;

  try {
    // INTENTIONAL FLAW: lodash.merge on vulnerable 4.17.15 modifies prototypes
    _.merge(targetObject, userInput);

    // Also support deep merge if passed as json string
    if (userInput && userInput.jsonPayload) {
      const parsed = JSON.parse(userInput.jsonPayload);
      _.merge(targetObject, parsed);
    }

    const testObject = {};
    const pollutedValue = testObject.polluted || Object.prototype.polluted || null;
    const isPolluted = (pollutedValue !== null);

    return res.json({
      status: 'success',
      vulnerability: 'Prototype Pollution (CVE-2019-10744 / CVE-2020-8203 via lodash@4.17.15)',
      scannerTarget: 'Snyk SCA',
      mergedResult: targetObject,
      isPrototypePolluted: isPolluted,
      pollutedValue: pollutedValue,
      message: isPolluted
        ? 'ALERT: Object.prototype has been polluted across the entire Node.js runtime!'
        : 'Pass payload {"constructor": {"prototype": {"polluted": "value"}}} to trigger pollution'
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// VULNERABLE ENDPOINT: Unvalidated external request using vulnerable axios
router.get('/fetch-url', async (req, res) => {
  const targetUrl = req.query.url;

  if (!targetUrl) {
    return res.status(400).json({ error: 'Missing url query parameter' });
  }

  try {
    // INTENTIONAL FLAW: Unvalidated SSRF + vulnerable axios 0.21.1 (CVE-2020-28168)
    const response = await axios.get(targetUrl, { timeout: 3000 });
    return res.json({
      status: 'success',
      fetchedUrl: targetUrl,
      dataSnippet: typeof response.data === 'string' ? response.data.substring(0, 200) : response.data
    });
  } catch (err) {
    return res.status(502).json({
      status: 'error',
      message: 'Failed to fetch external resource',
      details: err.message
    });
  }
});

module.exports = router;
