/** Combine real image and IaC scan results for the Markdown summary. */
const fs = require('fs');

function readReport(filename) {
  const report = JSON.parse(fs.readFileSync(filename, 'utf8'));
  if (!report || typeof report !== 'object' || Array.isArray(report) ||
      !Number.isInteger(report.SchemaVersion) ||
      (report.Results != null && !Array.isArray(report.Results))) {
    throw new Error(`Invalid Trivy JSON report: ${filename}`);
  }
  return report;
}

try {
  // Require both scans so a partial scan cannot produce a misleading clean summary.
  const image = readReport('trivy-image-results.json');
  const config = readReport('trivy-config-results.json');
  const combined = {
    SchemaVersion: image.SchemaVersion,
    Results: [...(image.Results || []), ...(config.Results || [])],
  };
  fs.writeFileSync('trivy-report.json', JSON.stringify(combined, null, 2) + '\n');
} catch (error) {
  console.error(`Unable to combine Trivy reports: ${error.message}`);
  process.exitCode = 1;
}
