/**
 * Render security tool JSON reports as GitHub Actions Markdown summaries.
 */
const fs = require('fs');
const path = require('path');

const summaryFile = process.env.GITHUB_STEP_SUMMARY;
const target = process.argv[2];

function appendSummary(markdown) {
  if (summaryFile) {
    fs.appendFileSync(summaryFile, markdown + '\n\n', 'utf8');
  } else {
    console.log(markdown);
  }
}

function cell(value) {
  return String(value ?? '—')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\|/g, '&#124;')
    .replace(/`/g, '&#96;')
    .replace(/\*/g, '&#42;')
    .replace(/_/g, '&#95;')
    .replace(/\[/g, '&#91;')
    .replace(/\]/g, '&#93;')
    .replace(/\\/g, '&#92;')
    .replace(/\r\n|\r|\n/g, '<br>');
}

function table(headers, rows) {
  appendSummary([
    `| ${headers.map(cell).join(' | ')} |`,
    `| ${headers.map(() => '---').join(' | ')} |`,
    ...rows.map((row) => `| ${row.map(cell).join(' | ')} |`),
  ].join('\n'));
}

function truncate(value, length) {
  const text = String(value ?? '');
  return text.length > length ? text.slice(0, length) + '...' : text;
}

function renderReport(filenames, render) {
  const filename = filenames.find((name) => fs.existsSync(path.join(process.cwd(), name)));
  if (!filename) {
    appendSummary(`*Report file ${filenames.map(cell).join(' or ')} not found.*`);
    return;
  }
  try {
    render(JSON.parse(fs.readFileSync(path.join(process.cwd(), filename), 'utf8')));
  } catch (error) {
    appendSummary(`⚠️ Could not read or parse ${cell(filename)}: ${cell(error.message)}`);
    process.exitCode = 1;
  }
}

function findingsArray(value, field) {
  if (!Array.isArray(value)) {
    throw new Error(`Expected ${field} to be an array.`);
  }
  return value;
}

switch (target) {
  case 'gitleaks': {
    appendSummary('## 🔑 Runner 1: Gitleaks Secrets Gate Findings');
    renderReport(['gitleaks-report.json'], (data) => {
      const findings = findingsArray(data, 'Gitleaks findings');
      if (findings.length === 0) {
        appendSummary('✅ No secrets detected.');
        return;
      }
      table(['Description', 'Rule ID', 'File', 'Start Line', 'Secret Snippet'],
        findings.map((finding) => [
          finding.Description, finding.RuleID, finding.File, finding.StartLine,
          truncate(finding.Secret || finding.Match, 28),
        ]));
      appendSummary(`**Total Secrets Flagged**: ${findings.length}`);
    });
    break;
  }

  case 'sast': {
    appendSummary('## 🛡️ Runner 2: SAST (Semgrep) Findings');
    renderReport(['sast-results.json'], (data) => {
      const results = findingsArray(data.results, 'results');
      if (results.length === 0) {
        appendSummary('✅ No vulnerabilities or issues detected.');
        return;
      }
      table(['Severity', 'Rule ID', 'CWE', 'File', 'Start Line', 'Snippet / Message'],
        results.map((result) => {
          const extra = result.extra || {};
          const cwe = extra.metadata?.cwe;
          const context = [extra.lines, extra.message].filter(Boolean).join('\n');
          return [extra.severity, result.check_id, Array.isArray(cwe) ? cwe.join(', ') : cwe,
            result.path, result.start?.line, context || undefined];
        }));
      appendSummary(`**Total SAST Findings**: ${results.length}`);
    });
    break;
  }

  case 'sca': {
    appendSummary('## 📦 Runner 3: SCA (npm audit) Findings');
    renderReport(['reports/npm-audit.json', 'npm-audit.json'], (data) => {
      const vulnerabilities = data.vulnerabilities;
      if (!vulnerabilities || typeof vulnerabilities !== 'object' || Array.isArray(vulnerabilities)) {
        throw new Error('Expected vulnerabilities to be an object.');
      }
      const entries = Object.entries(vulnerabilities);
      if (entries.length === 0) {
        appendSummary('✅ No vulnerabilities or issues detected.');
        return;
      }
      table(['Package', 'Severity', 'Vulnerability / Advisory', 'Vulnerable Range', 'Fix Available'],
        entries.map(([packageName, vulnerability]) => {
          const advisories = (Array.isArray(vulnerability.via) ? vulnerability.via : [])
            .map((via) => typeof via === 'string' ? via : [via.title, via.url || via.source].filter(Boolean).join(' — '));
          const fix = vulnerability.fixAvailable;
          const fixText = fix && typeof fix === 'object'
            ? [fix.name, fix.version].filter(Boolean).join('@') || 'Available (version not specified)'
            : fix === true ? 'Available (version not specified)' : fix === false ? 'Not available' : undefined;
          return [vulnerability.name || packageName, vulnerability.severity,
            advisories.join('\n') || undefined, vulnerability.range, fixText];
        }));
    });
    break;
  }

  case 'trivy': {
    appendSummary('## 🐳 Runner 4: Trivy Container & IaC Security Findings');
    renderReport(['trivy-report.json'], (data) => {
      const results = findingsArray(data.Results ?? [], 'Results');
      const misconfigurations = [];
      const vulnerabilities = [];
      results.forEach((result) => {
        findingsArray(result.Misconfigurations ?? [], 'Misconfigurations').forEach((finding) => {
          misconfigurations.push([result.Target, finding.Severity, finding.ID,
            finding.Title || finding.Message, finding.Resolution || finding.Description]);
        });
        findingsArray(result.Vulnerabilities ?? [], 'Vulnerabilities').forEach((finding) => {
          vulnerabilities.push([result.Target, finding.Severity, finding.PkgName,
            finding.InstalledVersion, finding.FixedVersion, finding.VulnerabilityID]);
        });
      });
      if (misconfigurations.length === 0 && vulnerabilities.length === 0) {
        appendSummary('✅ No container or IaC issues detected.');
        return;
      }
      if (misconfigurations.length > 0) {
        appendSummary('### Misconfigurations / IaC');
        table(['Target', 'Severity', 'ID', 'Title / Message', 'Resolution / Description'], misconfigurations);
      }
      if (vulnerabilities.length > 0) {
        appendSummary('### OS / Package Vulnerabilities');
        table(['Target', 'Severity', 'Package', 'Installed Version', 'Fixed Version', 'Vulnerability ID (CVE)'], vulnerabilities);
      }
    });
    break;
  }
}
