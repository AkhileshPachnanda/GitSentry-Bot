const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const VULNERABLE_PACKAGES = {
  'lodash': {
    versions: ['< 4.17.21'],
    severity: 'high',
    title: 'Prototype Pollution in lodash',
    cve: 'CVE-2020-8203'
  },
  'lodash.includes': {
    versions: ['< 4.3.1'],
    severity: 'high',
    title: 'Prototype Pollution in lodash.includes',
    cve: 'CVE-2020-8203'
  },
  'lodash.isboolean': {
    versions: ['< 3.0.4'],
    severity: 'high',
    title: 'Prototype Pollution in lodash.isboolean',
    cve: 'CVE-2020-8203'
  },
  'lodash.isinteger': {
    versions: ['< 4.0.5'],
    severity: 'high',
    title: 'Prototype Pollution in lodash.isinteger',
    cve: 'CVE-2020-8203'
  },
  'lodash.isnumber': {
    versions: ['< 3.0.4'],
    severity: 'high',
    title: 'Prototype Pollution in lodash.isnumber',
    cve: 'CVE-2020-8203'
  },
  'lodash.isplainobject': {
    versions: ['< 4.0.7'],
    severity: 'high',
    title: 'Prototype Pollution in lodash.isplainobject',
    cve: 'CVE-2020-8203'
  },
  'lodash.isstring': {
    versions: ['< 4.0.2'],
    severity: 'high',
    title: 'Prototype Pollution in lodash.isstring',
    cve: 'CVE-2020-8203'
  },
  'lodash.once': {
    versions: ['< 4.1.2'],
    severity: 'high',
    title: 'Prototype Pollution in lodash.once',
    cve: 'CVE-2020-8203'
  },
  'express': {
    versions: ['< 4.17.3'],
    severity: 'medium',
    title: 'qs vulnerability in Express',
    cve: 'CVE-2022-24999'
  },
  'axios': {
    versions: ['< 1.6.0'],
    severity: 'medium',
    title: 'Server-Side Request Forgery in axios',
    cve: 'CVE-2023-45857'
  }
};

function isVersionVulnerable(version, vulnerableRanges) {
  if (!version) return false;
  const cleanVersion = version.replace(/^v/, '').trim();
  for (const range of vulnerableRanges) {
    if (range.includes('<')) {
      const maxVersion = range.replace('<', '').trim();
      if (compareVersions(cleanVersion, maxVersion) < 0) return true;
    }
  }
  return false;
}

function compareVersions(v1, v2) {
  v1 = v1.replace(/^v/, '').trim();
  v2 = v2.replace(/^v/, '').trim();
  const parts1 = v1.split('.').map(Number);
  const parts2 = v2.split('.').map(Number);
  for (let i = 0; i < Math.min(parts1.length, parts2.length); i++) {
    if (isNaN(parts1[i]) || isNaN(parts2[i])) {
      return v1.localeCompare(v2);
    }
    if (parts1[i] !== parts2[i]) {
      return parts1[i] - parts2[i];
    }
  }
  return parts1.length - parts2.length;
}

async function fetchFileContent(octokit, owner, repo, filePath, ref) {
  console.log('Fetching file: ' + filePath + ' (ref: ' + ref + ')');
  try {
    const response = await octokit.repos.getContent({
      owner,
      repo,
      path: filePath,
      ref
    });
    const content = Buffer.from(response.data.content, 'base64').toString('utf8');
    console.log('File fetched, size: ' + content.length + ' chars');
    return content;
  } catch (error) {
    console.error('Could not fetch ' + filePath + ':', error.message);
    return null;
  }
}

async function parseLockfileForVulnerabilities(lockContent) {
  const findings = [];
  try {
    const lockData = JSON.parse(lockContent);
    const packages = lockData.packages || {};
    const rootPkg = packages[''] || {};
    const rootDeps = rootPkg.dependencies || {};
    
    console.log('Checking root dependencies for vulnerabilities...');
    for (const [pkgName, pkgVersion] of Object.entries(rootDeps)) {
      const vulnInfo = VULNERABLE_PACKAGES[pkgName];
      if (vulnInfo && isVersionVulnerable(pkgVersion, vulnInfo.versions)) {
        console.log('Found vulnerable root dependency: ' + pkgName + '@' + pkgVersion);
        findings.push({
          package: pkgName,
          severity: vulnInfo.severity,
          title: vulnInfo.title,
          cve: vulnInfo.cve,
          vulnerable_versions: vulnInfo.versions.join(', '),
          category: 'dependency'
        });
      }
    }

    console.log('Checking packages section...');
    for (const [pkgName, pkgInfo] of Object.entries(packages)) {
      if (pkgName && pkgName !== '' && pkgInfo.version) {
        const shortName = pkgName.replace(/^node_modules\//, '');
        const vulnInfo = VULNERABLE_PACKAGES[shortName];
        if (vulnInfo && isVersionVulnerable(pkgInfo.version, vulnInfo.versions)) {
          console.log('Found vulnerable package: ' + shortName + '@' + pkgInfo.version);
          findings.push({
            package: shortName,
            severity: vulnInfo.severity,
            title: vulnInfo.title,
            cve: vulnInfo.cve,
            vulnerable_versions: vulnInfo.versions.join(', '),
            category: 'dependency'
          });
        }
        if (shortName.startsWith('lodash.')) {
          const baseVuln = VULNERABLE_PACKAGES['lodash'];
          if (baseVuln && isVersionVulnerable(pkgInfo.version, baseVuln.versions)) {
            console.log('Found vulnerable lodash sub-package: ' + shortName + '@' + pkgInfo.version);
            findings.push({
              package: shortName,
              severity: baseVuln.severity,
              title: baseVuln.title + ' (in ' + shortName + ')',
              cve: baseVuln.cve,
              vulnerable_versions: baseVuln.versions.join(', '),
              category: 'dependency'
            });
          }
        }
      }
    }
    console.log('Total vulnerable packages found in lockfile: ' + findings.length);
  } catch (e) {
    console.error('Failed to parse lockfile: ' + e.message);
  }
  return findings;
}

async function runNpmAudit(pkgContent, lockContent) {
  console.log('Running npm audit');
  return new Promise((resolve) => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsentry-'));
    const pkgPath = path.join(tempDir, 'package.json');
    fs.writeFileSync(pkgPath, pkgContent);
    if (lockContent) {
      const lockPath = path.join(tempDir, 'package-lock.json');
      fs.writeFileSync(lockPath, lockContent);
      console.log('Created temp package-lock.json');
    }
    console.log('Created temp package.json');

    const timeout = setTimeout(() => {
      console.error('npm audit timed out');
      fs.rmSync(tempDir, { recursive: true, force: true });
      resolve([]);
    }, 30000);

    exec('npm audit --json', { cwd: tempDir, timeout: 25000 }, (error, stdout, stderr) => {
      clearTimeout(timeout);
      fs.rmSync(tempDir, { recursive: true, force: true });

      if (stdout) console.log('stdout preview: ' + stdout.substring(0, 300));
      if (error && !stdout) {
        console.error('npm audit failed with no output');
        resolve([]);
        return;
      }
      if (!stdout) {
        console.error('npm audit returned empty stdout');
        resolve([]);
        return;
      }

      try {
        const data = JSON.parse(stdout);
        const findings = [];

        // Check for vulnerabilities in the new format (npm v7+)
        if (data.vulnerabilities) {
          console.log('Using vulnerabilities format (npm v7+)');
          for (const [pkgName, vulnInfo] of Object.entries(data.vulnerabilities)) {
            // Skip if it's not a direct vulnerability or if it's only a warning
            if (vulnInfo.via && vulnInfo.via.length > 0) {
              // via can be an array of objects or strings
              const viaEntries = vulnInfo.via.filter(v => typeof v === 'object');
              for (const via of viaEntries) {
                findings.push({
                  package: pkgName,
                  severity: vulnInfo.severity || 'unknown',
                  title: via.title || 'No title',
                  cve: via.cve || 'N/A',
                  vulnerable_versions: vulnInfo.range || 'N/A',
                  category: 'dependency'
                });
              }
            }
          }
        }

        // Also check for advisories (older npm format)
        if (data.advisories) {
          console.log('Using advisories format (older npm)');
          for (const [id, adv] of Object.entries(data.advisories)) {
            findings.push({
              package: adv.module_name,
              severity: adv.severity || 'unknown',
              title: adv.title || 'No title',
              cve: adv.cve || 'N/A',
              vulnerable_versions: adv.vulnerable_versions || 'N/A',
              category: 'dependency'
            });
          }
        }

        console.log('npm vulnerabilities found: ' + findings.length);
        resolve(findings);
      } catch (e) {
        console.error('Failed to parse npm audit JSON: ' + e.message);
        console.error('Raw stdout (first 500 chars):', stdout.substring(0, 500));
        resolve([]);
      }
    });
  });
}

async function runPipAudit(content) {
  console.log('Running pip-audit');
  return new Promise((resolve) => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsentry-'));
    const reqPath = path.join(tempDir, 'requirements.txt');
    fs.writeFileSync(reqPath, content);
    exec('pip-audit --requirement ' + reqPath + ' --format json', { cwd: tempDir }, (error, stdout, stderr) => {
      fs.rmSync(tempDir, { recursive: true, force: true });
      if (error && !stdout) {
        console.error('pip-audit failed: ' + error.message);
        resolve([]);
        return;
      }
      try {
        const data = JSON.parse(stdout);
        const findings = [];
        for (const dep of data.dependencies || []) {
          for (const vuln of dep.vulnerabilities || []) {
            findings.push({
              package: dep.name,
              severity: vuln.severity || 'unknown',
              title: vuln.description || 'No description',
              cve: vuln.id || 'N/A',
              vulnerable_versions: vuln.fixed_versions ? 'Need upgrade to ' + vuln.fixed_versions.join(', ') : 'N/A',
              category: 'dependency'
            });
          }
        }
        console.log('pip vulnerabilities found: ' + findings.length);
        resolve(findings);
      } catch (e) {
        console.error('Failed to parse pip-audit JSON: ' + e.message);
        resolve([]);
      }
    });
  });
}

async function scanDependencies(octokit, owner, repo, prNumber, headSha) {
  console.log('scanDependencies called with headSha: ' + headSha);

  const filesResponse = await octokit.pulls.listFiles({
    owner,
    repo,
    pull_number: prNumber
  });

  const changedFiles = filesResponse.data.map(f => f.filename);
  console.log('Changed files: ' + JSON.stringify(changedFiles));

  const findings = [];
  let pkgFile = null;
  let lockFile = null;
  let reqFile = null;

  for (const file of changedFiles) {
    if (file.endsWith('package.json')) pkgFile = file;
    if (file.endsWith('package-lock.json')) lockFile = file;
    if (file.endsWith('requirements.txt')) reqFile = file;
  }

  if (pkgFile && lockFile) {
    console.log('Found both package.json and package-lock.json');
    const pkgContent = await fetchFileContent(octokit, owner, repo, pkgFile, headSha);
    const lockContent = await fetchFileContent(octokit, owner, repo, lockFile, headSha);
    if (pkgContent && lockContent) {
      const vulns = await runNpmAudit(pkgContent, lockContent);
      vulns.forEach(v => findings.push({ file: pkgFile, type: 'npm vulnerability', ...v }));
    }
  } else if (lockFile) {
    console.log('Found package-lock.json without package.json. Parsing lockfile directly.');
    const lockContent = await fetchFileContent(octokit, owner, repo, lockFile, headSha);
    if (lockContent) {
      const vulns = await parseLockfileForVulnerabilities(lockContent);
      vulns.forEach(v => findings.push({ file: lockFile, type: 'npm vulnerability (from lockfile)', ...v }));
    }
  } else if (pkgFile) {
    console.log('Found package.json without package-lock.json. Running npm audit without lockfile.');
    const pkgContent = await fetchFileContent(octokit, owner, repo, pkgFile, headSha);
    if (pkgContent) {
      const vulns = await runNpmAudit(pkgContent, null);
      vulns.forEach(v => findings.push({ file: pkgFile, type: 'npm vulnerability', ...v }));
    }
  }

  if (reqFile) {
    console.log('Found requirements.txt: ' + reqFile);
    const content = await fetchFileContent(octokit, owner, repo, reqFile, headSha);
    if (content) {
      const vulns = await runPipAudit(content);
      vulns.forEach(v => findings.push({ file: reqFile, type: 'pip vulnerability', ...v }));
    }
  }

  console.log('Total dependency findings: ' + findings.length);
  return findings;
}

module.exports = { scanDependencies };