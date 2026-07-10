const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const logger = require("../lib/logger");

const VULNERABLE_PACKAGES = {
  lodash: {
    versions: ["< 4.17.21"],
    severity: "high",
    title: "Prototype Pollution in lodash",
    cve: "CVE-2020-8203",
  },
  "lodash.includes": {
    versions: ["< 4.3.1"],
    severity: "high",
    title: "Prototype Pollution in lodash.includes",
    cve: "CVE-2020-8203",
  },
  "lodash.isboolean": {
    versions: ["< 3.0.4"],
    severity: "high",
    title: "Prototype Pollution in lodash.isboolean",
    cve: "CVE-2020-8203",
  },
  "lodash.isinteger": {
    versions: ["< 4.0.5"],
    severity: "high",
    title: "Prototype Pollution in lodash.isinteger",
    cve: "CVE-2020-8203",
  },
  "lodash.isnumber": {
    versions: ["< 3.0.4"],
    severity: "high",
    title: "Prototype Pollution in lodash.isnumber",
    cve: "CVE-2020-8203",
  },
  "lodash.isplainobject": {
    versions: ["< 4.0.7"],
    severity: "high",
    title: "Prototype Pollution in lodash.isplainobject",
    cve: "CVE-2020-8203",
  },
  "lodash.isstring": {
    versions: ["< 4.0.2"],
    severity: "high",
    title: "Prototype Pollution in lodash.isstring",
    cve: "CVE-2020-8203",
  },
  "lodash.once": {
    versions: ["< 4.1.2"],
    severity: "high",
    title: "Prototype Pollution in lodash.once",
    cve: "CVE-2020-8203",
  },
  express: {
    versions: ["< 4.17.3"],
    severity: "medium",
    title: "qs vulnerability in Express",
    cve: "CVE-2022-24999",
  },
  axios: {
    versions: ["< 1.6.0"],
    severity: "medium",
    title: "Server-Side Request Forgery in axios",
    cve: "CVE-2023-45857",
  },
};

function isVersionVulnerable(version, vulnerableRanges) {
  if (!version) {
    return false;
  }

  const cleanVersion = version.replace(/^v/, "").trim();
  for (const range of vulnerableRanges) {
    if (range.includes("<")) {
      const maxVersion = range.replace("<", "").trim();
      if (compareVersions(cleanVersion, maxVersion) < 0) {
        return true;
      }
    }
  }
  return false;
}

function compareVersions(v1, v2) {
  const normalizedV1 = v1.replace(/^v/, "").trim();
  const normalizedV2 = v2.replace(/^v/, "").trim();
  const parts1 = normalizedV1.split(".").map(Number);
  const parts2 = normalizedV2.split(".").map(Number);

  for (
    let index = 0;
    index < Math.min(parts1.length, parts2.length);
    index += 1
  ) {
    if (Number.isNaN(parts1[index]) || Number.isNaN(parts2[index])) {
      return normalizedV1.localeCompare(normalizedV2);
    }

    if (parts1[index] !== parts2[index]) {
      return parts1[index] - parts2[index];
    }
  }

  return parts1.length - parts2.length;
}

async function fetchFileContent(octokit, owner, repo, filePath, ref) {
  try {
    const response = await octokit.repos.getContent({
      owner,
      repo,
      path: filePath,
      ref,
    });

    if (response?.data?.content) {
      return Buffer.from(response.data.content, "base64").toString("utf8");
    }

    return null;
  } catch (error) {
    logger.debug(`Unable to fetch ${filePath}`, error.message);
    return null;
  }
}

async function parseLockfileForVulnerabilities(lockContent) {
  const findings = [];
  try {
    const lockData = JSON.parse(lockContent);
    const packages = lockData.packages || {};
    const rootPkg = packages[""] || {};
    const rootDeps = rootPkg.dependencies || {};

    for (const [pkgName, pkgVersion] of Object.entries(rootDeps)) {
      const vulnInfo = VULNERABLE_PACKAGES[pkgName];
      if (vulnInfo && isVersionVulnerable(pkgVersion, vulnInfo.versions)) {
        findings.push({
          package: pkgName,
          severity: vulnInfo.severity,
          title: vulnInfo.title,
          cve: vulnInfo.cve,
          vulnerable_versions: vulnInfo.versions.join(", "),
          category: "dependency",
        });
      }
    }

    for (const [pkgName, pkgInfo] of Object.entries(packages)) {
      if (pkgName && pkgName !== "" && pkgInfo.version) {
        const shortName = pkgName.replace(/^node_modules\//, "");
        const vulnInfo = VULNERABLE_PACKAGES[shortName];
        if (
          vulnInfo &&
          isVersionVulnerable(pkgInfo.version, vulnInfo.versions)
        ) {
          findings.push({
            package: shortName,
            severity: vulnInfo.severity,
            title: vulnInfo.title,
            cve: vulnInfo.cve,
            vulnerable_versions: vulnInfo.versions.join(", "),
            category: "dependency",
          });
        }

        if (shortName.startsWith("lodash.")) {
          const baseVuln = VULNERABLE_PACKAGES.lodash;
          if (
            baseVuln &&
            isVersionVulnerable(pkgInfo.version, baseVuln.versions)
          ) {
            findings.push({
              package: shortName,
              severity: baseVuln.severity,
              title: `${baseVuln.title} (in ${shortName})`,
              cve: baseVuln.cve,
              vulnerable_versions: baseVuln.versions.join(", "),
              category: "dependency",
            });
          }
        }
      }
    }
  } catch (error) {
    logger.error("Failed to parse dependency lockfile", error.message);
  }

  return findings;
}

async function runNpmAudit(pkgContent, lockContent) {
  return new Promise((resolve) => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "gitsentry-"));
    const pkgPath = path.join(tempDir, "package.json");
    fs.writeFileSync(pkgPath, pkgContent);

    if (lockContent) {
      fs.writeFileSync(path.join(tempDir, "package-lock.json"), lockContent);
    }

    const timeout = setTimeout(() => {
      fs.rmSync(tempDir, { recursive: true, force: true });
      resolve([]);
    }, 30000);

    exec(
      "npm audit --json",
      { cwd: tempDir, timeout: 25000 },
      (error, stdout) => {
        clearTimeout(timeout);
        fs.rmSync(tempDir, { recursive: true, force: true });

        if (!stdout) {
          resolve([]);
          return;
        }

        try {
          const data = JSON.parse(stdout);
          const findings = [];

          if (data.vulnerabilities) {
            for (const [pkgName, vulnInfo] of Object.entries(
              data.vulnerabilities,
            )) {
              if (vulnInfo.via && vulnInfo.via.length > 0) {
                const viaEntries = vulnInfo.via.filter(
                  (entry) => typeof entry === "object",
                );
                for (const via of viaEntries) {
                  findings.push({
                    package: pkgName,
                    severity: vulnInfo.severity || "unknown",
                    title: via.title || "No title",
                    cve: via.cve || "N/A",
                    vulnerable_versions: vulnInfo.range || "N/A",
                    category: "dependency",
                  });
                }
              }
            }
          }

          if (data.advisories) {
            for (const adv of Object.values(data.advisories)) {
              findings.push({
                package: adv.module_name,
                severity: adv.severity || "unknown",
                title: adv.title || "No title",
                cve: adv.cve || "N/A",
                vulnerable_versions: adv.vulnerable_versions || "N/A",
                category: "dependency",
              });
            }
          }

          resolve(findings);
        } catch (auditError) {
          logger.error("Failed to parse npm audit output", auditError.message);
          resolve([]);
        }
      },
    );
  });
}

async function runPipAudit(content) {
  return new Promise((resolve) => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "gitsentry-"));
    const reqPath = path.join(tempDir, "requirements.txt");
    fs.writeFileSync(reqPath, content);

    exec(
      `pip-audit --requirement ${reqPath} --format json`,
      { cwd: tempDir },
      (error, stdout) => {
        fs.rmSync(tempDir, { recursive: true, force: true });

        if (!stdout) {
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
                severity: vuln.severity || "unknown",
                title: vuln.description || "No description",
                cve: vuln.id || "N/A",
                vulnerable_versions: vuln.fixed_versions
                  ? `Need upgrade to ${vuln.fixed_versions.join(", ")}`
                  : "N/A",
                category: "dependency",
              });
            }
          }
          resolve(findings);
        } catch (auditError) {
          logger.error("Failed to parse pip-audit output", auditError.message);
          resolve([]);
        }
      },
    );
  });
}

async function scanDependencies(octokit, owner, repo, prNumber, headSha) {
  const filesResponse = await octokit.pulls.listFiles({
    owner,
    repo,
    pull_number: prNumber,
  });

  const changedFiles = filesResponse.data.map((file) => file.filename);
  const findings = [];
  let pkgFile = null;
  let lockFile = null;
  let reqFile = null;

  for (const file of changedFiles) {
    if (file.endsWith("package.json")) {
      pkgFile = file;
    }
    if (file.endsWith("package-lock.json")) {
      lockFile = file;
    }
    if (file.endsWith("requirements.txt")) {
      reqFile = file;
    }
  }

  if (pkgFile && lockFile) {
    const pkgContent = await fetchFileContent(
      octokit,
      owner,
      repo,
      pkgFile,
      headSha,
    );
    const lockContent = await fetchFileContent(
      octokit,
      owner,
      repo,
      lockFile,
      headSha,
    );
    if (pkgContent && lockContent) {
      const vulns = await runNpmAudit(pkgContent, lockContent);
      vulns.forEach((finding) =>
        findings.push({ file: pkgFile, type: "npm vulnerability", ...finding }),
      );
    }
  } else if (lockFile) {
    const lockContent = await fetchFileContent(
      octokit,
      owner,
      repo,
      lockFile,
      headSha,
    );
    if (lockContent) {
      const vulns = await parseLockfileForVulnerabilities(lockContent);
      vulns.forEach((finding) =>
        findings.push({
          file: lockFile,
          type: "npm vulnerability (from lockfile)",
          ...finding,
        }),
      );
    }
  } else if (pkgFile) {
    const pkgContent = await fetchFileContent(
      octokit,
      owner,
      repo,
      pkgFile,
      headSha,
    );
    if (pkgContent) {
      const vulns = await runNpmAudit(pkgContent, null);
      vulns.forEach((finding) =>
        findings.push({ file: pkgFile, type: "npm vulnerability", ...finding }),
      );
    }
  }

  if (reqFile) {
    const content = await fetchFileContent(
      octokit,
      owner,
      repo,
      reqFile,
      headSha,
    );
    if (content) {
      const vulns = await runPipAudit(content);
      vulns.forEach((finding) =>
        findings.push({ file: reqFile, type: "pip vulnerability", ...finding }),
      );
    }
  }

  return findings;
}

module.exports = { scanDependencies };
