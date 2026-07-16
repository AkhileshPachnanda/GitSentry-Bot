const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const { Octokit } = require("@octokit/rest");
const GitHubAppAuth = require("./lib/githubauth");
const { scanForSecrets } = require("./scanners/regex");
const { scanForEntropy } = require("./scanners/entropy");
const { scanDependencies } = require("./scanners/dependency");
const { verifyWebhookSignature } = require("./lib/security");
const logger = require("./lib/logger");
const config = require("./config");
const { createDashboardStore } = require("./dashboard/store");
const { getRemediation } = require("./lib/llm");
require("dotenv").config();

const app = express();
const PORT = config.port;
const dashboardStore = createDashboardStore();

app.use(cors());
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  }),
);

function buildReviewComment(findings) {
  const secretFindings = findings.filter(
    (finding) => finding.category === "secret",
  );
  const dependencyFindings = findings.filter(
    (finding) => finding.category === "dependency",
  );

  let commentBody = "## GitSentry Security Findings\n\n";

  if (secretFindings.length > 0) {
    commentBody += "### Secrets Detected\n\n";
    secretFindings.forEach((finding, index) => {
      commentBody += `**${index + 1}. ${finding.type}** (Line ${finding.line} in \`${finding.file || "unknown"}\`)\n`;
      const snippet = finding.content ? finding.content.substring(0, 100) : "";
      commentBody += `\`${snippet}${snippet.length === 100 ? "..." : ""}\`\n`;
      if (finding.remediation) {
        commentBody += `💡 **AI Remediation Suggestion:** ${finding.remediation}\n`;
      }
      commentBody += "\n";
    });
  }

  if (dependencyFindings.length > 0) {
    commentBody += "### Vulnerable Dependencies\n\n";
    dependencyFindings.forEach((finding) => {
      const severityEmoji =
        finding.severity === "critical" || finding.severity === "high"
          ? "🔴"
          : finding.severity === "medium"
            ? "🟡"
            : "🟢";
      commentBody += `${severityEmoji} **${finding.package}** (${finding.severity})\n`;
      commentBody += `   - ${finding.title}\n`;
      if (finding.cve && finding.cve !== "N/A") {
        commentBody += `   - CVE: ${finding.cve}\n`;
      }
      if (finding.vulnerable_versions) {
        commentBody += `   - Affected: ${finding.vulnerable_versions}\n`;
      }
      commentBody += `   - File: \`${finding.file || "unknown"}\`\n`;
      if (finding.remediation) {
        commentBody += `   - 💡 **AI Remediation Suggestion:** ${finding.remediation}\n`;
      }
      commentBody += "\n";
    });
  }

  commentBody += "---\n⚠️ Please resolve these findings before merging.";
  return commentBody;
}

// ============================================
// HEALTH & API ROUTES
// ============================================

app.get("/healthz", (req, res) => {
  res.status(200).json({ status: "ok" });
});

app.get("/api/dashboard/summary", async (req, res) => {
  try {
    const summary = await dashboardStore.getDashboardSummary();
    res.status(200).json(summary);
  } catch (error) {
    logger.error("Failed to load dashboard summary", error.message);
    res.status(500).json({ error: "Failed to load dashboard summary" });
  }
});

app.get("/api/dashboard/scans", async (req, res) => {
  try {
    const scans = await dashboardStore.getRecentScans();
    res.status(200).json(scans);
  } catch (error) {
    logger.error("Failed to load scan history", error.message);
    res.status(500).json({ error: "Failed to load scan history" });
  }
});

app.get("/api/dashboard/findings", async (req, res) => {
  try {
    const findings = await dashboardStore.getRecentFindings();
    res.status(200).json(findings);
  } catch (error) {
    logger.error("Failed to load recent findings", error.message);
    res.status(500).json({ error: "Failed to load recent findings" });
  }
});

app.post("/api/webhook", async (req, res) => {
  if (!verifyWebhookSignature(req, config.webhookSecret)) {
    logger.warn("Rejected webhook request with an invalid signature");
    return res.status(401).json({ error: "Invalid signature" });
  }

  const event = req.headers["x-github-event"];
  if (!event) {
    return res.status(400).json({ error: "Missing event header" });
  }

  if (event !== "pull_request") {
    logger.info(`Ignored unsupported event: ${event}`);
    return res
      .status(202)
      .json({ status: "ignored", reason: "unsupported event" });
  }

  const action = req.body?.action;
  if (!["opened", "reopened", "synchronize"].includes(action)) {
    logger.info(`Ignored pull request action: ${action}`);
    return res
      .status(202)
      .json({ status: "ignored", reason: "unsupported action" });
  }

  const pr = req.body?.pull_request;
  const repo = req.body?.repository;
  const installationId = req.body?.installation?.id;

  if (!pr || !repo || !installationId) {
    logger.warn("Webhook payload is missing pull request metadata");
    return res.status(400).json({ error: "Invalid webhook payload" });
  }

  logger.info(`Processing PR #${pr.number} in ${repo.full_name}`, {
    action,
    sha: pr.head?.sha,
  });

  try {
    if (!config.githubAppId) {
      logger.error("GITHUB_APP_ID is not configured");
      return res.status(500).json({ error: "GitHub app is not configured" });
    }

    const auth = new GitHubAppAuth(
      config.githubAppId,
      config.githubPrivateKeyPath,
    );
    const token = await auth.getInstallationToken(installationId);
    const octokit = new Octokit({ auth: token });

    const diffResponse = await octokit.pulls.get({
      owner: repo.owner.login,
      repo: repo.name,
      pull_number: pr.number,
      mediaType: { format: "diff" },
    });
    const diffContent = diffResponse.data;

    const regexFindings = scanForSecrets(diffContent);
    const entropyFindings = scanForEntropy(diffContent);
    const dependencyFindings = await scanDependencies(
      octokit,
      repo.owner.login,
      repo.name,
      pr.number,
      pr.head.sha,
    );

    const allFindings = [
      ...regexFindings,
      ...entropyFindings,
      ...dependencyFindings,
    ];
    logger.info(`Scan completed with ${allFindings.length} finding(s)`, {
      pullRequest: pr.number,
    });

    if (allFindings.length > 0) {
      await Promise.all(
        allFindings.map(async (finding) => {
          finding.remediation = await getRemediation(finding);
        }),
      );

      await octokit.pulls.createReview({
        owner: repo.owner.login,
        repo: repo.name,
        pull_number: pr.number,
        body: buildReviewComment(allFindings),
        event: "COMMENT",
      });
    }

    await dashboardStore.saveScanResult({
      repository: repo.full_name,
      pullRequest: pr.number,
      status: allFindings.length > 0 ? "findings" : "clean",
      findingsCount: allFindings.length,
      findings: allFindings,
    });

    return res.status(200).json({ status: "ok", findings: allFindings.length });
  } catch (error) {
    logger.error("Failed to process pull request", error.message);
    return res.status(500).json({ error: "Internal error" });
  }
});

// ============================================
// SERVE REACT DASHBOARD (NO WILDCARD ROUTE)
// ============================================

// 1. Serve static assets (JS, CSS, images) from client/dist
app.use(express.static(path.join(__dirname, "../client/dist")));

// 2. Fallback: for any non-API, non-file request, serve index.html (React Router)
// This avoids the need for the `*` wildcard route.
app.use((req, res, next) => {
  // Skip API routes (already handled above) and health check
  if (req.path.startsWith("/api/") || req.path === "/healthz") {
    return next();
  }

  // If the request has a file extension (like .js, .css, .png), it's a static asset
  // which would have already been handled by express.static, so skip.
  if (path.extname(req.path) !== "") {
    return next();
  }

  // Otherwise, serve index.html for client-side routing
  const indexPath = path.join(__dirname, "../client/dist", "index.html");
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).json({ error: "Dashboard not built" });
  }
});

// Error handler
app.use((err, req, res, next) => {
  logger.error("Unhandled server error", err.message);
  res.status(500).json({ error: "Internal server error" });
});

if (require.main === module) {
  app.listen(PORT, () => {
    logger.info(`GitSentry server listening on port ${PORT}`);
  });
}

module.exports = { app };
