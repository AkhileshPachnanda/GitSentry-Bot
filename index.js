const express = require("express");
const crypto = require("crypto");
const { Octokit } = require("@octokit/rest");
const GitHubAppAuth = require("./githubauth");
const { scanForSecrets } = require("./scanners/regex");
const { scanForEntropy } = require("./scanners/entropy");
const { scanDependencies } = require("./scanners/dependency");
require("dotenv").config();

const app = express();
const PORT = 3000;

// Raw body parser for signature verification
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  }),
);

// Verify HMAC signature
function verifySignature(req) {
  const signature = req.headers['x-hub-signature-256'];
  console.log('🔍 Headers:', Object.keys(req.headers));
  console.log('🔍 Signature header present?', !!signature);
  if (!signature) {
    console.log('❌ No signature header found');
    return false;
  }

  // Log the secret (first few chars only)
  const secret = process.env.WEBHOOK_SECRET;
  console.log('🔍 Secret length:', secret ? secret.length : 0);
  console.log('🔍 Secret first 5 chars:', secret ? secret.substring(0,5) : 'undefined');

  // Log raw body presence and size
  console.log('🔍 Raw body present?', !!req.rawBody);
  console.log('🔍 Raw body size:', req.rawBody ? req.rawBody.length : 0);
  if (req.rawBody) {
    console.log('🔍 Raw body preview:', req.rawBody.substring(0, 100));
  }

  // Compute expected signature
  const expected = 'sha256=' + crypto.createHmac('sha256', secret)
                                      .update(req.rawBody || '')
                                      .digest('hex');

  console.log('🔑 Received signature (full):', signature);
  console.log('🔑 Expected signature (full): ', expected);
  const isValid = crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  console.log('🔑 Is valid?', isValid);

  return isValid;
}

app.get("/", (req, res) => {
  res.send("GitSentry server is running");
});

app.post("/api/webhook", async (req, res) => {
  console.log("Webhook received");

  if (!verifySignature(req)) {
    console.error("Invalid signature");
    return res.status(401).send("Invalid signature");
  }

  const event = req.headers["x-github-event"];
  if (event !== "pull_request") {
    console.log("Ignoring event:", event);
    return res.status(200).send("Ignored");
  }

  const action = req.body.action;
  if (
    action !== "opened" &&
    action !== "reopened" &&
    action !== "synchronize"
  ) {
    console.log("Ignoring action:", action);
    return res.status(200).send("Ignored");
  }

  const pr = req.body.pull_request;
  const repo = req.body.repository;
  const installationId = req.body.installation.id;

  console.log(`Processing PR #${pr.number} in ${repo.full_name}`);
  console.log(`Title: ${pr.title}`);
  console.log(`Head SHA: ${pr.head.sha}`);
  console.log(`Action: ${action}`);

  try {
    const auth = new GitHubAppAuth(
      process.env.GITHUB_APP_ID,
      process.env.NODE_ENV === "production" ? null : "./private-key.pem",
    );
    const token = await auth.getInstallationToken(installationId);
    console.log("Installation token obtained");

    const octokit = new Octokit({ auth: token });
    const diffResponse = await octokit.pulls.get({
      owner: repo.owner.login,
      repo: repo.name,
      pull_number: pr.number,
      mediaType: { format: "diff" },
    });
    const diffContent = diffResponse.data;
    console.log(`Diff size: ${diffContent.length} characters`);

    // ---- RUN ALL SCANNERS ----
    const regexFindings = scanForSecrets(diffContent);
    const entropyFindings = scanForEntropy(diffContent);
    const depFindings = await scanDependencies(
      octokit,
      repo.owner.login,
      repo.name,
      pr.number,
      pr.head.sha,
    );

    const allFindings = [...regexFindings, ...entropyFindings, ...depFindings];
    console.log(`Total findings: ${allFindings.length} letters`);

    // ---- POST COMMENT ----
    if (allFindings.length > 0) {
      let commentBody = "## GitSentry Security Findings\n\n";

      const secretFindings = allFindings.filter((f) => f.category === "secret");
      const depFindingsOnly = allFindings.filter(
        (f) => f.category === "dependency",
      );

      if (secretFindings.length > 0) {
        commentBody += "### Secrets Detected\n\n";
        secretFindings.forEach((f, idx) => {
          commentBody += `**${idx + 1}. ${f.type}** (Line ${f.line} in \`${f.file || "unknown"}\`)\n`;
          commentBody += `\`${f.content.substring(0, 100)}${f.content.length > 100 ? "..." : ""}\`\n\n`;
        });
      }

      if (depFindingsOnly.length > 0) {
        commentBody += "### Vulnerable Dependencies\n\n";
        depFindingsOnly.forEach((f, idx) => {
          const severityEmoji =
            f.severity === "critical" || f.severity === "high"
              ? "🔴"
              : f.severity === "medium"
                ? "🟡"
                : "🟢";
          commentBody += `${severityEmoji} **${f.package}** (${f.severity})\n`;
          commentBody += `   - ${f.title}\n`;
          if (f.cve && f.cve !== "N/A") commentBody += `   - CVE: ${f.cve}\n`;
          if (f.vulnerable_versions)
            commentBody += `   - Affected: ${f.vulnerable_versions}\n`;
          commentBody += `   - File: \`${f.file}\`\n\n`;
        });
      }

      commentBody += "---\n⚠️ Please fix these issues before merging.";

      await octokit.pulls.createReview({
        owner: repo.owner.login,
        repo: repo.name,
        pull_number: pr.number,
        body: commentBody,
        event: "COMMENT",
      });
      console.log("Review comment posted!");
    } else {
      console.log("No issues found, clean PR");
    }

    res.status(200).send("OK");
  } catch (error) {
    console.error("Error processing PR:", error.message);
    res.status(500).send("Internal error");
  }
});

app.listen(PORT, () => {
  console.log(`GitSentry running on http://localhost:${PORT}`);
});
