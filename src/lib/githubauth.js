const jwt = require("jsonwebtoken");
const { Octokit } = require("@octokit/rest");
const fs = require("fs");
const path = require("path");

/**
 * Handles authentication for a GitHub App.
 *
 * Implements the two-step flow required by GitHub Apps:
 * 1. Signs a short-lived JWT (RS256, 10-minute expiry) with the App's private key.
 * 2. Exchanges that JWT for a scoped installation access token by calling
 *    the GitHub REST API (`POST /app/installations/{id}/access_tokens`).
 *
 * The installation token is then used for all repository-level API calls
 * (fetching diffs, listing files, posting review comments) within the
 * lifetime of a single webhook request.
 */
class GitHubAppAuth {
  constructor(appId, privateKeyPath) {
    if (!appId) {
      throw new Error("GitHub app ID is required.");
    }

    this.appId = appId;
    this.privateKey = this.loadPrivateKey(privateKeyPath);
  }

  loadPrivateKey(privateKeyPath) {
    const configuredPath =
      privateKeyPath || process.env.GITHUB_PRIVATE_KEY_PATH;
    if (configuredPath) {
      const resolvedPath = path.isAbsolute(configuredPath)
        ? configuredPath
        : path.resolve(process.cwd(), configuredPath);

      if (!fs.existsSync(resolvedPath)) {
        throw new Error(`GitHub private key file not found at ${resolvedPath}`);
      }

      return fs.readFileSync(resolvedPath, "utf8");
    }

    const key = process.env.GITHUB_PRIVATE_KEY;
    if (!key) {
      throw new Error("GitHub private key not found.");
    }

    return this.normalizePrivateKey(key);
  }

  normalizePrivateKey(key) {
    if (!key) {
      return key;
    }

    if (key.includes("\n")) {
      return key;
    }

    const match = key.match(
      /-----BEGIN (?:RSA )?PRIVATE KEY-----\s*(.*?)\s*-----END (?:RSA )?PRIVATE KEY-----/s,
    );
    if (match) {
      const base64 = match[1].replace(/\s/g, "");
      const chunks = base64.match(/.{1,64}/g) || [base64];
      return `-----BEGIN RSA PRIVATE KEY-----\n${chunks.join("\n")}\n-----END RSA PRIVATE KEY-----\n`;
    }

    return key.replace(/\s+/g, "\n");
  }

  /**
   * Builds a signed RS256 JWT for authenticating as the GitHub App.
   *
   * The JWT payload contains:
   * - `iat`: issued-at timestamp (seconds since epoch)
   * - `exp`: expiry timestamp (iat + 600 seconds = 10 minutes)
   * - `iss`: the GitHub App ID
   *
   * @returns {string} A signed JWT string valid for 10 minutes.
   */
  getJwt() {
    const now = Math.floor(Date.now() / 1000);
    return jwt.sign(
      { iat: now, exp: now + 600, iss: this.appId },
      this.privateKey,
      { algorithm: "RS256" },
    );
  }

  /**
   * Exchanges a GitHub App JWT for a scoped installation access token.
   *
   * The token is scoped to the specific installation and the repositories
   * it has been granted access to. It is valid for approximately 1 hour
   * and is not cached — a new token is requested on every webhook event.
   *
   * @param {number} installationId - The installation ID from the webhook payload
   *   (`req.body.installation.id`).
   * @returns {Promise<string>} A short-lived installation access token.
   * @throws {Error} If the GitHub API request fails.
   */
  async getInstallationToken(installationId) {
    const jwtToken = this.getJwt();
    const octokit = new Octokit({ auth: jwtToken });
    const response = await octokit.apps.createInstallationAccessToken({
      installation_id: installationId,
    });
    return response.data.token;
  }
}

module.exports = GitHubAppAuth;
