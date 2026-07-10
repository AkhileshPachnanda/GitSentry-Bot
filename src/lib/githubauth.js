const jwt = require("jsonwebtoken");
const { Octokit } = require("@octokit/rest");
const fs = require("fs");
const path = require("path");

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

  getJwt() {
    const now = Math.floor(Date.now() / 1000);
    return jwt.sign(
      { iat: now, exp: now + 600, iss: this.appId },
      this.privateKey,
      { algorithm: "RS256" },
    );
  }

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
