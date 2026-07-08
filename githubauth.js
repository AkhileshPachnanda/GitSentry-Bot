const jwt = require('jsonwebtoken');
const { Octokit } = require('@octokit/rest');
const fs = require('fs');

class GitHubAppAuth {
  /**
   * @param {string} appId - GitHub App ID
   * @param {string|null} privateKeyPath - Path to PEM file (local). If null, read from env.
   */
  constructor(appId, privateKeyPath) {
    this.appId = appId;

    let rawKey = null;

    if (privateKeyPath) {
      // Local development: read from file
      rawKey = fs.readFileSync(privateKeyPath, 'utf8');
    } else {
      // Cloud (ECS): read from environment variable
      rawKey = process.env.GITHUB_PRIVATE_KEY;
      if (!rawKey) {
        throw new Error(
          'GitHub private key not found. Provide GITHUB_PRIVATE_KEY env or privateKeyPath.'
        );
      }
      // IMPORTANT: Replace escaped newlines with real ones
      rawKey = rawKey.replace(/\\n/g, '\n');
    }

    // Remove any surrounding whitespace and ensure it's a valid PEM
    this.privateKey = rawKey.trim();

    // Optional: quick validation – check for header/footer
    if (
      !this.privateKey.includes('-----BEGIN RSA PRIVATE KEY-----') ||
      !this.privateKey.includes('-----END RSA PRIVATE KEY-----')
    ) {
      console.warn('⚠️ Private key does not contain valid PEM headers.');
    }
  }

  /**
   * Generate a JWT for the GitHub App
   * @returns {string} JWT
   */
  getJwt() {
    const now = Math.floor(Date.now() / 1000);
    return jwt.sign(
      {
        iat: now,
        exp: now + 600, // 10 minutes
        iss: this.appId,
      },
      this.privateKey,
      { algorithm: 'RS256' }
    );
  }

  /**
   * Exchange the JWT for an installation access token
   * @param {number} installationId
   * @returns {Promise<string>} installation token
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