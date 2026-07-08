const jwt = require('jsonwebtoken');
const { Octokit } = require('@octokit/rest');
const fs = require('fs');

class GitHubAppAuth {
  constructor(appId, privateKeyPath) {
    this.appId = appId;
    if (privateKeyPath) {
      this.privateKey = fs.readFileSync(privateKeyPath, 'utf8');
    } else {
      let key = process.env.GITHUB_PRIVATE_KEY;
      if (!key) {
        throw new Error('GitHub private key not found. Provide GITHUB_PRIVATE_KEY env or privateKeyPath.');
      }
      // If the key contains literal \n characters, replace them with actual newlines
      if (key.includes('\\n')) {
        key = key.replace(/\\n/g, '\n');
      }
      // Ensure the key has proper PEM headers and footers
      if (!key.includes('-----BEGIN RSA PRIVATE KEY-----')) {
        // If not, we may need to reconstruct it (unlikely)
        console.warn('Private key missing headers – ensure it is a valid PEM.');
      }
      this.privateKey = key;
    }
  }

  getJwt() {
    const now = Math.floor(Date.now() / 1000);
    return jwt.sign(
      { iat: now, exp: now + 600, iss: this.appId },
      this.privateKey,
      { algorithm: 'RS256' }
    );
  }

  async getInstallationToken(installationId) {
    const jwtToken = this.getJwt();
    const octokit = new Octokit({ auth: jwtToken });
    const response = await octokit.apps.createInstallationAccessToken({
      installation_id: installationId
    });
    return response.data.token;
  }
}

module.exports = GitHubAppAuth;