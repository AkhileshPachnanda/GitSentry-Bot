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
        throw new Error('GitHub private key not found.');
      }
      // If the key is a single line without newlines, reconstruct it
      if (!key.includes('\n')) {
        // Extract the base64 part between header and footer
        const match = key.match(/-----BEGIN RSA PRIVATE KEY-----\s*(.+?)\s*-----END RSA PRIVATE KEY-----/s);
        if (match) {
          const base64 = match[1].replace(/\s/g, ''); // remove all spaces
          // Insert newlines every 64 characters
          const chunks = base64.match(/.{1,64}/g);
          const pem = '-----BEGIN RSA PRIVATE KEY-----\n' + chunks.join('\n') + '\n-----END RSA PRIVATE KEY-----\n';
          this.privateKey = pem;
        } else {
          // Fallback: try replacing spaces with newlines (not ideal but may work)
          this.privateKey = key.replace(/\s+/g, '\n');
        }
      } else {
        this.privateKey = key;
      }
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