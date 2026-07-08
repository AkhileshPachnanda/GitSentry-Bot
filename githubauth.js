const jwt = require('jsonwebtoken');
const { Octokit } = require('@octokit/rest');
const fs = require('fs');

class GitHubAppAuth {
  constructor(appId, privateKeyPath) {
    this.appId = appId;
    if (privateKeyPath) {
      this.privateKey = fs.readFileSync(privateKeyPath, 'utf8');
    } else {
      //AWS
      this.privateKey = process.env.GITHUB_PRIVATE_KEY;
      if (!this.privateKey) {
        throw new Error('GitHub private key not found. Provide GITHUB_PRIVATE_KEY env or privateKeyPath.');
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