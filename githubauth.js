const jwt = require('jsonwebtoken');
const { Octokit } = require('@octokit/rest');
const fs = require('fs');

class GitHubAppAuth {
  constructor(appId, privateKeyPath) {
    this.appId = appId;
    this.privateKey = fs.readFileSync(privateKeyPath, 'utf8');
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