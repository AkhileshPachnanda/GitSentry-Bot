function getNumberEnv(name, fallback) {
  const value = process.env[name];
  if (!value) {
    return fallback;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

module.exports = {
  port: getNumberEnv("PORT", 3000),
  nodeEnv: process.env.NODE_ENV || "development",
  webhookSecret: process.env.WEBHOOK_SECRET || "",
  githubAppId: process.env.GITHUB_APP_ID || "",
  githubPrivateKeyPath: process.env.GITHUB_PRIVATE_KEY_PATH || null,
};
