const crypto = require("node:crypto");

function verifyWebhookSignature(req, secret = process.env.WEBHOOK_SECRET) {
  const signature = req?.headers?.["x-hub-signature-256"];
  const payload = req?.rawBody ?? req?.body;

  if (!signature || !secret || !payload) {
    return false;
  }

  const expectedSignature = Buffer.from(
    `sha256=${crypto.createHmac("sha256", secret).update(Buffer.from(payload)).digest("hex")}`,
  );
  const providedSignature = Buffer.from(signature);

  if (expectedSignature.length !== providedSignature.length) {
    return false;
  }

  try {
    return crypto.timingSafeEqual(expectedSignature, providedSignature);
  } catch (error) {
    return false;
  }
}

module.exports = {
  verifyWebhookSignature,
};
