const crypto = require("node:crypto");

/**
 * Verifies a GitHub webhook request signature using HMAC-SHA256.
 *
 * GitHub signs every webhook delivery with a shared secret and includes the
 * result in the `X-Hub-Signature-256` header. This function recomputes the
 * expected signature over the raw request body and compares it using a
 * timing-safe equality check to prevent timing-oracle attacks.
 *
 * @param {import("express").Request} req - The Express request object.
 *   Must have `req.rawBody` (a Buffer captured before JSON parsing) or
 *   `req.body` as a fallback. Must have `req.headers["x-hub-signature-256"]`.
 * @param {string} [secret=process.env.WEBHOOK_SECRET] - The shared webhook
 *   secret configured on the GitHub App.
 * @returns {boolean} `true` if the signature is valid, `false` otherwise.
 */
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

