const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { verifyWebhookSignature } = require("../security");

test("verifies a valid GitHub webhook signature", () => {
  const secret = "super-secret";
  const payload = JSON.stringify({ hello: "world" });
  const signature = `sha256=${crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("hex")}`;

  const req = {
    headers: { "x-hub-signature-256": signature },
    rawBody: Buffer.from(payload),
  };

  assert.equal(verifyWebhookSignature(req, secret), true);
});

test("rejects signatures for the wrong secret without throwing", () => {
  const secret = "super-secret";
  const payload = JSON.stringify({ hello: "world" });
  const signature = `sha256=${crypto
    .createHmac("sha256", "wrong-secret")
    .update(payload)
    .digest("hex")}`;

  const req = {
    headers: { "x-hub-signature-256": signature },
    rawBody: Buffer.from(payload),
  };

  assert.equal(verifyWebhookSignature(req, secret), false);
});

test("rejects missing signatures", () => {
  const req = { headers: {}, rawBody: Buffer.from("payload") };
  assert.equal(verifyWebhookSignature(req, "secret"), false);
});
