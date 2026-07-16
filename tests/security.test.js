// tests/security.test.js
const crypto = require('crypto');
const { verifyWebhookSignature } = require('../src/lib/security');

const WEBHOOK_SECRET = 'test_secret';

// Helper to create a fake request with signature
function createRequest(body, secret = WEBHOOK_SECRET) {
  const rawBody = JSON.stringify(body);
  const signature = 'sha256=' + crypto.createHmac('sha256', secret)
                                      .update(rawBody)
                                      .digest('hex');
  return {
    rawBody: Buffer.from(rawBody),
    headers: { 'x-hub-signature-256': signature }
  };
}

describe('verifyWebhookSignature', () => {
  test('verifies a valid GitHub webhook signature', () => {
    const payload = { action: 'opened' };
    const req = createRequest(payload);
    expect(verifyWebhookSignature(req, WEBHOOK_SECRET)).toBe(true);
  });

  test('verifies signature using req.body fallback if req.rawBody is missing', () => {
    const payload = { action: 'opened' };
    const rawBody = JSON.stringify(payload);
    const signature = 'sha256=' + crypto.createHmac('sha256', WEBHOOK_SECRET)
                                        .update(rawBody)
                                        .digest('hex');
    const req = {
      body: Buffer.from(rawBody),
      headers: { 'x-hub-signature-256': signature }
    };
    expect(verifyWebhookSignature(req, WEBHOOK_SECRET)).toBe(true);
  });

  test('rejects signatures for the wrong secret', () => {
    const payload = { action: 'opened' };
    const req = createRequest(payload, 'wrong_secret');
    expect(verifyWebhookSignature(req, WEBHOOK_SECRET)).toBe(false);
  });

  test('rejects missing signatures', () => {
    const req = {
      rawBody: Buffer.from(JSON.stringify({ action: 'opened' })),
      headers: {}
    };
    expect(verifyWebhookSignature(req, WEBHOOK_SECRET)).toBe(false);
  });

  test('rejects invalid signature format', () => {
    const req = {
      rawBody: Buffer.from(JSON.stringify({ action: 'opened' })),
      headers: { 'x-hub-signature-256': 'invalid' }
    };
    expect(verifyWebhookSignature(req, WEBHOOK_SECRET)).toBe(false);
  });

  test('rejects when signature length mismatch', () => {
    const payload = { action: 'opened' };
    const req = createRequest(payload);
    // Provided signature has different length
    req.headers['x-hub-signature-256'] = 'sha256=abc';
    expect(verifyWebhookSignature(req, WEBHOOK_SECRET)).toBe(false);
  });

  test('uses process.env.WEBHOOK_SECRET default fallback', () => {
    process.env.WEBHOOK_SECRET = 'env_secret';
    const payload = { action: 'opened' };
    const req = createRequest(payload, 'env_secret');
    expect(verifyWebhookSignature(req)).toBe(true);
    delete process.env.WEBHOOK_SECRET;
  });

  test('returns false when crypto.timingSafeEqual throws an error', () => {
    const spy = jest.spyOn(crypto, 'timingSafeEqual').mockImplementation(() => {
      throw new Error('Forced timingSafeEqual error');
    });

    const payload = { action: 'opened' };
    const req = createRequest(payload);
    expect(verifyWebhookSignature(req, WEBHOOK_SECRET)).toBe(false);

    spy.mockRestore();
  });
});