const { scanForSecrets } = require('../src/scanners/regex');
const logger = require('../src/lib/logger');

describe('scanForSecrets', () => {
  let debugSpy;

  beforeEach(() => {
    debugSpy = jest.spyOn(logger, 'debug').mockImplementation(() => {});
  });

  afterEach(() => {
    debugSpy.mockRestore();
  });

  test('returns empty array when diffContent is falsy', () => {
    expect(scanForSecrets(null)).toEqual([]);
    expect(scanForSecrets('')).toEqual([]);
  });

  test('ignores lines not starting with + or starting with +++', () => {
    const diff = `
--- a/file.js
+++ b/file.js
- const oldKey = "AKIAIOSFODNN7EXAMPLE";
  const unchangedKey = "AKIAIOSFODNN7EXAMPLE";
    `;
    expect(scanForSecrets(diff)).toEqual([]);
  });

  test('detects AWS keys in a diff', () => {
    const diff = `+ const key = "AKIAIOSFODNN7EXAMPLE";`;
    const findings = scanForSecrets(diff);
    expect(findings.length).toBe(1);
    expect(findings[0].type).toBe('AWS Access Key');
    expect(findings[0].secret).toBe('AKIAIOSFODNN7EXAMPLE');
    expect(debugSpy).toHaveBeenCalled();
  });

  test('detects GitHub Tokens', () => {
    const diff = `+ const token = "ghp_123456789012345678901234567890123456";`;
    const findings = scanForSecrets(diff);
    expect(findings.length).toBe(1);
    expect(findings[0].type).toBe('GitHub Token');
  });

  test('detects Stripe Secret Keys', () => {
    const diff = `+ const stripe = "sk_live_123456789012345678901234";`;
    const findings = scanForSecrets(diff);
    expect(findings.length).toBe(1);
    expect(findings[0].type).toBe('Stripe Secret Key');
  });

  test('detects Google API Keys', () => {
    const diff = `+ const key = "AIzaSyA12345678901234567890123456789012";`;
    const findings = scanForSecrets(diff);
    expect(findings.length).toBe(1);
    expect(findings[0].type).toBe('Google API Key');
  });

  test('detects RSA Private Keys', () => {
    const diff = `+ -----BEGIN RSA PRIVATE KEY-----`;
    const findings = scanForSecrets(diff);
    expect(findings.length).toBe(1);
    expect(findings[0].type).toBe('RSA Private Key');
  });

  test('detects SSH Private Keys', () => {
    const diff = `+ -----BEGIN OPENSSH PRIVATE KEY-----`;
    const findings = scanForSecrets(diff);
    expect(findings.length).toBe(1);
    expect(findings[0].type).toBe('SSH Private Key');
  });
});