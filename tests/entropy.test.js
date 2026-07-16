const { scanForEntropy, calculateEntropy } = require('../src/scanners/entropy');
const logger = require('../src/lib/logger');

describe('entropy scanner', () => {
  let debugSpy;

  beforeEach(() => {
    debugSpy = jest.spyOn(logger, 'debug').mockImplementation(() => {});
  });

  afterEach(() => {
    debugSpy.mockRestore();
  });

  describe('calculateEntropy', () => {
    test('returns 0 for falsy or short strings', () => {
      expect(calculateEntropy(null)).toBe(0);
      expect(calculateEntropy('')).toBe(0);
      expect(calculateEntropy('abc')).toBe(0);
    });

    test('calculates correct entropy value', () => {
      // String with all identical characters has 0 entropy
      expect(calculateEntropy('aaaaaaaa')).toBe(0);
      // High-entropy string has positive value
      expect(calculateEntropy('abcdefgh')).toBeGreaterThan(2);
    });
  });

  describe('scanForEntropy', () => {
    test('returns empty array when diffContent is falsy', () => {
      expect(scanForEntropy(null)).toEqual([]);
      expect(scanForEntropy('')).toEqual([]);
    });

    test('ignores non-added lines or diff headers', () => {
      const diff = `
--- a/file.js
+++ b/file.js
- const secret = "z7k9x2v5t8m4n1p6q3r0s9w2x5v8t3m6";
      `;
      expect(scanForEntropy(diff)).toEqual([]);
    });

    test('ignores lines without assignment or keywords', () => {
      const diff = `+ console.log("z7k9x2v5t8m4n1p6q3r0s9w2x5v8t3m6");`;
      expect(scanForEntropy(diff)).toEqual([]);
    });

    test('detects high-entropy strings in assignments', () => {
      const diff = `+ const secret = "z7k9x2v5t8m4n1p6q3r0s9w2x5v8t3m6";`;
      const findings = scanForEntropy(diff);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].type).toContain('High-Entropy String');
      expect(debugSpy).toHaveBeenCalled();
    });

    test('ignores low-entropy strings in assignments', () => {
      const diff = `+ const normal = "helloWorldhelloWorld";`;
      const findings = scanForEntropy(diff);
      expect(findings.length).toBe(0);
    });
  });
});