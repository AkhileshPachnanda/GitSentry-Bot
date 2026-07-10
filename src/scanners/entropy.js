const logger = require("../lib/logger");

/**
 * Computes the Shannon entropy of a string in bits per character.
 *
 * @param {string} str - Input string. Returns 0 for strings shorter than 8 chars.
 * @returns {number} Entropy value in bits/character. Higher values indicate
 *   more randomness (typical secrets score > 4.0).
 */
function calculateEntropy(str) {
  if (!str || str.length < 8) {
    return 0;
  }

  const freq = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;
  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Scans a unified diff for high-entropy string literals that may be secrets.
 *
 * Only evaluates added lines (`+` prefix) that look like an assignment
 * (contain `=`, `:`, or keywords such as `key`, `secret`, `token`, `password`,
 * `credential`, `private`, `api`). Quoted strings ≥ 20 characters are
 * extracted and scored; anything above 4.0 bits/character is flagged.
 *
 * This catches credentials that don't match a known format — random API keys,
 * custom tokens, base64-encoded secrets, etc.
 *
 * @param {string} diffContent - Raw unified diff text from the GitHub API.
 * @returns {import('../index').Finding[]} Array of high-entropy findings.
 *   Empty array if no suspicious strings are detected or input is falsy.
 */
function scanForEntropy(diffContent) {
  if (!diffContent) {
    return [];
  }

  const findings = [];
  const lines = diffContent.split("\n");
  const stringPattern = /["'`]([A-Za-z0-9_\-+/=.]{20,})["'`]/g;

  lines.forEach((line, index) => {
    if (!line.startsWith("+") || line.startsWith("+++")) {
      return;
    }

    const isAssignment =
      /=\s*["'`]/.test(line) ||
      /:\s*["'`]/.test(line) ||
      /key|secret|token|password|credential|private|api/i.test(line);

    if (!isAssignment) {
      return;
    }

    stringPattern.lastIndex = 0;
    let match;
    while ((match = stringPattern.exec(line)) !== null) {
      const potentialSecret = match[1];
      const entropy = calculateEntropy(potentialSecret);

      if (entropy > 4.0) {
        findings.push({
          line: index + 1,
          content: line.substring(1).trim(),
          type: `High-Entropy String (${entropy.toFixed(2)} bits/char)`,
          secret: potentialSecret,
          category: "secret",
        });
      }
    }
  });

  if (findings.length > 0) {
    logger.debug(`Detected ${findings.length} high-entropy string(s)`, {
      scanner: "entropy",
    });
  }

  return findings;
}

module.exports = { scanForEntropy };
