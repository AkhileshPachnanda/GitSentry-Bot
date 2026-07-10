const logger = require("../logger");

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
