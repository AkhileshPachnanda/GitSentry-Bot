// scanners/regex-scanner.js

function scanForSecrets(diffContent) {
  const findings = [];
  const lines = diffContent.split('\n');
  
  const patterns = [
    { regex: /AKIA[0-9A-Z]{16}/g, type: 'AWS Access Key' },
    { regex: /gh[pousr]_[A-Za-z0-9_]{36}/g, type: 'GitHub Token' },
    { regex: /sk_live_[A-Za-z0-9]{24,}/g, type: 'Stripe Secret Key' },
    { regex: /-----BEGIN RSA PRIVATE KEY-----/g, type: 'RSA Private Key' },
    { regex: /AIza[0-9A-Za-z\-_]{35}/g, type: 'Google API Key' },
    { regex: /-----BEGIN OPENSSH PRIVATE KEY-----/g, type: 'SSH Private Key' },
  ];
  
  lines.forEach((line, index) => {
    patterns.forEach(({ regex, type }) => {
      let match;
      while ((match = regex.exec(line)) !== null) {
        if (line.startsWith('+') && !line.startsWith('+++')) {
          findings.push({
            line: index + 1,
            content: line.substring(1).trim(),
            type: type,
            secret: match[0],
            category: 'secret'
          });
        }
      }
    });
  });
  
  return findings;
}

module.exports = { scanForSecrets };