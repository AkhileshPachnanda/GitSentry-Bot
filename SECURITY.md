# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, email the maintainer directly or open a [GitHub Security Advisory](https://github.com/AkhileshPachnanda/GitSentry-Bot/security/advisories/new) (private, disclosed only to maintainers).

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (diff, payload, curl command, etc.)
- Any suggested mitigations if you have them

You will receive an acknowledgement within **72 hours** and a resolution timeline within **7 days**.

---

## Threat Model

GitSentry is a webhook receiver that handles incoming events from GitHub and posts findings back as PR review comments. The following threats are in scope and mitigated:

### 1. Forged Webhook Requests

**Threat:** An attacker sends a crafted `POST /api/webhook` payload to trigger false scans, flood the database, or enumerate internal behaviour.

**Mitigation:** Every incoming webhook is verified against a GitHub-provided `X-Hub-Signature-256` header using HMAC-SHA256 over the **raw request body** (captured before JSON parsing via Express's `verify` callback). The comparison uses `crypto.timingSafeEqual` to prevent timing-oracle attacks. Requests with a missing, malformed, or incorrect signature are rejected with `401` before any PR data is read.

```
Incoming POST
    │
    ▼
Raw body captured ──► HMAC-SHA256(body, WEBHOOK_SECRET)
    │                         │
    ▼                         ▼
X-Hub-Signature-256  ◄── timingSafeEqual ──► match? continue : 401
```

Covered by: [`src/lib/security.js`](src/lib/security.js), [`tests/security.test.js`](tests/security.test.js)

---

### 2. Long-lived GitHub Credentials

**Threat:** A compromised long-lived Personal Access Token (PAT) gives an attacker persistent write access to repositories.

**Mitigation:** GitSentry never uses a PAT. It authenticates as a GitHub App using a short-lived RS256 JWT (10-minute expiry), then immediately exchanges it for a scoped **installation access token** that is valid only for the repositories that installed the app. The private key is never transmitted; only the signed JWT is sent to GitHub.

```
Private Key (PEM on disk / env var)
    │
    ▼
RS256 JWT (iat, exp=now+600, iss=APP_ID)
    │
    ▼
POST /app/installations/{id}/access_tokens
    │
    ▼
Installation Token (scoped, ~1hr TTL) ──► Octokit requests
```

Covered by: [`src/lib/githubauth.js`](src/lib/githubauth.js)

---

### 3. Private Key Exposure

**Threat:** The GitHub App's RSA private key is leaked via logs, error messages, or committed to the repository.

**Mitigations:**
- The key is read from a file path (`GITHUB_PRIVATE_KEY_PATH`) or an environment variable (`GITHUB_PRIVATE_KEY`) — never hardcoded.
- `*.pem` and `private-key.pem` are listed in `.gitignore`.
- The key is never logged. Errors thrown during key loading expose only the file path, not the key content.
- In CI/CD, the key is stored as a GitHub Actions secret and injected at runtime.

---

### 4. Secret Leakage in Scan Findings

**Threat:** The bot logs or persists raw secret values it discovers in diffs (e.g. actual API keys), creating a secondary vector for credential theft.

**Mitigation:**
- Regex and entropy findings store the **surrounding line content** (up to 100 characters, truncated), not the extracted secret value itself, in the PR review comment.
- The `secret` field on finding objects (used internally for deduplication) is **not** written to the database or included in dashboard API responses.
- Contributors adding new patterns must not log matched secret values at any log level.

---

### 5. Dependency Confusion / Supply Chain

**Threat:** A malicious package with the same name as an internal package is published to npm and pulled in by `npm install`.

**Mitigation:**
- `package-lock.json` is committed and `npm ci` is used in Docker builds (`RUN npm ci --only=production`) to guarantee reproducible installs from the lockfile.
- The Dockerfile runs a two-stage build: the production stage installs only production dependencies.

---

### 6. Server-Side Code Execution via Scanner Input

**Threat:** A maliciously crafted PR diff causes the scanner to execute arbitrary code (e.g. via `eval`, `RegExp` catastrophic backtracking, or command injection in the dependency scanner).

**Mitigations:**
- No `eval` or dynamic code execution is used anywhere in the scanner code.
- All regexes are statically defined with anchored patterns and finite quantifiers. A 30-second timeout is applied to the `npm audit` subprocess; if it does not complete, the result is discarded and processing continues.
- `npm audit` and `pip-audit` are invoked via `child_process.exec` with a sandboxed temp directory created via `fs.mkdtempSync`. The temp directory is deleted in all code paths (success, timeout, error) via `fs.rmSync`.

---

## How Secrets Are Handled at Rest

| Data | Stored? | Where | Notes |
|---|---|---|---|
| Webhook secret | No | Env var only | Never written to disk or DB |
| GitHub App private key | No | Env var / `.pem` file | Excluded from git via `.gitignore` |
| Installation access tokens | No | In-memory, per-request | Not persisted anywhere |
| Finding content (line snippet) | Yes | PostgreSQL `findings` table | Truncated to 100 chars, no raw secret |
| PR diff | No | In-memory, per-request | Not persisted |

---

## Supported Versions

| Version | Supported |
|---|---|
| `main` branch | ✅ |
| Older tags | ❌ — please upgrade |
