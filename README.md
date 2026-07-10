# GitSentry Bot

A GitHub App that automatically scans pull requests for exposed secrets, high-entropy credentials, and known-vulnerable dependencies — posting findings directly as a PR review comment before code is merged.

---

## Overview

GitSentry runs as a GitHub App webhook receiver. On every `opened`, `reopened`, or `synchronize` pull request event, it:

1. Authenticates as the GitHub App (JWT → installation access token)
2. Pulls the raw unified diff for the PR via the GitHub REST API
3. Runs three independent scanners against the added lines of the diff
4. Aggregates findings and posts a single consolidated review comment on the PR
5. Persists the scan result (repo, PR number, findings, status) for the dashboard

It ships with a React + Tailwind dashboard for viewing scan history and finding trends across repositories.

## Architecture

```
GitHub PR event
      │
      ▼
POST /api/webhook  ──►  HMAC-SHA256 signature verification (timing-safe)
      │
      ▼
GitHub App JWT (RS256) ──► Installation Access Token
      │
      ▼
Fetch PR diff (Octokit) ──► Regex Scanner
                        ├──► Entropy Scanner
                        └──► Dependency Scanner
      │
      ▼
Aggregate findings ──► POST PR review comment
      │
      ▼
Persist to Postgres / in-memory store ──► Dashboard API ──► React dashboard
```

- **Backend:** Node.js + Express
- **Dashboard:** React + Tailwind CSS
- **Persistence:** PostgreSQL (via `pg`), with an in-memory fallback when `DATABASE_URL` is not set
- **Deployment:** Dockerized, with a GitHub Actions workflow that builds the image, pushes to Amazon ECR, and forces a rolling deployment on ECS

## How the Scanners Work

All three scanners operate only on **added lines** (`+` prefixed) in the PR diff — unchanged and removed code is not flagged.

### 1. Regex Scanner (`scanners/regex.js`)
Pattern-matches known credential formats against each added line:

| Pattern | Detects |
|---|---|
| `AKIA[0-9A-Z]{16}` | AWS Access Key |
| `gh[pousr]_[A-Za-z0-9_]{36}` | GitHub Token (PAT / OAuth / user-to-server) |
| `sk_live_[A-Za-z0-9]{24,}` | Stripe Live Secret Key |
| `-----BEGIN RSA PRIVATE KEY-----` | RSA Private Key |
| `AIza[0-9A-Za-z\-_]{35}` | Google API Key |
| `-----BEGIN OPENSSH PRIVATE KEY-----` | SSH Private Key |

### 2. Entropy Scanner (`scanners/entropy.js`)
Catches credentials that don't match a known format (custom tokens, random API keys) by computing Shannon entropy on quoted string literals:

- Only evaluates lines that look like an assignment (`key =`, `key:`, or containing `key/secret/token/password/credential/private/api`)
- Extracts quoted strings ≥ 20 characters
- Flags any string with entropy > **4.0 bits/character** as a potential secret

### 3. Dependency Scanner (`scanners/dependency.js`)
Cross-references `package.json` changes in the PR against a maintained table of known-vulnerable packages (e.g. `lodash < 4.17.21` → CVE-2020-8203 prototype pollution, `express < 4.17.3` → CVE-2022-24999), returning severity, CVE ID, and affected version range for each match.


## Security Design

- **Webhook signature verification** uses HMAC-SHA256 over the raw request body, compared with `crypto.timingSafeEqual` to prevent timing attacks (`security.js`)
- **GitHub App authentication** uses short-lived JWTs (RS256, 10-minute expiry) exchanged for scoped installation access tokens per request — no long-lived PAT is ever used
- Covered by unit tests in `tests/security.test.js` (valid signature acceptance, invalid signature rejection, malformed payload handling)

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/healthz` | Health check for deployment/load balancer probes |
| `POST` | `/api/webhook` | GitHub webhook receiver (PR events) |
| `GET` | `/api/dashboard/summary` | Aggregate scan metrics |
| `GET` | `/api/dashboard/scans` | Recent scan history |
| `GET` | `/api/dashboard/findings` | Recent findings across repositories |

## Tech Stack

**Backend:** Node.js, Express 5, Octokit REST, jsonwebtoken, pg
**Frontend:** React 18, Vite, Tailwind CSS
**Infra:** Docker, Docker Compose, AWS ECS + ECR, GitHub Actions

## Getting Started

### Prerequisites
- Node.js 18+
- A registered [GitHub App](https://docs.github.com/en/apps/creating-github-apps) with `pull_requests: write` permission and a webhook subscribed to `pull_request` events
- (Optional) PostgreSQL instance — falls back to in-memory storage if omitted

### Setup

```bash
git clone https://github.com/AkhileshPachnanda/GitSentry-Bot.git
cd GitSentry-Bot

cp .env.example .env
# fill in GITHUB_APP_ID, GITHUB_PRIVATE_KEY_PATH, WEBHOOK_SECRET, DATABASE_URL

npm install
cd client && npm install && cd ..
```

### Environment Variables

| Variable | Description |
|---|---|
| `GITHUB_APP_ID` | Your GitHub App's numeric ID |
| `GITHUB_PRIVATE_KEY_PATH` | Path to the App's downloaded `.pem` private key |
| `WEBHOOK_SECRET` | Shared secret configured on the GitHub App's webhook |
| `DATABASE_URL` | Postgres connection string (optional — omit for in-memory mode) |



### Run

```bash
npm start              # backend on the configured port
npm run dev:client     # dashboard, local dev with HMR
npm run build:client   # production dashboard build, served by Express
npm test               # runs the node:test suite
```

### Deploy

The included `Dockerfile` and `docker-compose.yml` containerize the backend (with the dashboard build served statically). `.github/workflows/deploy.yml` builds the image, pushes to Amazon ECR, and forces a new ECS service deployment on every push to `main`.

## Roadmap

- Replace the static vulnerable-package table with a live OSV/NVD query
- Expand secret patterns (Slack tokens, JWT secrets, generic private keys beyond RSA/OpenSSH)
- Per-repository configuration (severity thresholds, ignored paths)
- Historical trend charts on the dashboard

## License

ISC
