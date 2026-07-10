# GitSentry Bot — Architecture

This document describes the system design, component boundaries, and data flows in GitSentry Bot.

---

## High-Level Overview

GitSentry is a **GitHub App** that acts as a webhook receiver. It has no user-facing login — it is installed on GitHub repositories and responds to repository events.

```
┌─────────────────────────────────────────────────────────────────┐
│                          GitHub.com                             │
│                                                                 │
│   Developer opens / updates a Pull Request                      │
│           │                                                     │
│           ▼                                                     │
│   GitHub fires POST /api/webhook  ──────────────────────────┐  │
│   (X-Hub-Signature-256 header)                              │  │
└─────────────────────────────────────────────────────────────┼──┘
                                                              │
                      HTTPS (TLS)                             │
                                                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     GitSentry Backend (Node.js / Express)       │
│                                                                 │
│  ┌──────────────┐    ┌──────────────────────────────────────┐  │
│  │  Middleware  │    │         Webhook Handler               │  │
│  │              │    │                                       │  │
│  │ HMAC-SHA256  │───►│  1. Verify signature (timingSafeEq)  │  │
│  │ verification │    │  2. Authenticate as GitHub App (JWT) │  │
│  │  (security)  │    │  3. Fetch PR diff via Octokit        │  │
│  └──────────────┘    │  4. Run scanners (parallel)          │  │
│                      │  5. Aggregate & post PR review       │  │
│  ┌──────────────┐    │  6. Persist scan result              │  │
│  │   Scanners   │◄───┤                                      │  │
│  │              │    └──────────────────────────────────────┘  │
│  │ ▸ Regex      │                    │                          │
│  │ ▸ Entropy    │                    │                          │
│  │ ▸ Dependency │          ┌─────────▼──────────┐              │
│  └──────────────┘          │  Dashboard Store    │              │
│                            │  (PostgreSQL / mem) │              │
│  ┌──────────────┐          └─────────┬──────────┘              │
│  │  Dashboard   │◄────────────────── │                         │
│  │  REST API    │   GET /api/dash..  │                         │
│  └──────────────┘                    │                          │
│                                      │                          │
│  ┌──────────────────────────────┐    │                          │
│  │  Static file server          │    │                          │
│  │  (client/dist via Express)   │    │                          │
│  └──────────────────────────────┘    │                          │
└─────────────────────────────────────────────────────────────────┘
                                       │
                          ┌────────────▼────────────┐
                          │       PostgreSQL          │
                          │  tables: scans, findings  │
                          └───────────────────────────┘
```

---

## Component Details

### `src/index.js` — Application Entry Point

Bootstraps Express, registers middleware, mounts all routes, and starts the HTTP server. The webhook handler and dashboard API routes all live here. Serves the compiled React dashboard from `client/dist` as static files.

### `src/config/index.js` — Configuration

Single source of truth for all environment-driven config values. Reads from `process.env` with typed defaults. Nothing else reads `process.env` directly (except `src/lib/security.js` which accepts the secret as a parameter).

### `src/lib/security.js` — Webhook Verification

Implements GitHub's [webhook signature verification](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries) spec:

```
HMAC-SHA256(raw_body, WEBHOOK_SECRET)
    → "sha256=" + hex digest
    → timingSafeEqual(expected, provided)
```

The raw body is captured before JSON parsing by Express's `verify` callback so the HMAC is computed over the exact bytes GitHub signed.

### `src/lib/githubauth.js` — GitHub App Authentication

Two-step authentication flow:

```
1.  Build JWT:
      { iat: now, exp: now+600, iss: APP_ID }
      signed with RS256 using the App's private key

2.  POST /app/installations/{installationId}/access_tokens
      Authorization: Bearer <jwt>
      → returns a scoped installation token (~1hr TTL)
```

The installation token is then used for all Octokit API calls within that webhook request's lifecycle.

### `src/lib/logger.js` — Logger

A thin levelled wrapper around `console.log`. Level priority: `error > warn > info > debug`. Controlled by the `LOG_LEVEL` environment variable. All scanners and request handlers use this rather than `console` directly.

---

## Scanner Pipeline

All scanners receive the raw unified diff text and return an array of `Finding` objects. They are run **sequentially** (awaited in order) and their results are merged into `allFindings`.

```
Raw diff text (string)
        │
        ├──► scanForSecrets(diff)    → Finding[]   (regex.js)
        │
        ├──► scanForEntropy(diff)    → Finding[]   (entropy.js)
        │
        └──► scanDependencies(...)   → Finding[]   (dependency.js)
                    │
                    ▼
             Fetches package.json + package-lock.json
             from the PR head via Octokit, then runs:
               - npm audit (subprocess, 25s timeout)
               - OR lockfile cross-reference (VULNERABLE_PACKAGES table)
               - OR pip-audit for requirements.txt
```

### Finding Shape

```js
{
  line:     Number,  // 1-indexed line in the diff
  content:  String,  // sanitised line (leading "+" stripped, trimmed)
  type:     String,  // human-readable label e.g. "AWS Access Key"
  category: String,  // "secret" | "dependency"
  severity: String,  // "critical" | "high" | "medium" | "low"
  // dependency findings additionally include:
  package:            String,
  cve:                String,
  vulnerable_versions: String,
  file:               String,
}
```

---

## Persistence Layer

`src/dashboard/store.js` exposes an identical API regardless of whether a PostgreSQL connection is available:

| Function | Description |
|---|---|
| `getDashboardSummary()` | Aggregate totals (total scans) |
| `getRecentScans(limit)` | Latest N scan records |
| `getRecentFindings(limit)` | Latest N finding records |
| `saveScanResult(data)` | Persist a scan + its findings atomically |
| `closePool()` | Drain the Postgres connection pool (for graceful shutdown) |

When `DATABASE_URL` is set, each call uses a `pg.Pool`. When it is absent, `saveScanResult` is a no-op and query functions return empty arrays — the server remains fully functional for webhook processing.

**Database schema** (PostgreSQL):

```sql
CREATE TABLE scans (
  id             SERIAL PRIMARY KEY,
  repository     TEXT NOT NULL,
  pull_request   INTEGER NOT NULL,
  status         TEXT NOT NULL,          -- 'clean' | 'findings'
  findings_count INTEGER NOT NULL,
  created_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE findings (
  id         SERIAL PRIMARY KEY,
  scan_id    INTEGER REFERENCES scans(id),
  type       TEXT,
  severity   TEXT,
  file       TEXT,
  line       INTEGER,
  content    TEXT,
  cve        TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

## Frontend (Dashboard)

A React 18 + Vite + Tailwind CSS single-page app located in `client/`. It communicates with the backend exclusively via the `/api/dashboard/*` REST endpoints. In development it runs on its own Vite dev server (proxied to the backend). In production, `npm run build:client` compiles it to `client/dist/`, which Express serves as static files.

---

## Deployment

```
GitHub push to main
        │
        ▼
.github/workflows/deploy.yml
        │
        ├── docker build -f docker/Dockerfile .
        │       Stage 1 (builder):  npm install + npm run build  (client/)
        │       Stage 2 (prod):     npm ci --only=production + copy client/dist
        │
        ├── docker push → Amazon ECR
        │
        └── aws ecs update-service --force-new-deployment
```

The two-stage Docker build ensures the production image contains only compiled assets and production Node modules — no dev dependencies, no Vite, no source maps.

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| CommonJS (`require`) throughout | Avoids ESM interop friction with older `@octokit/rest` and `pg` versions |
| No lint/format config committed | Low-friction for contributors; can be added incrementally |
| Static `VULNERABLE_PACKAGES` table | Deterministic, no network call at scan time; trade-off is manual maintenance |
| In-memory fallback store | Allows the webhook processor to run without any infrastructure for local testing |
| No wildcard catch-all Express route | Avoids masking 404s as 200s; uses a middleware-based fallback instead |
