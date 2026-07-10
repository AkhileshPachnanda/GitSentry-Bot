# Contributing to GitSentry Bot

Thank you for taking the time to contribute! This document covers everything you need to get up and running, add new detection capability, write tests, and submit a clean PR.

---

## Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Adding a New Scanner Pattern](#adding-a-new-scanner-pattern)
- [Coding Standards](#coding-standards)
- [Commit Conventions](#commit-conventions)
- [Testing Guidelines](#testing-guidelines)
- [Submitting a Pull Request](#submitting-a-pull-request)

---

## Development Setup

### Prerequisites

- **Node.js** 18 or later
- **npm** 9 or later
- A registered [GitHub App](https://docs.github.com/en/apps/creating-github-apps) with `pull_requests: write` permission and a webhook subscribed to `pull_request` events
- (Optional) A local PostgreSQL instance — the server falls back to an in-memory store when `DATABASE_URL` is absent

### Steps

```bash
# 1. Fork + clone
git clone https://github.com/<your-fork>/GitSentry-Bot.git
cd GitSentry-Bot

# 2. Install backend dependencies
npm install

# 3. Install frontend dependencies
cd client && npm install && cd ..

# 4. Configure environment
cp .env.example .env
# Edit .env and fill in:
#   GITHUB_APP_ID
#   GITHUB_PRIVATE_KEY_PATH   (path to your downloaded .pem)
#   WEBHOOK_SECRET            (the secret set on your GitHub App webhook)
#   DATABASE_URL              (optional Postgres URI)

# 5. Start the backend
npm run dev

# 6. Start the dashboard (separate terminal)
npm run dev:client
```

> **Tip:** Use [smee.io](https://smee.io/) or [ngrok](https://ngrok.com/) to forward GitHub webhook events to your local server during development.

---

## Project Structure

```
src/
├── config/index.js       # Environment-driven config (port, secrets, IDs)
├── lib/
│   ├── logger.js         # Levelled console logger
│   ├── security.js       # HMAC-SHA256 webhook signature verification
│   └── githubauth.js     # GitHub App JWT + installation token logic
├── scanners/
│   ├── regex.js          # Pattern-based secret detection
│   ├── entropy.js        # Shannon entropy secret detection
│   └── dependency.js     # Vulnerable dependency cross-referencing
├── dashboard/
│   └── store.js          # PostgreSQL / in-memory persistence layer
└── index.js              # Express app + route definitions
tests/                    # node:test suite
client/                   # React + Vite dashboard
docker/                   # Dockerfile + docker-compose.yml
.github/workflows/        # CI/CD (ECS deploy)
```

---

## Adding a New Scanner Pattern

GitSentry has two places where detection patterns live depending on what you want to detect.

### A. Adding a new regex pattern (known credential format)

Open [`src/scanners/regex.js`](src/scanners/regex.js) and add an entry to the `patterns` array:

```js
const patterns = [
  // existing patterns …
  { regex: /YOUR_REGEX_HERE/g, type: "Human-readable label" },
];
```

**Rules:**
- The regex **must** use the `g` flag so `exec` loops correctly.
- The `type` string appears verbatim in the PR review comment — keep it short and descriptive (e.g. `"Slack Bot Token"`, `"Twilio Auth Token"`).
- Only added diff lines (those prefixed with `+`) are evaluated — the scanner handles this automatically.
- Add at least one positive and one negative test case in `tests/` (see [Testing Guidelines](#testing-guidelines)).

### B. Adding a new vulnerable dependency

Open [`src/scanners/dependency.js`](src/scanners/dependency.js) and add an entry to `VULNERABLE_PACKAGES`:

```js
const VULNERABLE_PACKAGES = {
  // existing entries …
  "package-name": {
    versions: ["< X.Y.Z"],       // semver range(s) considered vulnerable
    severity: "high",            // "critical" | "high" | "medium" | "low"
    title: "Short description",
    cve: "CVE-YYYY-NNNNN",       // use "N/A" if no CVE is assigned
  },
};
```

**Rules:**
- Source CVE data from the [OSV database](https://osv.dev/), [NVD](https://nvd.nist.gov/), or the package's own security advisories.
- Include the CVE number wherever one exists.
- Add a note in the PR description linking to the advisory.

### C. Adding an entirely new scanner

1. Create `src/scanners/<name>.js` — export an async function with the signature:

   ```js
   /**
    * @param {string} diffContent - Raw unified diff text from the GitHub API
    * @returns {Promise<Finding[]>}
    */
   async function scanForXxx(diffContent) { … }
   module.exports = { scanForXxx };
   ```

2. Import and call it in [`src/index.js`](src/index.js) inside the webhook handler, then spread the results into `allFindings`.

3. Ensure your findings conform to the shared shape:

   ```js
   {
     line: Number,       // 1-indexed line number in the diff
     content: String,    // sanitised line content (no leading "+")
     type: String,       // human-readable finding label
     category: String,   // "secret" | "dependency" | (your new category)
     severity: String,   // "critical" | "high" | "medium" | "low"
   }
   ```

---

## Coding Standards

- **Style:** The project uses no linter config yet — follow the style of the existing files (2-space indent, single quotes, trailing commas in multi-line arrays/objects).
- **`require` only:** The project uses CommonJS (`"type": "commonjs"` in `package.json`). Do not use `import`/`export`.
- **No external runtime dependencies** for utility code — prefer Node built-ins (`crypto`, `fs`, `path`, `os`) over adding packages.
- **Error handling:** Never let an unhandled promise rejection crash the server. Wrap scanner calls in try/catch and log with `logger.error`.
- **Logging:** Use the shared logger (`src/lib/logger.js`), not `console.log` directly. Choose the right level:
  - `logger.error` — operation failed, requires attention
  - `logger.warn` — suspicious but recoverable (e.g. rejected webhook)
  - `logger.info` — normal operational events (scan started/completed)
  - `logger.debug` — verbose detail useful during development
- **JSDoc:** Add JSDoc comments to all exported functions (params, return type, brief description).

---

## Commit Conventions

This project follows the [Conventional Commits](https://www.conventionalcommits.org/) specification.

```
<type>(<optional scope>): <short summary>

[optional body]

[optional footer]
```

### Types

| Type | When to use |
|---|---|
| `feat` | A new scanner pattern, endpoint, or feature |
| `fix` | A bug fix |
| `docs` | Documentation only |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or updating tests |
| `chore` | Build process, dependency updates, CI/CD changes |
| `perf` | Performance improvement |

### Examples

```
feat(scanners): add Slack bot token pattern
fix(security): handle missing rawBody in webhook verification
docs: expand CONTRIBUTING scanner section
test(entropy): add edge case for short string below threshold
chore(ci): specify Dockerfile path in ECR build step
```

**Rules:**
- Summary is lowercase, no trailing period, ≤ 72 characters.
- Reference issues/PRs in the footer: `Closes #42`, `Refs #17`.

---

## Testing Guidelines

Tests live in `tests/` and use Node's built-in `node:test` runner (no external test framework needed).

### Running tests

```bash
npm test
```

### Writing a test

```js
const test = require("node:test");
const assert = require("node:assert/strict");
const { scanForSecrets } = require("../src/scanners/regex");

test("detects AWS access key in added line", () => {
  const diff = "+  const key = 'AKIAIOSFODNN7EXAMPLE';\n";
  const findings = scanForSecrets(diff);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, "AWS Access Key");
});

test("does not flag removed lines", () => {
  const diff = "-  const key = 'AKIAIOSFODNN7EXAMPLE';\n";
  const findings = scanForSecrets(diff);
  assert.equal(findings.length, 0);
});
```

### Expectations for every PR

- **New regex pattern** → at least one positive match test + one negative (removed line, unrelated content).
- **New dependency entry** → test with a vulnerable version string and a safe version string.
- **New scanner module** → cover the happy path, empty diff, and `null`/`undefined` input.
- **Security-related changes** → update `tests/security.test.js` accordingly.

All tests must pass before a PR will be reviewed.

---

## Submitting a Pull Request

1. Branch off `main`: `git checkout -b feat/my-feature`
2. Make your changes, following the standards above.
3. Run `npm test` — all tests must pass.
4. Push your branch and open a PR against `main`.
5. Fill in the PR description:
   - What problem does this solve?
   - What approach did you take?
   - Link any relevant issues or advisories.
6. A maintainer will review within a few days. Please be responsive to feedback.
