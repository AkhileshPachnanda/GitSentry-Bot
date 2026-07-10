# GitSentry Bot

GitSentry Bot is a production-ready GitHub webhook service that scans pull requests for exposed secrets, high-entropy strings, and vulnerable dependencies. It is designed for secure automation and can be deployed behind a GitHub App with a private key.

## Features

- Verifies GitHub webhook signatures before processing events
- Scans pull request diffs for secrets and suspicious strings
- Checks dependency manifests for known vulnerable packages
- Publishes review comments back to GitHub pull requests
- Exposes a lightweight health endpoint for deployment checks

## Setup

1. Copy [.env.example](.env.example) to .env and fill in the required values.
2. Install dependencies:
   - npm install
3. Start the service:
   - npm start

## Scripts

- npm start: start the server
- npm test: run the regression test suite

## API

- GET /healthz: health check
- POST /api/webhook: GitHub webhook receiver
