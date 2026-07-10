# GitSentry Bot

GitSentry Bot is a production-ready GitHub webhook service that scans pull requests for exposed secrets, high-entropy strings, and vulnerable dependencies. It is designed for secure automation and can be deployed behind a GitHub App with a private key.

## What this project now includes

- A backend webhook processor running on Node.js + Express
- A React + Tailwind dashboard for scan history and findings
- A dashboard API backed by an in-memory store or PostgreSQL when DATABASE_URL is provided
- GitHub PR review comments for detected issues
- Health and dashboard endpoints for deployment visibility

## Architecture

- Backend: Node.js + Express
- Dashboard UI: React + Tailwind CSS
- Persistence: PostgreSQL (optional) or in-memory fallback for local development
- Deployment: AWS ECS ready for the backend service

## Setup

1. Copy [.env.example](.env.example) to .env and fill in the required values.
2. Install backend dependencies:
   - npm install
3. Install dashboard dependencies:
   - cd client && npm install
4. Start the backend:
   - npm start
5. Start the dashboard locally:
   - npm run dev:client

## Scripts

- npm start: start the backend server
- npm run dev:client: start the React dashboard locally
- npm run build:client: build the dashboard for production
- npm test: run the regression suite

## API

- GET /healthz: health check
- POST /api/webhook: GitHub webhook receiver
- GET /api/dashboard/summary: overview metrics
- GET /api/dashboard/scans: recent scan history
- GET /api/dashboard/findings: recent findings
