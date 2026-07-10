FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (including dev dependencies needed for build)
RUN npm ci

# Copy all source code (including frontend)
COPY . .

# Build the React dashboard (if you have a build script)
# If you already have frontend/dist committed, you can skip this step
RUN cd frontend && npm install && npm run build

# ─── Production Stage ──────────────────────────────────
FROM node:20-alpine

WORKDIR /app

# Copy only production dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy backend source code
COPY . .

# ✅ CRITICAL: Copy the built React dashboard from the builder stage
COPY --from=builder /app/frontend/dist ./frontend/dist

EXPOSE 3000

CMD ["node", "index.js"]