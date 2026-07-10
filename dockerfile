# ─── Stage 1: Build the React Dashboard ──────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy the React source code (client folder)
COPY client/ ./client/

# Install dependencies
WORKDIR /app/client
RUN npm install

# 🔧 Fix: Ensure vite binary is executable
RUN chmod +x node_modules/.bin/vite

# Build the React app
RUN npm run build

# ─── Stage 2: Production Backend ──────────────────────
FROM node:20-alpine

WORKDIR /app

# Copy backend package files and install production dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy backend source code
COPY . .

# ✅ Copy the built React dashboard from the builder stage
COPY --from=builder /app/client/dist ./frontend/dist

EXPOSE 3000

CMD ["node", "index.js"]