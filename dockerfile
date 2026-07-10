# ─── Stage 1: Build the React Dashboard ──────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy the React source code (client folder)
COPY client/ ./client/

# Install dependencies and build the React app
WORKDIR /app/client
RUN npm install
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
#    The build output is in /app/client/dist
#    We copy it to /app/frontend/dist (where index.js expects it)
COPY --from=builder /app/client/dist ./frontend/dist

EXPOSE 3000

CMD ["node", "index.js"]