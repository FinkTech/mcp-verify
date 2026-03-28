# --- Stage 1: Builder ---
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci

# Copy source code
COPY . .

# Build the single-file bundle
RUN npm run build

# --- Stage 2: Runner ---
FROM node:20-alpine

WORKDIR /app

# Create a non-root user for security (Best Practice)
RUN addgroup -S mcp && adduser -S mcp -G mcp

# Copy only the bundled artifact from builder
COPY --from=builder /app/dist/mcp-verify.js ./mcp-verify.js

# Set permissions
RUN chown mcp:mcp /app/mcp-verify.js

# Switch to non-root user
USER mcp

# Define entrypoint
ENTRYPOINT ["node", "/app/mcp-verify.js"]
CMD ["--help"]
