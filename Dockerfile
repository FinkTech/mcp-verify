# --- Stage 1: Builder ---
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies for the entire workspace
# Copy root package files
COPY package*.json ./

# Copy all workspace package files using a more maintainable approach
# This ensures npm ci has the context of the workspaces
COPY apps/ ./apps/
COPY libs/ ./libs/

# Remove everything except package.json files from the workspaces to optimize cache
# This is a trick to only invalidate the cache when dependencies change
RUN find apps libs -type f ! -name "package.json" -delete

# Now we can safely run npm ci with full workspace context
RUN npm ci

# Copy the actual source code (this will overwrite the package.json files but that's fine)
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
