# ---- Build Stage ----
FROM oven/bun:1-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package.json and lockfile first (better caching)
COPY package.json bun.lockb* ./

# Install deps
RUN bun install --omit=dev --omit=peer --omit=optional --frozen-lockfile

# Copy all project files
COPY . .

# Run your build script (creates /dist)
RUN bun run bun:build


# ---- Runtime Stage ----
FROM oven/bun:1-alpine

# Set working directory
WORKDIR /app

# Copy built dist files from builder
COPY --from=builder /app/dist ./dist

# Expose the port your Hono server runs on (default 3000?)
EXPOSE 3000

# Start the server with Bun
CMD ["bun", "./dist/index.js"]