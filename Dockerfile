# Multi-stage Dockerfile for Observable Framework app
# This allows users to run the application without installing Node.js or npm locally

# Stage 1: Build dependencies and application
FROM node:20-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Copy source code
COPY . .

# Build the application (if needed for production)
# Note: Observable Framework typically runs in dev mode for local development
# RUN npm run build

# Stage 2: Production runtime
FROM node:20-alpine AS runtime

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S observable -u 1001 -G nodejs

# Set working directory
WORKDIR /app

# Copy built application from builder stage
COPY --from=builder --chown=observable:nodejs /app .

# Switch to non-root user
USER observable

# Expose the port Observable Framework uses
EXPOSE 3000

# Health check to ensure the application is running
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000 || exit 1

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the Observable Framework development server
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"]