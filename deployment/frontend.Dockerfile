# Multi-stage Dockerfile for SecureOps Frontend
FROM node:20-alpine as builder

# Set working directory
WORKDIR /app

# Copy package files
COPY src/frontend/package.json src/frontend/package-lock.json* ./

# Install all dependencies (including dev) so vite is available for build
RUN npm ci && npm cache clean --force

# Copy source code
COPY src/frontend/ .

# Build the application
RUN npm run build

# Production stage
FROM nginx:alpine as production

# Install curl for health checks
RUN apk add --no-cache curl

# Copy built application from builder stage (Vite outputs to dist by default)
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom nginx configurations
COPY deployment/nginx-frontend.conf /etc/nginx/conf.d/default.conf
COPY deployment/nginx-frontend-main.conf /etc/nginx/nginx.conf

# Create directories and set permissions for nginx user
RUN mkdir -p /tmp/nginx && \
    chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /tmp/nginx && \
    chmod -R 755 /tmp/nginx

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Switch to non-root user
USER nginx

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
