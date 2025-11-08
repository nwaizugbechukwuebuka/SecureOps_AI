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

# Create nginx user and set permissions
RUN addgroup -g 101 nginx \
    && adduser -S -D -H -u 101 -h /var/cache/nginx -s /sbin/nologin -G nginx -g nginx nginx \
    && chown -R nginx:nginx /usr/share/nginx/html \
    && chown -R nginx:nginx /var/cache/nginx \
    && chown -R nginx:nginx /var/log/nginx

# Switch to nginx user
USER nginx

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/ || exit 1

# Switch to non-root user
USER nginx

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
