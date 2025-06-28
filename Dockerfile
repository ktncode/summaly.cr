FROM crystallang/crystal:1.7.3-alpine AS builder

WORKDIR /app

# Install dependencies for MyHTML
RUN apk add --no-cache --update \
    gcc \
    g++ \
    musl-dev \
    libxml2-dev \
    yaml-dev \
    zlib-dev

# Copy dependency files
COPY shard.yml shard.lock ./

# Install shards
RUN shards install --production

# Copy source code
COPY src/ ./src/

# Build the application
RUN shards build --release --static

# Runtime stage
FROM alpine:3.17

RUN apk add --no-cache --update \
    ca-certificates \
    tzdata

WORKDIR /app

# Copy the binary
COPY --from=builder /app/bin/summaly ./

# Create non-root user
RUN addgroup -g 1000 summaly && \
    adduser -D -s /bin/sh -u 1000 -G summaly summaly

USER summaly

EXPOSE 12267

ENTRYPOINT ["./summaly"]
