# Builder image
FROM golang:1.22-alpine3.21 AS builder

# Install required runtime dependencies
# RUN apk add --no-cache \
#     ca-certificates \
#     libc6 \
#     libssl3 \
#     && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN go build -o ecsd-bin cmd/ecsd/main.go

# Runtime image
FROM alpine:3.21

WORKDIR /app

# Create necessary directories
RUN mkdir -p /app/keys /app/data

# Copy the binary and public key
COPY --from=builder /app/ecsd-bin /app/ecsd-bin
COPY --from=builder /app/ecsd/keypair/cipherowl-inc-ecs-signing-prod-public.asc /app/keys/cipherowl-inc-ecs-signing-prod-public.asc

# Default ports
EXPOSE 8080 9090

# Set configuration environment variables with defaults
ENV PORT=8080 \
    BURST=5 \
    RATELIMIT=20 \
    BLOOMFILTER_PATH="/app/data/bloomfilter.gob"

# Create a volume for persistent bloom filter storage
VOLUME /app/data

VOLUME /app/keys

# SECURITY NOTE: Sensitive variables should be passed at runtime, not in the Dockerfile
# CO_CLIENT_SECRET
# KEY_PASSPHRASE
# Examples:
# 1. Using environment variables (less secure):
#    docker run -e CO_CLIENT_SECRET=your_secret -e KEY_PASSPHRASE=your_passphrase your-image-name
# 
# 2. Using Docker secrets (more secure, requires swarm mode):
#    # First, create secrets:
#    docker secret create co_client_secret ./client_secret.txt
#    docker secret create key_passphrase ./passphrase.txt
#    
#    # Then deploy service with secrets:
#    docker service create \
#      --name ecsd-service \
#      --secret co_client_secret \
#      --secret key_passphrase \
#      --env CO_CLIENT_SECRET_FILE=/run/secrets/co_client_secret \
#      --env KEY_PASSPHRASE_FILE=/run/secrets/key_passphrase \
#      your-image-name
# 
# 3. Using environment files:
#    docker run --env-file=./secure.env your-image-name

ENTRYPOINT ["/app/ecsd-bin"]