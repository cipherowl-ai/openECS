FROM ubuntu:22.04

WORKDIR /app

# Install required runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libc6 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Define ARGs for key file paths with defaults
ARG PRIVKEY_PATH=ecsd/keypair/privkey_sample.asc
ARG PUBKEY_PATH=ecsd/keypair/pubkey_sample.asc
ARG BINARY_PATH=target/release/pa-ecsd

# Create necessary directories
RUN mkdir -p /app/keys /app/data

# Copy the pre-built binary
COPY ${BINARY_PATH} /app/ecsd-bin

# Make the binary executable
RUN chmod +x /app/ecsd-bin

# Copy the key files
COPY ${PRIVKEY_PATH} /app/keys/privkey.asc
COPY ${PUBKEY_PATH} /app/keys/pubkey.asc

# Create a data directory for the bloomfilter
RUN mkdir -p /app/.co_data

# Default ports
EXPOSE 8080 9090

# Set configuration environment variables with defaults
ENV PORT=8080 \
    BURST=5 \
    RATELIMIT=20 \
    BLOOMFILTER_PATH="/app/data/bloomfilter.gob" 

# Create a volume for persistent bloom filter storage
VOLUME /app/data

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

# Create a wrapper script to handle environment variables
COPY <<-"EOF" /app/entrypoint.sh
#!/bin/sh
exec /app/ecsd-bin \
    -p ${PORT} \
    -b ${BURST} \
    -r ${RATELIMIT} \
    -f ${BLOOMFILTER_PATH} \
    -private-key-file /app/keys/privkey.asc \
    -public-key-file /app/keys/pubkey.asc
EOF

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"] 