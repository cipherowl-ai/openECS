FROM alpine:latest

WORKDIR /app

# Copy the pre-built binary
COPY target/release/pa_unix-ecsd /app/ecsd

# Copy the default bloomfilter.gob
COPY bloomfilter.gob /app/bloomfilter.gob

# Copy the key files
COPY ecsd/keypair/privkey_sample.asc /app/keys/privkey.asc
COPY ecsd/keypair/pubkey_sample.asc /app/keys/pubkey.asc

# Create a data directory for the bloomfilter
RUN mkdir -p /app/.co_data

# Make the binary executable
RUN chmod +x /app/ecsd

# Default ports
EXPOSE 8080 9090

# Set environment variables
ENV CO_CLIENT_ID=""
ENV CO_CLIENT_SECRET=""
ENV CO_BASE_URL="svc.cipherowl.ai"
ENV CO_ENV="prod"
ENV KEY_PASSPHRASE=""

# Default command
ENTRYPOINT ["/app/ecsd"]
CMD ["-f", "/app/bloomfilter.gob", "-private-key-file", "/app/keys/privkey.asc", "-public-key-file", "/app/keys/pubkey.asc"] 