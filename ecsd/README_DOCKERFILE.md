# Docker Instructions for ECSD

## Building the Docker Image
Update Dockerfile, and make sure the ARG values are correct.

From the root directory of the project, run:

```bash
docker build -t ecsd -f ecsd/Dockerfile .
```

## Running the Container

### Basic Run Command
```bash
docker run -e CO_CLIENT_SECRET=your_secret -e KEY_PASSPHRASE=your_passphrase -p 18080:8080 -p 19090:9090 --rm ecsd
```

### Environment Variables

The following environment variables can be configured:

- Required:
  - `CO_CLIENT_SECRET`: Your CipherOwl client secret
  - `KEY_PASSPHRASE`: Your key passphrase

- Optional (with defaults):
  - `PORT`: Port to listen on (default: 8080)
  - `BURST`: Burst rate (default: 5)
  - `RATELIMIT`: Rate limit (default: 20)
  - `BLOOMFILTER_PATH`: Path to bloomfilter file (default: "/app/data/bloomfilter.gob")
  - `PRIVATE_KEY_FILE`: Path to private key file (default: "/app/keys/privkey.asc")
  - `PUBLIC_KEY_FILE`: Path to public key file (default: "/app/keys/pubkey.asc")

### Persistent Storage

To persist the Bloom filter data between container restarts:

```bash
# Create a named volume
docker volume create ecsd-data

# Run with volume mounted
docker run \
  -e CO_CLIENT_SECRET=your_secret \
  -e KEY_PASSPHRASE=your_passphrase \
  -p 18080:8080 \
  -p 19090:9090 \
  -v ecsd-data:/app/data \
  --rm \
  ecsd
```

## Port Mappings

- `8080`: HTTP service port (mapped to 18080 on host)
- `9090`: GRPC Secondary port (mapped to 19090 on host)

## Security Notes

1. Never commit sensitive information (secrets, keys) to version control
2. Use Docker secrets or environment files for production deployments
3. Consider using a non-root user in the container for production
4. Keep the base image and dependencies up to date 