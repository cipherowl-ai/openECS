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
docker run --env-file docker.env -p 8080:8080 -p 9090:9090 -v ~/keys/:/app/keys  ecsd:latest
```


### Environment Variables

The following environment variables can be configured:

#### Bloom Filter Configuration
- `CO_FILENAME`: Bloom filter file path (default: "bloomfilter.gob")
- `CO_DECRYPT_KEY`: Path to decrypt key file (default: "")
- `CO_SIGNING_KEY`: Path to signing key file (default: "")
- `CO_DECRYPT_KEY_PASSPHRASE`: Decrypt key passphrase (default: "")
- `CO_HASH`: If true, the bloom filter stores address hashes instead of addresses strings (default: false)

#### Server Configuration
- `CO_HTTP_PORT`: HTTP port (default: 8080)
- `CO_GRPC_PORT`: gRPC port (default: 9090)
- `CO_RATE_LIMIT`: Rate limit (default: 20)
- `CO_BURST`: Burst limit (default: 5)

#### Service Configuration (All Required)
- `CO_CHAIN`: Chain name
- `CO_DATASET`: Dataset name
- `CO_BASE_URL`: Base URL for the API
- `CO_CLIENT_ID`: Client ID
- `CO_CLIENT_SECRET`: Client secret

### Persistent Storage

```bash
# Create a named volume
docker volume create ecsd-data

# Run with volume mounted
docker run \
  --env-file docker.env \
  -v $(pwd)/ecsd/keypair/:/app/keys \
  -v $(pwd)/ecsd-data:/app/data \
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