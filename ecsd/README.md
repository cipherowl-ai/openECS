# ECS Service for Bloom Filter

This is a Edge compliance service for Bloom filter. It is a simple HTTP service that can be used to check if an address is in the Bloom filter.

## Features

1. GET `/check?address=[address]` - check if an address is in the Bloom filter
2. POST `/batch-check` - check a list of addresses in JSON format (array of addresses), where the body is {"addresses":["address1","address2"]}, the list cannot be longer than 100 elements
3. GET `/inspect` - inspect the Bloom filter file and print the statistics and last update
4. GET `/health` - check the health of the service
5. PATCH `/update` - signal the filter update, the server will download the new filter from CO_BASE_URL with CO_CLIENT_ID and CO_CLIENT_SECRET credentials, and replace the path bloomfilter.gob. The new filter will be reloaded asynchronously in the background.

## Configuration

The service can be configured using command line options:

- `-f`: the path to the Bloom filter file (default: "bloomfilter.gob"), by default it is in .co_data
- `-p`: the port to listen on (default: 8080)
- `-r`: the rate limit (default: 20)
- `-b`: the burst (default: 5)
- `-private-key-file`: the path to the private key file (optional)
- `-public-key-file`: the path to the public key file (optional)

Environment variables can be set in a `.env` file in the service root directory:

- `CO_CLIENT_ID`: the client ID
- `CO_CLIENT_SECRET`: the client secret
- `CO_BASE_URL`: the base URL (default: "svc.cipherowl.ai")
- `CO_ENV`: the environment (default: "prod")
- `KEY_PASSPHRASE`: the passphrase for the private key

## Building and Running

### Build

```bash
cd cmd/ecsd
go build -o ecsd
```

### Run

```bash
# Run with default options
./ecsd

# Specify a different Bloom filter file
./ecsd -f /path/to/bloomfilter.gob

# Change the port
./ecsd -p 8081

# Set rate limits
./ecsd -r 50 -b 10

# Use encryption keys
./ecsd -private-key-file /path/to/private.key -public-key-file /path/to/public.key
```

## Docker

### Build Docker image

```bash
# From the repository root
docker build -t ecsd -f cmd/ecsd/Dockerfile .
```

### Run Docker container

```bash
# Run with default configuration
docker run -p 8080:8080 ecsd

# Set environment variables
docker run -p 8080:8080 \
  -e CO_CLIENT_ID=your_client_id \
  -e CO_CLIENT_SECRET=your_client_secret \
  -e CO_ENV=dev \
  ecsd

# Mount your own Bloom filter file
docker run -p 8080:8080 \
  -v /path/to/your/bloomfilter.gob:/app/bloomfilter.gob \
  ecsd -f bloomfilter.gob
```

## API Examples

### Check an address

```bash
curl "http://localhost:8080/check?address=0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
```

### Batch check addresses

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"addresses":["0x742d35Cc6634C0532925a3b844Bc454e4438f44e","0x1111111111111111111111111111111111111111"]}' \
  "http://localhost:8080/batch-check"
```

### Inspect the Bloom filter

```bash
curl "http://localhost:8080/inspect"
```

### Update the Bloom filter

```bash
curl -X POST -H "Content-Type: application/json" -d '{"url":"https://example.com/bloomfilter.gob"}' "http://localhost:8080/update"
```

### Health check

```bash
curl "http://localhost:8080/health"
```
