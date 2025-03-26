# ECS Service for Bloom Filter

This is a Edge compliance service for Bloom filter. It is a simple HTTP service with GRPC interface that can be used to check if an address is in the Bloom filter.

## Features

1. GET `/check?address=[address]` - check if an address is in the Bloom filter
2. POST `/batch-check` - check a list of addresses in JSON format (array of addresses), where the body is {"addresses":["address1","address2"]}, the list cannot be longer than 100 elements
3. GET `/inspect` - inspect the Bloom filter file and print the statistics and last update
4. GET `/health` - check the health of the service
5. PATCH `/update` - signal the filter update, the server will download the new filter from CO_BASE_URL with CO_CLIENT_ID and CO_CLIENT_SECRET credentials, and replace the path bloomfilter.gob. The new filter will be reloaded asynchronously in the background.

## Configuration

The service can be configured using command line options or environment variables. Environment variables take precedence over command line flags.

### Command Line Options

- `-f, --filename`: Path to the Bloom filter file (default: "bloomfilter.gob")
- `-p, --port`: HTTP port to listen on (default: 8080)
- `--grpc-port`: gRPC port to listen on (default: 9090)
- `-r, --ratelimit`: Rate limit for requests (default: 20)
- `-b, --burst`: Burst limit for rate limiting (default: 5)
- `--decrypt-key`: Path to the decrypt key file (optional)
- `--signing-key`: Path to the signing key file (optional)
- `--decrypt-key-passphrase`: Passphrase for the decrypt key (optional)
- `--chain`: Chain name (required)
- `--dataset`: Dataset name (required)
- `--base-url`: Base URL for the API (required)
- `--client-id`: Client ID for authentication (required)
- `--client-secret`: Client secret for authentication (required)

### Environment Variables

All environment variables are prefixed with `CO_` and use underscores instead of hyphens. For example, `--decrypt-key` becomes `CO_DECRYPT_KEY`.

- `CO_FILENAME`: Bloom filter file path
- `CO_PORT`: HTTP port
- `CO_GRPC_PORT`: gRPC port
- `CO_RATELIMIT`: Rate limit
- `CO_BURST`: Burst limit
- `CO_DECRYPT_KEY`: Path to decrypt key file
- `CO_SIGNING_KEY`: Path to signing key file
- `CO_DECRYPT_KEY_PASSPHRASE`: Decrypt key passphrase
- `CO_CHAIN`: Chain name
- `CO_DATASET`: Dataset name
- `CO_BASE_URL`: Base URL for the API
- `CO_CLIENT_ID`: Client ID
- `CO_CLIENT_SECRET`: Client secret

### Example Usage

```bash
# Using command line flags
./ecsd --chain ethereum_mainnet --dataset co-demo --base-url https://api.example.com \
       --client-id your_client_id --client-secret your_client_secret

# Using environment variables
export CO_CHAIN=ethereum_mainnet
export CO_DATASET=co-demo
export CO_BASE_URL=https://api.example.com
export CO_CLIENT_ID=your_client_id
export CO_CLIENT_SECRET=your_client_secret
./ecsd
```

## Building and Running

### Build

```bash
make # target/*/pa-ecsd
```

### Run

```bash
# Run with default options
./target/release/pa-ecsd

# Specify a different Bloom filter file
./target/release/pa-ecsd -f /path/to/bloomfilter.gob

# Change the port
./target/release/pa-ecsd -p 8081

# Set rate limits
./target/release/pa-ecsd -r 50 -b 10

# Use environment variables with GRPC port 9090 and HTTP port 8080, plus encryption keys
export KEY_PASSPHRASE=123456 # the passphrase for the private key, alternatively can put into the `.env`                   
./target/release/pa-ecsd -f bloomfilter.gob -p 8080 -gp 9090 -r 2000 -b 5000 --decrypt-key securedata/testdata/privkey.asc --signing-key securedata/testdata/pubkey.asc
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
  -e KEY_PASSPHRASE=your_passphrase \
  -e CO_BASE_URL=your_base_url \
  ecsd

# Mount your own Bloom filter file
docker run -p 8080:8080 \
  -v /path/to/your/bloomfilter.gob:/app/bloomfilter.gob \
  ecsd -f bloomfilter.gob
```

## API Examples

### Check an address

```bash
curl "http://localhost:8080/check?address=0x96244d83dc15d36847c35209bbdc5bdde9bec3d8"
```

### Batch check addresses

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"addresses":["0x96244d83dc15d36847c35209bbdc5bdde9bec3d8","0x1111111111111111111111111111111111111111"]}' \
  "http://localhost:8080/batch-check"
```

### Inspect the Bloom filter

```bash
curl "http://localhost:8080/inspect"
```

### Health check

```bash
curl "http://localhost:8080/health"
```

### Enable special bot caller mode

with a special header `__llm_bot_caller__: on`, the service will return explanations for LLM bots which returns a data dictionary of the json response to help the bot works better

```bash
curl "http://localhost:8080/check?address=0xE5a00E3FccEfcCd9e4bA75955e12b6710eB254bE" -H "__llm_bot_caller__: on" | jq
```

```json
{
  "query": "0xE5a00E3FccEfcCd9e4bA75955e12b6710eB254bE",
  "in_set": false,
  "message": "",
  "__llm_explanations__data_dictionary__": {
    "in_set": "Whether the address was found in the Bloom filter (true) or not (false). Note that Bloom filters may have false positives but never false negatives",
    "message": "Additional information or error message",
    "query": "The address that was queried"
  }
}
```

```bash
curl "http://localhost:8080/check?address=0x96244d83dc15d36847c35209bbdc5bdde9bec3d8" -H "__llm_bot_caller__: 1" | jq
```

```json
{
  "query": "0x96244d83dc15d36847c35209bbdc5bdde9bec3d8",
  "in_set": true,
  "message": "",
  "__llm_explanations__data_dictionary__": {
    "in_set": "Whether the address was found in the Bloom filter (true) or not (false). Note that Bloom filters may have false positives but never false negatives",
    "message": "Additional information or error message",
    "query": "The address that was queried"
  }
}

```

```bash
curl http://localhost:8080/inspect -H "__llm_bot_caller__: 1" | jq
```

```json
{
  "stats": {
    "k": 7,
    "m": 26168,
    "n": 1007,
    "estimated_capacity": 3738,
    "false_positive_rate": 4.094744429579303e-05
  },
  "last_update": "2025-03-15T22:54:07Z",
  "__llm_explanations__data_dictionary__": {
    "estimated_capacity": "Estimated maximum capacity of the Bloom filter before exceeding the false positive probability threshold",
    "false_positive_rate": "Estimated probability that the filter will incorrectly report that an element is in the set when it is not",
    "k": "Number of hash functions used in the Bloom filter",
    "last_update": "ISO 8601 timestamp of when the Bloom filter was last updated",
    "m": "Size of the bit array in the Bloom filter",
    "n": "Number of elements added to the Bloom filter"
  }
}
```

## Using the gRPC Interface

The ECSD service also provides a gRPC interface on port 9090 (by default). You can interact with it using tools like `grpcurl`.

### List Available Services

```bash
grpcurl -plaintext localhost:9090 list
```

Output:
```
grpc.reflection.v1.ServerReflection
grpc.reflection.v1alpha.ServerReflection
proto.ECSd
```

### List Available Methods

```bash
grpcurl -plaintext localhost:9090 list proto.ECSd
```

Output:
```bash
proto.ECSd.BatchCheckAddresses
proto.ECSd.CheckAddress
proto.ECSd.InspectFilter
```

### Get Bloom Filter Statistics

```bash
grpcurl -plaintext localhost:9090 proto.ECSd.InspectFilter
```

Example output:
```json
{
  "k": 7,
  "m": "26168",
  "n": "1007",
  "estimatedCapacity": "3738",
  "falsePositiveRate": 4.094744429579303e-05,
  "lastUpdate": "2025-03-16T05:21:54Z"
}
```

### Check if an Address is in the Filter

```bash
grpcurl -plaintext -d '{"address": "0x96244d83dc15d36847c35209bbdc5bdde9bec3d8"}' localhost:9090 proto.ECSd.CheckAddress
```

Example output:
```json
{
  "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "isSet": true
}
```

### Batch Check Multiple Addresses

```bash
grpcurl -plaintext -d '{"addresses": ["0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "0x96244d83dc15d36847c35209bbdc5bdde9bec3d8"]}' localhost:9090 proto.ECSd.BatchCheckAddresses
```

Example output:
```json
{
  "found": [
    "0x96244d83dc15d36847c35209bbdc5bdde9bec3d8"
  ],
  "notFound": [
    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
  ],
  "foundCount": 1,
  "notFoundCount": 1
}
```

