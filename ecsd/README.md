# ECS Service for Bloom Filter

This is an Edge compliance service for Bloom filter. It provides both HTTP and gRPC interfaces for checking addresses against a Bloom filter.

## Features

1. HTTP Endpoints:
   - GET `/check?address=[address]` - Check if an address is in the Bloom filter
   - POST `/batch-check` - Check multiple addresses (max 100) with body `{"addresses":["addr1","addr2"]}`
   - GET `/inspect` - Get Bloom filter statistics and last update time
   - GET `/health` - Check service health

2. gRPC Services:
   - `CheckAddress` - Check single address
   - `BatchCheckAddresses` - Check multiple addresses
   - `InspectFilter` - Get filter statistics

## Configuration

Configuration can be done via command-line flags or environment variables. command-line flags take precedence.

### Command Line Options

#### Bloom Filter Options
- `-f, --filename`: Path to the Bloom filter file (default: "bloomfilter.gob")
- `--decrypt-key`: Path to the decrypt key file (default: "")
- `--signing-key`: Path to the signing key file (default: "")
- `--decrypt-key-passphrase`: Passphrase for the decrypt key (default: "")

#### Server Options
- `--http-port`: HTTP port to listen on (default: 8080)
- `--grpc-port`: gRPC port to listen on (default: 9090)
- `--rate-limit`: Rate limit for requests (default: 20)
- `--burst`: Burst limit for rate limiting (default: 5)

#### Service Options (All Required)
- `--chain`: Chain name (e.g., "ethereum_mainnet")
- `--dataset`: Dataset name (e.g., "co-demo")
- `--base-url`: Base URL for the API (e.g., "https://api.example.com")
- `--client-id`: Client ID for authentication
- `--client-secret`: Client secret for authentication

### Environment Variables

All environment variables are prefixed with `CO_` and use underscores instead of hyphens. For example, `--decrypt-key` becomes `CO_DECRYPT_KEY`.

#### Bloom Filter Configuration
- `CO_FILENAME`: Bloom filter file path (default: "bloomfilter.gob")
- `CO_DECRYPT_KEY`: Path to decrypt key file (default: "")
- `CO_SIGNING_KEY`: Path to signing key file (default: "")
- `CO_DECRYPT_KEY_PASSPHRASE`: Decrypt key passphrase (default: "")

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
Copy 'example.local.env' to 'docker.env' and modify the variables as needed.

```bash
# Run with default configuration
docker run -p 8080:8080 ecsd

# Set environment variables
docker run docker run --env-file docker.env -p 8080:8080 -p 9090:9090 -v $(pwd)/ecsd/keypair/:/app/keys --rm ecsd:latest

# Mount your own Bloom filter file
docker run -p 8080:8080 \
  -v /path/to/your/bloomfilter.gob:/app/bloomfilter.gob \
  ecsd -f bloomfilter.gob
```
For more details, see [README_DOCKERFILE.md](README_DOCKERFILE.md).


## API Examples

### HTTP Examples

#### Check Single Address
```bash
curl "http://localhost:8080/check?address=0x96244d83dc15d36847c35209bbdc5bdde9bec3d8"
```

#### Batch Check Addresses
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"addresses":["0x96244d83dc15d36847c35209bbdc5bdde9bec3d8","0x1111111111111111111111111111111111111111"]}' \
  "http://localhost:8080/batch-check"
```

#### Inspect Filter
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