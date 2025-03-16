# ECS Service for Bloom Filter

This is a Edge compliance service for Bloom filter. It is a simple HTTP service with GRPC interface that can be used to check if an address is in the Bloom filter.

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

# Use environment variables with GRPC port 9090 and HTTP port 8080, plus encryption keys
export KEY_PASSPHRASE=123456                    
./ecsd -f bloomfilter.gob -p 8080 -gp 9090 -r 2000 -b 5000 -private-key-file securedata/testdata/privkey.asc -public-key-file securedata/testdata/pubkey.asc
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

### Enable special bot caller mode

with a special header `__llm_bot_caller__: on`, the service will return explanations for LLM bots which returns a data dictionary of the json response to help the bot works better

```bash
curl http://localhost:8080/check?address=0x742d35Cc6634C0532925a3b844Bc454e4438f44e -H "__llm_bot_caller__: on"
```

```json
{
  "query": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
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
curl http://localhost:8080/check?address=0xE5a00E3FccEfcCd9e4bA75955e12b6710eB254bE -H "__llm_bot_caller__: 1" |jq
```

```json
{
  "query": "0xE5a00E3FccEfcCd9e4bA75955e12b6710eB254bE",
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
curl http://localhost:8080/inspect -H "__llm_bot_caller__: 1" |jq
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
```
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
grpcurl -plaintext -d '{"address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"}' localhost:9090 proto.ECSd.CheckAddress
```

Example output:
```json
{
  "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
}
```

### Batch Check Multiple Addresses

```bash
grpcurl -plaintext -d '{"addresses": ["0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "0xE5a00E3FccEfcCd9e4bA75955e12b6710eB254bE"]}' localhost:9090 proto.ECSd.BatchCheckAddresses
```

Example output:
```json
{
  "found": [
    "0xE5a00E3FccEfcCd9e4bA75955e12b6710eB254bE"
  ],
  "notFound": [
    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
  ],
  "foundCount": 1,
  "notFoundCount": 1
}
```

