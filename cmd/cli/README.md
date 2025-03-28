# CLI tool for working with address bloom filters

## Commands

### Generate Addresses
Generate Ethereum addresses for testing purposes.
```bash
pa-cli generate-addresses --output ./addresses.txt -n 1000000
```

Options:
- `-n, --n`: Number of addresses to generate (default: 1000000)
- `-o, --output`: Output file path (default: "addresses.txt")

### Encode Addresses to Bloom Filter
Create a bloom filter from a list of addresses.
```bash
pa-cli encode --input ./addresses.txt --output ./bloomfilter.gob \
    --signing-key securedata/testdata/privkey.asc --encrypt-key securedata/testdata/pubkey.asc \
    --signing-key-passphrase "123456" --hash
```

Options:
- `-i, --input`: Input file path containing addresses (default: "addresses.txt")
- `-o, --output`: Output bloom filter file path (default: "bloomfilter.gob")
- `-n, --number`: Number of elements expected (default: 10000000)
- `-p, --probability`: False positive probability (default: 0.00001)
- `-s, --signing-key`: Path to the signing key file
- `-e, --encrypt-key`: Path to the encryption key file
- `-p, --signing-key-passphrase`: Passphrase for the signing key
- `--hash`: Convert addresses to hash values (accepts both EVM addresses and int64 strings)

### Interactive Address Checker
Check individual addresses against a bloom filter interactively.
```bash
pa-cli check --filename ./bloomfilter.gob \
    --decrypt-key securedata/testdata/privkey.asc --signing-key securedata/testdata/pubkey.asc \
    --decrypt-key-passphrase "123456" --hash
```

Options:
- `-f, --filename`: Path to the bloom filter file (default: "bloomfilter.gob")
- `-d, --decrypt-key`: Path to the decrypt key file
- `-s, --signing-key`: Path to the signing key file
- `-p, --decrypt-key-passphrase`: Passphrase for the decrypt key
- `--hash`: Check addresses as hash values (accepts both EVM addresses and int64 strings)

### Batch Address Checker
Check multiple addresses from stdin against a bloom filter.
```bash
cat addresses.txt | ./pa-cli batch-check --filename ./bloomfilter.gob \
    --decrypt-key ./securedata/testdata/privkey.asc --signing-key ./securedata/testdata/pubkey.asc \
    --decrypt-key-passphrase "123456" --hash
```

Options:
- `-f, --filename`: Path to the bloom filter file (default: "bloomfilter.gob")
- `-d, --decrypt-key`: Path to the decrypt key file
- `-s, --signing-key`: Path to the signing key file
- `-p, --decrypt-key-passphrase`: Passphrase for the decrypt key
- `--hash`: Check addresses as hash values (accepts both EVM addresses and int64 strings)

### Add Address to Bloom Filter
Add a single address to an existing bloom filter.
```bash
./pa-cli add --input ./bloomfilter.gob --address 0x1234567890123456789012345678901234567890 --output ./bloomfilter.gob --hash
```

Options:
- `-i, --input`: Input bloom filter file path (default: "bloomfilter.gob")
- `-o, --output`: Output bloom filter file path (default: "bloomfilter.gob")
- `-a, --address`: Address to add (required)
- `--hash`: Add address as hash value (accepts both EVM addresses and int64 strings)

### Inspect Bloom Filter
Inspect the statistics and metadata of a bloom filter.
```bash
./pa-cli inspect --filename ./bloomfilter.gob \
    --decrypt-key ./securedata/testdata/privkey.asc --signing-key ./securedata/testdata/pubkey.asc \
    --decrypt-key-passphrase "123456" \
    --json
```

Options:
- `-f, --filename`: Path to the bloom filter file (default: "bloomfilter.gob")
- `-j, --json`: Output in JSON format (default: false)
- `-d, --decrypt-key`: Path to the decrypt key file
- `-s, --signing-key`: Path to the signing key file
- `-p, --decrypt-key-passphrase`: Passphrase for the decrypt key

## Environment Variables

All command line flags can be configured using environment variables. The environment variables are prefixed with `CO_` and use underscores instead of hyphens. For example:

- `CO_FILENAME` corresponds to `--filename`
- `CO_DECRYPT_KEY` corresponds to `--decrypt-key`
- `CO_SIGNING_KEY` corresponds to `--signing-key`
- `CO_DECRYPT_KEY_PASSPHRASE` corresponds to `--decrypt-key-passphrase`
- `CO_ENCRYPT_KEY` corresponds to `--encrypt-key`
- `CO_SIGNING_KEY_PASSPHRASE` corresponds to `--signing-key-passphrase`

## Example Usage

1. Generate test addresses:
```bash
pa-cli generate-addresses -n 1000000 -o ./addresses.txt
```

2. Create an encrypted bloom filter with hash mode:
```bash
pa-cli encode -i ./addresses.txt -o ./bloomfilter.gob \
    --signing-key ./keys/private.asc \
    --encrypt-key ./keys/public.asc \
    --signing-key-passphrase "123456" \
    --hash
```

3. Check addresses interactively with hash mode:
```bash
pa-cli check -f ./bloomfilter.gob \
    --decrypt-key ./keys/private.asc \
    --signing-key ./keys/public.asc \
    --decrypt-key-passphrase "123456" \
    --hash
```

4. Batch check addresses with hash mode:
```bash
cat addresses_to_check.txt | pa-cli batch-check -f ./bloomfilter.gob \
    --decrypt-key ./keys/private.asc \
    --signing-key ./keys/public.asc \
    --decrypt-key-passphrase "123456" \
    --hash
```

5. Inspect bloom filter statistics:
```bash
pa-cli inspect -f ./bloomfilter.gob --json
```

```bash
gpg --full-generate-key
```

- Follow the prompts to configure the key's type, size, expiration, and user identity (name, email, etc.).
- Provide a passphrase when prompted.

```bash
gpg --list-keys
```

- This command displays your public keys. Identify the Key ID or Fingerprint of the newly created key.

```bash
gpg --armor --export <KEY_ID> > test_public.asc
gpg --armor --export-secret-key <KEY_ID> > test_private.asc
```

- This command exports the public key to public.asc and the private key to private.asc.