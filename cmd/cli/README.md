# CLI tool for working with address bloom filters

## usage

### Encoder to build a bloomfilter from a list of addresses
```bash
pa-cli encode --input ./addresses.txt --public-key-file securedata/testdata/pubkey.asc --output ./bloomfilter.gob
```

- `-input`: Input file path, one address per line
- `-output`: Output file path, it is a binary bloomfilter file, the content is not human readable.
- `-n`: Number of entries (should match the number of generated addresses)
- `-p`: False positive rate. e.g. 0.000001 is 1 in a million.
- `--public-key-file`: Path to the recipient public key file

### Console based interactive client for testing bloomfilter

```bash
pa-cli check -f=./bloomfilter.gob --public-key-file securedata/testdata/pubkey.asc
```

- `-f`: Path to the bloomfilter file
- `--public-key-file`: Path to the sender public key file

### A Batch Checker for bloomfilter

```bash
cat btc_tocheck.txt | pa-cli batch-check -f=./bloomfilter.gob --public-key-file ./public.asc > /tmp/missing.txt
```

Where btc_tocheck.txt is a file with one address per line

- `-f`: Path to the bloomfilter file
- `--public-key-file`: Path to the sender public key file

### A Batch Checker for bloomfilter

```bash
pa-cli generate-addresses --output ./addresses.txt -n 1000000
```

Where btc_tocheck.txt is a file with one address per line

### Add addresses to a bloomfilter

```bash
pa-cli add --file ./bloomfilter.gob --address 0x1234567890123456789012345678901234567890 --output ./bloomfilter.gob
```

- `-f`: Path to the bloomfilter file
- `--address`: Address to add
- `--output`: Path to the output bloomfilter file

### Generate a pgp key pair

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