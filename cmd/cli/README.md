# CLI tool for working with address bloom filters

## usage

### Encoder to build a bloomfilter from a list of addresses
```bash
pa-cli encode --input ./addresses.txt --output ./bloomfilter.gob -n 1000000 -p 0.000001 --private-key-file ./private.asc --public-key-file ./public.asc --private-key-passphrase "123456"
```

- `-input`: Input file path, one address per line
- `-output`: Output file path, it is a binary bloomfilter file, the content is not human readable.
- `-n`: Number of entries (should match the number of generated addresses)
- `-p`: False positive rate. e.g. 0.000001 is 1 in a million.
- `--private-key-file`: Path to the sender private key file
- `--public-key-file`: Path to the recipient public key file
- `--private-key-passphrase`: Passphrase for the sender private key

### Console based interactive client for testing bloomfilter

```bash
pa-cli check -f=./bloomfilter.gob --private-key-file ./private.asc --public-key-file ./public.asc --private-key-passphrase "123456"
```

- `-f`: Path to the bloomfilter file
- `--private-key-file`: Path to the recipient private key file
- `--public-key-file`: Path to the sender public key file
- `--private-key-passphrase`: Passphrase for the recipient private key

### A Batch Checker for bloomfilter

```bash
cat btc_tocheck.txt | pa-cli batch-check -f=./bloomfilter.gob --private-key-file ./private.asc --public-key-file ./public.asc --private-key-passphrase "123456" > /tmp/missing.txt
```

Where btc_tocheck.txt is a file with one address per line

- `-f`: Path to the bloomfilter file
- `--private-key-file`: Path to the recipient private key file
- `--public-key-file`: Path to the sender public key file
- `--private-key-passphrase`: Passphrase for the recipient private key

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
