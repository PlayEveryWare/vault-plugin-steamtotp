# Vault Plugin: Steam TOTP

A HashiCorp Vault secrets plugin that stores Steam Guard shared secrets and generates the 5-character Steam Guard codes derived from them. It is modeled on Vault's built-in `totp` secrets engine, but produces Steam's alphabet and returns window metadata so automation can decide whether to use the current code or wait for the next one.

## Features

- **Write-only secrets**: Steam shared secrets are stored seal-wrapped in Vault and are never returned by any endpoint
- **Steam Guard codes**: Generates the 5-character codes Steam expects (`23456789BCDFGHJKMNPQRTVWXY` alphabet, 30 second period)
- **Window metadata**: Each code response includes `expires_in`, `valid_until`, and `next_code`
- **Bitwarden / authenticator key format**: Accepts keys as `steam://<base32>` or plain `<base32>`, matching `@playeveryware/totp`
- **No external dependencies at runtime**: Uses only the Go standard library for code generation

## Requirements

- HashiCorp Vault 1.12 or later
- Go 1.25.0 or later (for building from source)

## Installation

### Building from Source

1. Clone the repository:
```bash
git clone https://github.com/playeveryware/vault-plugin-steamtotp.git
cd vault-plugin-steamtotp
```

2. Build the plugin:
```bash
go build -o vault-plugin-steamtotp ./cmd/vault-plugin-steamtotp
```

3. Register the plugin with Vault (see [Vault Plugin Registration](https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture#plugin-registration))

Release builds for linux/darwin/windows (amd64 and arm64) plus a `.sha256sums` file are published on every `v*` tag.

### Plugin Registration

1. Place the compiled plugin binary in Vault's configured `plugin_directory`
2. Calculate the SHA256 checksum:
```bash
sha256sum vault-plugin-steamtotp
```

3. Register the plugin in Vault:
```bash
vault write sys/plugins/catalog/secret/vault-plugin-steamtotp \
  sha256="<checksum>" \
  command="vault-plugin-steamtotp"
```

4. Enable the plugin:
```bash
vault secrets enable -path=steamtotp vault-plugin-steamtotp
```

On Windows the binary carries an `.exe` suffix, so pass it explicitly: `vault plugin register -sha256=<checksum> -command=vault-plugin-steamtotp.exe secret vault-plugin-steamtotp`.

## Usage

### Storing a Steam Guard Secret

```bash
vault write steamtotp/keys/pewbuild \
  key="steam://JBSWY3DPEHPK3PXP" \
  account_name="pew_build_bot"
```

**Parameters:**
- `key` (required): The Steam Guard shared secret in base32. An optional `steam://` prefix (the format Bitwarden and `@playeveryware/totp` use), whitespace, dashes, lower-case letters, and missing `=` padding are all accepted. The key is normalized before storage.
- `account_name` (optional): A label identifying the Steam account. Returned by reads.

Writing to an existing name overwrites it.

### Reading Key Metadata

```bash
vault read steamtotp/keys/pewbuild
```

**Response:** only `account_name`. The secret is never returned.

### Generating a Code

```bash
vault read steamtotp/code/pewbuild
```

**Response:**

| Field | Description |
|---|---|
| `code` | The Steam Guard code valid right now |
| `expires_in` | Seconds until `code` stops being valid (1–30) |
| `valid_until` | Unix timestamp at which `code` stops being valid |
| `next_code` | The code for the following 30 second window |
| `period` | Code period in seconds (always 30) |

Codes are computed from the Vault server's clock. If `expires_in` is smaller than the time your automation needs to submit the code, either sleep `expires_in` seconds and read again, or submit `next_code` once `valid_until` has passed.

### Listing and Deleting Keys

```bash
vault list steamtotp/keys
vault delete steamtotp/keys/pewbuild
```

## API Endpoints

### Keys

- `LIST /keys` - List key names
- `POST /keys/{name}` - Create or overwrite a key
- `GET /keys/{name}` - Read key metadata (`account_name`)
- `DELETE /keys/{name}` - Delete a key

### Codes

- `GET /code/{name}` - Generate the current and next Steam Guard codes

## Development

### Running Tests

```bash
go test ./...
```

The algorithm tests in `backend/steam_test.go` assert against codes produced by `@playeveryware/totp` at fixed timestamps, so the two implementations stay in lockstep.

### Local End-to-End

```bash
go build -o build/vault-plugin-steamtotp ./cmd/vault-plugin-steamtotp
vault server -dev -dev-root-token-id=root -dev-plugin-dir=$PWD/build &
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root
vault plugin register -sha256="$(sha256sum build/vault-plugin-steamtotp | cut -d' ' -f1)" secret vault-plugin-steamtotp
vault secrets enable -path=steamtotp vault-plugin-steamtotp
vault write steamtotp/keys/test key="steam://JBSWY3DPEHPK3PXP" account_name=test
vault read steamtotp/code/test
```

### Project Structure

```
.
├── backend/
│   ├── backend.go        # Factory and backend definition
│   ├── steam.go          # Key normalization and Steam Guard code algorithm
│   ├── key.go            # Storage model
│   ├── path_keys.go      # keys/ endpoints
│   ├── path_code.go      # code/ endpoint
│   └── *_test.go
├── cmd/
│   └── vault-plugin-steamtotp/
│       └── main.go       # Plugin entry point
└── go.mod
```

## Security Considerations

- Secrets are stored under the seal-wrapped `key/` storage prefix and are never returned by any endpoint; only derived codes leave Vault
- Use Vault policies to grant `read` on `steamtotp/code/*` to automation and restrict `keys/*` to operators
- Codes are derived from the Vault server's clock. Keep Vault's time synchronized (NTP); Steam tolerates only a small amount of drift

## Troubleshooting

### Steam rejects the code

1. Confirm the Vault server's clock is accurate
2. Confirm the key was entered correctly; compare `vault read steamtotp/code/<name>` against the authenticator that owns the secret at the same moment
3. If `expires_in` was small when the code was read, the window may have rolled over before submission; use `next_code` or re-read

### `invalid key` on write

The key must be base32 (`A–Z`, `2–7`). Characters such as `0`, `1`, `8`, `9` are not valid base32. If your secret came from a Steam `maFile`, its `shared_secret` is base64 and must be re-encoded to base32 first.

## License

This project is licensed under the BSD 2-Clause License - see the [LICENSE](LICENSE) file for details.
