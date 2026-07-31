# C2PA command line tool for C2PA cloud signing

This repository provides a customized build of the open source
[`c2patool`](https://github.com/contentauth/c2patool) project. It keeps the
core C2PA manifest creation, inspection, and embedding capabilities from the
upstream project, and adds a remote signer integration for a C2PA cloud signing
service used in Volcano Engine and BytePlus deployments.

The primary purpose of this codebase is to apply C2PA provenance metadata to
digital assets while delegating the cryptographic signing operation to a cloud
signature service. This allows media provenance workflows to use managed keys,
centralized signing policies, auditability, and cloud-side certificate
management instead of storing private signing keys locally.

## What This Tool Does

This tool can be used to:

- Create and embed C2PA manifests into supported assets.
- Sign C2PA assertions through a compatible C2PA cloud signing service.
- Inspect existing C2PA manifests and provenance data.
- Validate whether a file contains a valid C2PA manifest.
- Export manifest data for debugging, integration testing, or downstream
  provenance processing.

Typical scenarios include trusted media publishing, asset provenance marking,
AI-generated content labeling, internal media compliance workflows, and content
authenticity pipelines that require cloud-managed signing.

## Relationship to Open Source c2patool

This project is based on the open source `c2patool` implementation. The upstream
project provides the standard command-line workflow for working with C2PA
manifests. This repository extends that behavior with a cloud signer compatible
with Volcano Engine and BytePlus C2PA signing deployments.

The main differences from the upstream project are:

- Cloud signature support for C2PA manifest signing.
- Remote signer configuration for compatible cloud signing deployments.
- Signing flows that avoid local private-key storage.
- Parameter and configuration handling for cloud signing credentials, region,
  service endpoint, C2PA certificate instance ID, and signing algorithm.

Unless explicitly documented otherwise, the command-line behavior follows the
same model as upstream `c2patool`.

## Build

Install Rust and build the binary from the repository root:

```bash
cargo build --release
```

The release binary is generated under:

```bash
target/release/c2patool
```

For local development, use:

```bash
cargo build
```

## Basic Usage

Embed a manifest and sign it with the cloud signer:

```bash
c2patool input.jpg \
  --manifest manifest.json \
  --output output.jpg \
  --signer-url https://openapi.example.com \
  --access-key "$SIGNER_ACCESS_KEY" \
  --instance-id "your-c2pa-instance-id"
```

Inspect C2PA data in an asset:

```bash
c2patool output.jpg --info
```

Print detailed manifest data:

```bash
c2patool output.jpg --detailed
```

The tool validates manifests while reading or inspecting assets and reports the
validation status in the output. To see every CLI option supported by the
current binary, run:

```bash
c2patool --help
```

## Manifest Input

The manifest file describes the C2PA claim, assertions, ingredients, and
metadata that should be embedded into the target asset. A typical manifest
contains:

- Claim generator information.
- Assertions describing the asset, creation process, or editing actions.
- Ingredient references for source assets.
- Optional local signing configuration for development and testing.

Example:

```json
{
  "claim_generator": "c2patool-cloud-signing",
  "title": "example.jpg",
  "assertions": [
    {
      "label": "c2pa.actions",
      "data": {
        "actions": [
          {
            "action": "c2pa.created"
          }
        ]
      }
    }
  ]
}
```

## Remote Signer

The cloud signer delegates the C2PA signing operation to a compatible C2PA
OpenAPI signing service. Instead of loading a local private key, the tool
fetches the certificate chain with `GetC2PAInstance`, signs the claim digest
with `C2PASign`, and embeds the returned signature into the C2PA manifest.

Cloud signing is enabled only when `--signer-url` is provided. Without
`--signer-url`, the tool falls back to the subprocess signer, SDK settings
signer, manifest-local signer configuration, environment-provided local key
material, or the development-only default key path.

This design is useful when:

- Private keys must remain in managed cloud infrastructure.
- Signing access must be controlled by IAM or cloud-side policies.
- Signing operations require audit logs.
- Multiple applications need to share a centralized signing service.
- Certificate lifecycle management is handled by the cloud signing service.

## Signer Configuration

The cloud signer is configured through CLI parameters. Keep
secrets out of source control and prefer environment variables or a secure
secret manager in production.

Cloud signer parameters:

| Parameter | Description |
| --- | --- |
| `--signer-url <url>` | Cloud signing OpenAPI gateway host. Providing this option enables cloud signing. |
| `--access-key <ak>` | Access key ID. Required when `--signer-url` is used. Can also be provided with `SIGNER_ACCESS_KEY`. |
| `--secret-key <sk>` | Secret access key. Required when `--signer-url` is used. Can also be provided with `SIGNER_SECRET_KEY`. |
| `--region <region>` | Service region. Defaults to `cn-north-1`. |
| `--service <service>` | OpenAPI service name. Defaults to `c2pa_tob`. |
| `--api-version <version>` | OpenAPI version. Defaults to `1.0`. |
| `--instance-id <id>` | C2PA certificate instance ID used by `GetC2PAInstance` and `C2PASign`. Required when `--signer-url` is used. Can also be provided with `SIGNER_INSTANCE_ID`. |
| `--signing-algorithm <alg>` | Cloud signing algorithm. Defaults to `RSASSA_PSS_SHA_256`. |
| `--use-time-authority` | Enables timestamp authority use during cloud signing. The TSA URL is read from `ta_url` in the manifest signing config or from `C2PA_TA_URL`. |

Supported cloud signing algorithm values:

- `RSASSA_PSS_SHA_256`
- `RSASSA_PSS_SHA_384`
- `RSASSA_PSS_SHA_512`
- `ECDSA_SHA_256`
- `ECDSA_SHA_384`
- `ECDSA_SHA_512`
- `ED25519_SHA_512`

Example:

```bash
export SIGNER_SECRET_KEY="..."
export SIGNER_ACCESS_KEY="..."

c2patool input.jpg \
  --manifest manifest.json \
  --output output.jpg \
  --signer-url "$SIGNER_URL" \
  --access-key "$SIGNER_ACCESS_KEY" \
  --instance-id "your-c2pa-instance-id" \
  --region cn-north-1 \
  --service c2pa_tob \
  --api-version 1.0 \
  --signing-algorithm RSASSA_PSS_SHA_256
```

For local development and testing, signer settings can also be provided through
the manifest JSON or the C2PA SDK settings file.

Manifest-local signing configuration:

```json
{
  "alg": "es256",
  "private_key": "path/to/private.key",
  "sign_cert": "path/to/cert.pem",
  "ta_url": "https://timestamp.example.com",
  "assertions": []
}
```

SDK settings local signer configuration:

```toml
[signer.local]
alg = "ps256"
sign_cert = """-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
"""
private_key = """-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
"""
tsa_url = "https://timestamp.example.com"
```

The upstream C2PA SDK also supports a generic HTTP remote signer through
`[signer.remote]`. This is separate from the C2PA OpenAPI cloud signer above:

```toml
[signer.remote]
url = "https://signing.example.com/sign"
alg = "es256"
sign_cert = """-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
"""
tsa_url = "https://timestamp.example.com"
```

The generic SDK remote signer sends the bytes to sign as the HTTP request body
and expects raw signature bytes in the response. It does not understand Volcano
cloud signing access keys, regions, or instance IDs.

## Command-Line Parameters

The following parameters are commonly used when applying C2PA metadata:

| Parameter | Description |
| --- | --- |
| `<asset>` | Input asset to read, inspect, validate, or mark with C2PA metadata. |
| `--manifest <path>` | Path to the C2PA manifest JSON file to embed. |
| `--output <path>` | Path for the signed output asset. |
| `--config <json>` | Upstream `c2patool` uses this option for an inline manifest JSON string, not a signer configuration file path. Do not use it for `signer-config.toml` unless this fork explicitly changed the CLI behavior. |
| `--settings <path>` | Path to the C2PA SDK settings file in JSON or TOML. Defaults to `$XDG_CONFIG_HOME/c2pa/c2pa.toml` and can be overridden by `C2PATOOL_SETTINGS`. |
| `--signer-url <url>` | Enables the cloud signer and sets the OpenAPI gateway host. |
| `--access-key <ak>` | Access key ID for cloud signing. Can be supplied by `SIGNER_ACCESS_KEY`. |
| `--secret-key <sk>` | Secret access key for cloud signing. Can be supplied by `SIGNER_SECRET_KEY`. |
| `--region <region>` | Cloud signing service region. |
| `--service <service>` | OpenAPI service name. |
| `--api-version <version>` | OpenAPI version. |
| `--instance-id <id>` | C2PA certificate instance ID for cloud signing. Can be supplied by `SIGNER_INSTANCE_ID`. |
| `--signing-algorithm <alg>` | Cloud signing algorithm. |
| `--use-time-authority` | Enables timestamp authority use during cloud signing. |
| `--signer-path <command>` | Uses a subprocess signer for the C2PA claim signature. |
| `--identity-signer-path <command>` | Uses a subprocess signer for the CAWG identity assertion signature. |
| `--ingredient` | Creates an ingredient report for the input asset. This is a flag, not a path argument. |
| `--parent <path>` | Sets a parent asset when creating an asset derived from an existing file. |
| `--force` | Allows overwriting an existing output file when supported by the command. |
| `--info` | Prints a summary of C2PA data embedded in the asset. |
| `--detailed` | Prints detailed manifest and assertion data. |
| `--crjson` | Prints manifest data in crJSON format. |
| `--external-manifest <path>` | Validates or reads an asset against a separate binary `.c2pa` manifest. |
| `--sidecar` | Generates a sidecar `.c2pa` manifest. |
| `--tree` | Prints a tree diagram of the manifest store. |
| `--certs` | Extracts the certificate chain from the active manifest. |
| `--help` | Prints the complete CLI help for the current build. |

Check `c2patool --help` for the exact flag names enabled in the binary you are
using.

## Environment Variables

The following environment variables are read directly by this build:

```bash
export SIGNER_ACCESS_KEY="..."     # Used as --access-key
export SIGNER_SECRET_KEY="..."     # Used as --secret-key
export SIGNER_URL="..."            # Used as --signer-url
export SIGNER_INSTANCE_ID="..."    # Used as --instance-id
export C2PATOOL_SETTINGS="..."     # Path to the SDK settings file
export C2PA_PRIVATE_KEY="..."      # Local signer private key material
export C2PA_SIGN_CERT="..."        # Local signer certificate material
export C2PA_TA_URL="..."           # Timestamp authority URL
```

Use the credential names expected by your deployment and avoid committing real
credential values to the repository.

## Example Workflow

1. Prepare a C2PA manifest JSON file.
2. Prepare cloud signer credentials and a C2PA certificate instance ID.
3. Run `c2patool` with the input asset, manifest, output path, and cloud signer
   parameters.
4. Inspect the generated asset to confirm that the C2PA manifest was embedded.
5. Validate the asset before publishing or handing it to downstream systems.

Example:

```bash
c2patool ./assets/input.jpg \
  --manifest ./manifests/example.json \
  --output ./dist/input.c2pa.jpg \
  --signer-url "$SIGNER_URL" \
  --access-key "$SIGNER_ACCESS_KEY" \
  --instance-id "your-c2pa-instance-id"

c2patool ./dist/input.c2pa.jpg --info
c2patool ./dist/input.c2pa.jpg --detailed
```

## Security Notes

- Do not store access keys, secret keys, or private credentials in Git.
- Restrict cloud signing permissions to the minimum key and certificate scope
  needed by the application.
- Enable cloud-side audit logging for signing operations.
- Validate generated C2PA assets before publishing them.
- Keep the upstream `c2patool` dependency and this repository's remote signer
  implementation updated with relevant security fixes.

## Development Notes

Run formatting and tests before submitting changes:

```bash
cargo fmt
cargo test
```

When changing remote signer behavior, include tests or integration validation
for:

- Request construction.
- Credential handling.
- Signature algorithm selection.
- Certificate chain handling.
- Error handling for OpenAPI request and signing failures.
- Error messages returned to CLI users.

## License and Attribution

This repository is derived from the open source `c2patool` project and keeps
the same dual-license model as the upstream C2PA Rust SDK project:

- Apache License, Version 2.0
- MIT License

You may use this repository under either license, at your option. See
[`LICENSE-APACHE`](LICENSE-APACHE), [`LICENSE-MIT`](LICENSE-MIT), and
[`NOTICE`](NOTICE) for the full license and attribution text.

Portions of the upstream project are copyright Adobe and other upstream
contributors. Keep the upstream copyright, license, and attribution notices
when redistributing or modifying this project.

Additional changes in this repository add support for compatible C2PA cloud
signing services used by Volcano Engine and BytePlus deployments.

Copyright (c) 2026 Beijing Volcano Engine Technology Co., Ltd.
Copyright (c) 2026 北京火山引擎科技有限公司
