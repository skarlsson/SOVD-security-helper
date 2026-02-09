---
name: explain-project
description: Explain the SOVD Security Helper project architecture, API, and purpose. Use when someone asks what this project does or needs onboarding context.
allowed-tools: Read, Grep, Glob
context: fork
agent: Explore
---

Explain the SOVD Security Helper project to the user. Cover the following areas based on $ARGUMENTS (or all areas if no specific topic is given):

## Project Overview

This is a Rust-based authenticated key derivation service for the SOVD (Service-Oriented Vehicle Diagnostics) Explorer. It holds ECU (Electronic Control Unit) secrets server-side and computes security keys on behalf of authenticated users, protecting sensitive OEM cryptographic material.

## Architecture

- Single-file Rust application (`src/main.rs`, ~300 lines)
- Async HTTP server using **axum** + **tokio**
- Configuration via TOML (`config/secrets.toml`)
- CLI argument parsing with **clap** (supports env vars)

## REST API

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /info` | None | Service metadata and supported algorithms |
| `POST /calculate` | Bearer token | Derive security key from seed + ECU secret |

### POST /calculate flow
```
Request -> Bearer Token Check -> ECU Type Lookup -> Algorithm Validation
        -> Seed Hex Decode -> Secret Hex Decode -> XOR Computation -> Return Key
```

## Key Derivation

Currently implements XOR: `key[i] = seed[i] XOR secret[i % secret_len]`

## Configuration

`config/secrets.toml` maps ECU types (engine, transmission, body) to algorithms and hex-encoded shared secrets.

## Running

- `./start.sh` to build and launch (default port 9100)
- `./stop.sh` for graceful shutdown
- Token set via `--token` flag or `SOVD_HELPER_TOKEN` env var

## Important Notes

- This is a **reference implementation** for OEMs, not production-ready
- Bearer token auth should be replaced with OAuth/Entra ID in production
- Secrets are loaded from an unencrypted TOML file
