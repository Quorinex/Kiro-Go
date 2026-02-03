# Kiro API Proxy

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Convert Kiro accounts to OpenAI / Anthropic compatible API service.

[English](README.md) | [中文](README_CN.md)

## Features

- 🔄 **Anthropic Claude API** - Full support for `/v1/messages` endpoint
- 🤖 **OpenAI Chat API** - Compatible with `/v1/chat/completions`
- ⚖️ **Multi-Account Pool** - Round-robin load balancing
- 🔐 **Auto Token Refresh** - Seamless token management
- 📡 **Streaming** - Real-time SSE responses
- 🎛️ **Web Admin Panel** - Easy account management
- 🔑 **Multiple Auth Methods** - IAM SSO, SSO Token, Credentials import
- 📊 **Usage Tracking** - Monitor requests, tokens, and credits

## Quick Start

### Docker Compose (Recommended)

```bash
git clone https://github.com/Quorinex/kiro-api-proxy.git
cd kiro-api-proxy

# Create data directory for persistence
mkdir -p data

docker-compose up -d
```

### Docker Run

```bash
# Create data directory
mkdir -p /path/to/data

docker run -d \
  --name kiro-api-proxy \
  -p 8080:8080 \
  -e ADMIN_PASSWORD=your_secure_password \
  -v /path/to/data:/app/data \
  --restart unless-stopped \
  ghcr.io/quorinex/kiro-api-proxy:latest
```

> 📁 The `/app/data` volume stores `config.json` with accounts and settings. Mount it for data persistence.

### Build from Source

```bash
git clone https://github.com/Quorinex/kiro-api-proxy.git
cd kiro-api-proxy
go build -o kiro-api-proxy .
./kiro-api-proxy
```

## Configuration

Config file is auto-created at `data/config.json` on first run:

```json
{
  "password": "changeme",
  "port": 8080,
  "host": "127.0.0.1",
  "requireApiKey": false,
  "apiKey": "",
  "accounts": []
}
```

> ⚠️ **Change the default password before production use!**

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CONFIG_PATH` | Config file path | `data/config.json` |
| `ADMIN_PASSWORD` | Admin panel password (overrides config) | - |

## Usage

### 1. Access Admin Panel

Open `http://localhost:8080/admin` and login with your password.

### 2. Add Accounts

Three methods available:

| Method | Description |
|--------|-------------|
| **IAM SSO** | For enterprise users with SSO Start URL |
| **SSO Token** | Import `x-amz-sso_authn` from browser |
| **Credentials** | Import JSON from Kiro Account Manager |

#### Credentials Format

```json
{
  "refreshToken": "eyJ...",
  "accessToken": "eyJ...",
  "clientId": "xxx",
  "clientSecret": "xxx"
}
```

### 3. Call API

#### Claude API

```bash
curl http://localhost:8080/v1/messages \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

#### OpenAI API

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer any" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## Model Mapping

| Request Model | Actual Model |
|---------------|--------------|
| `claude-sonnet-4-20250514` | claude-sonnet-4-20250514 |
| `claude-sonnet-4.5` | claude-sonnet-4.5 |
| `claude-haiku-4.5` | claude-haiku-4.5 |
| `claude-opus-4.5` | claude-opus-4.5 |
| `gpt-4o`, `gpt-4` | claude-sonnet-4-20250514 |
| `gpt-3.5-turbo` | claude-sonnet-4-20250514 |

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /v1/models` | List models |
| `POST /v1/messages` | Claude Messages API |
| `POST /v1/messages/count_tokens` | Token counting |
| `POST /v1/chat/completions` | OpenAI Chat API |
| `GET /admin` | Admin panel |

## Project Structure

```
kiro-api-proxy/
├── main.go              # Entry point
├── config/              # Configuration management
├── pool/                # Account pool & load balancing
├── proxy/               # API handlers & Kiro client
│   ├── handler.go       # HTTP routing & admin API
│   ├── kiro.go          # Kiro API client
│   ├── kiro_api.go      # Kiro REST API (usage, models)
│   └── translator.go    # Request/response conversion
├── auth/                # Authentication
│   ├── iam_sso.go       # IAM SSO login
│   ├── oidc.go          # OIDC token refresh
│   └── sso_token.go     # SSO token import
├── web/                 # Admin panel frontend
├── Dockerfile
└── docker-compose.yml
```

## Disclaimer

This project is for educational and research purposes only. Please comply with Kiro's Terms of Service.

## License

[MIT](LICENSE)
