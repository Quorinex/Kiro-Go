# Kiro-Go

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
- 🔑 **Multiple Auth Methods** - AWS Builder ID, IAM Identity Center (Enterprise SSO), SSO Token, Local Cache, Credentials
- 📊 **Usage Tracking** - Monitor requests, tokens, and credits
- 📦 **Account Export/Import** - Compatible with Kiro Account Manager format
- 🔄 **Dynamic Model List** - Auto-synced from Kiro API with caching
- 🔔 **Version Update Check** - Automatic new version notification
- 🌐 **i18n** - Chinese / English admin panel

## Quick Start

### Docker Compose (Recommended)

```bash
git clone https://github.com/Quorinex/Kiro-Go.git
cd Kiro-Go

# Create data directory for persistence
mkdir -p data

docker-compose up -d
```

### Docker Run

```bash
# Create data directory
mkdir -p /path/to/data

docker run -d \
  --name kiro-go \
  -p 8080:8080 \
  -e ADMIN_PASSWORD=your_secure_password \
  -v /path/to/data:/app/data \
  --restart unless-stopped \
  ghcr.io/quorinex/kiro-go:latest
```

> 📁 The `/app/data` volume stores `config.json` with accounts and settings. Mount it for data persistence.

### Build from Source

```bash
git clone https://github.com/Quorinex/Kiro-Go.git
cd Kiro-Go
go build -o kiro-go .
./kiro-go
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

Multiple methods available:

| Method | Description |
|--------|-------------|
| **AWS Builder ID** | Login with AWS Builder ID (personal accounts) |
| **IAM Identity Center (Enterprise SSO)** | Login with IAM Identity Center (enterprise accounts) |
| **SSO Token** | Import `x-amz-sso_authn` token from browser |
| **Kiro Local Cache** | Import from local Kiro IDE cache files |
| **Credentials JSON** | Import JSON from Kiro Account Manager |

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
| `claude-opus-4.6` | claude-opus-4.6 |
| `gpt-4o`, `gpt-4` | claude-sonnet-4-20250514 |
| `gpt-3.5-turbo` | claude-sonnet-4-20250514 |

## Thinking Mode

Enable extended thinking by adding a suffix to the model name (default: `-thinking`).

### Usage

```bash
# OpenAI API with thinking
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4.5-thinking",
    "messages": [{"role": "user", "content": "Solve this step by step: 15 * 23"}],
    "stream": true
  }'

# Claude API with thinking
curl http://localhost:8080/v1/messages \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-sonnet-4.5-thinking",
    "max_tokens": 4096,
    "messages": [{"role": "user", "content": "Analyze this problem"}]
  }'
```

### Configuration

Configure thinking mode in the Admin Panel under **Settings > Thinking Mode Settings**:

| Setting | Description | Options |
|---------|-------------|---------|
| **Trigger Suffix** | Model name suffix to enable thinking | Default: `-thinking` (customizable, e.g., `-think`, `-reason`) |
| **OpenAI Output Format** | How thinking content is returned in OpenAI API | `reasoning_content` (DeepSeek compatible), `<thinking>` tag, `<think>` tag |
| **Claude Output Format** | How thinking content is returned in Claude API | `<thinking>` tag (default), `<think>` tag, plain text |

### Output Formats

**OpenAI API (`/v1/chat/completions`)**:
- `reasoning_content` - Thinking in separate `reasoning_content` field (DeepSeek compatible)
- `thinking` - Thinking wrapped in `<thinking>...</thinking>` tags in content
- `think` - Thinking wrapped in `<think>...</think>` tags in content

**Claude API (`/v1/messages`)**:
- `thinking` - Thinking wrapped in `<thinking>...</thinking>` tags (default)
- `think` - Thinking wrapped in `<think>...</think>` tags
- `reasoning_content` - Plain text output

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /v1/models` | List models |
| `GET /v1/stats` | Statistics |
| `POST /v1/messages` | Claude Messages API |
| `POST /v1/messages/count_tokens` | Token counting |
| `POST /v1/chat/completions` | OpenAI Chat API |
| `GET /admin` | Admin panel |

## Project Structure

```
Kiro-Go/
├── main.go              # Entry point
├── version.json         # Version info for update check
├── config/              # Configuration management
├── pool/                # Account pool & load balancing
├── proxy/               # API handlers & Kiro client
│   ├── handler.go       # HTTP routing & admin API
│   ├── kiro.go          # Kiro API client
│   ├── kiro_api.go      # Kiro REST API (usage, models)
│   └── translator.go    # Request/response conversion
├── auth/                # Authentication
│   ├── builderid.go     # AWS Builder ID login
│   ├── iam_sso.go       # IAM SSO login
│   ├── oidc.go          # OIDC token refresh
│   └── sso_token.go     # SSO token import
├── web/                 # Admin panel frontend
├── Dockerfile
└── docker-compose.yml
```

## Disclaimer

This project is provided for **educational and research purposes only**.

- This software is not affiliated with, endorsed by, or associated with Amazon, AWS, or Kiro in any way
- Users are solely responsible for ensuring their use complies with all applicable terms of service and laws
- The authors assume no liability for any misuse or violations arising from the use of this software
- Use at your own risk

By using this software, you acknowledge that you have read and understood this disclaimer.

## License

[MIT](LICENSE)
