# Kiro API Proxy

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

将 Kiro 账号转换为 OpenAI / Anthropic 兼容的 API 服务。

[English](README.md) | 中文

## 功能特性

- 🔄 **Anthropic Claude API** - 完整支持 `/v1/messages` 端点
- 🤖 **OpenAI Chat API** - 兼容 `/v1/chat/completions`
- ⚖️ **多账号池** - 轮询负载均衡
- 🔐 **自动刷新 Token** - 无缝 Token 管理
- 📡 **流式响应** - 实时 SSE 输出
- 🎛️ **Web 管理面板** - 便捷的账号管理
- 🔑 **多种认证方式** - IAM SSO、SSO Token、凭证导入
- 📊 **用量追踪** - 监控请求数、Token、Credits

## 快速开始

### Docker Compose（推荐）

```bash
git clone https://github.com/Quorinex/kiro-api-proxy.git
cd kiro-api-proxy

# 创建数据目录用于持久化
mkdir -p data

docker-compose up -d
```

### Docker 运行

```bash
# 创建数据目录
mkdir -p /path/to/data

docker run -d \
  --name kiro-api-proxy \
  -p 8080:8080 \
  -e ADMIN_PASSWORD=your_secure_password \
  -v /path/to/data:/app/data \
  --restart unless-stopped \
  ghcr.io/quorinex/kiro-api-proxy:latest
```

> 📁 `/app/data` 卷存储 `config.json`（包含账号和设置），挂载此目录以实现数据持久化。

### 源码编译

```bash
git clone https://github.com/Quorinex/kiro-api-proxy.git
cd kiro-api-proxy
go build -o kiro-api-proxy .
./kiro-api-proxy
```

## 配置

首次运行会自动创建 `data/config.json`：

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

> ⚠️ **生产环境请务必修改默认密码！**

## 环境变量

| 变量 | 说明 | 默认值 |
|-----|------|-------|
| `CONFIG_PATH` | 配置文件路径 | `data/config.json` |
| `ADMIN_PASSWORD` | 管理面板密码（覆盖配置文件） | - |

## 使用方法

### 1. 访问管理面板

打开 `http://localhost:8080/admin`，输入密码登录。

### 2. 添加账号

支持三种方式：

| 方式 | 说明 |
|------|------|
| **IAM SSO** | 企业用户，输入 SSO Start URL |
| **SSO Token** | 从浏览器导入 `x-amz-sso_authn` |
| **凭证导入** | 从 Kiro Account Manager 导入 JSON |

#### 凭证格式

```json
{
  "refreshToken": "eyJ...",
  "accessToken": "eyJ...",
  "clientId": "xxx",
  "clientSecret": "xxx"
}
```

### 3. 调用 API

#### Claude API

```bash
curl http://localhost:8080/v1/messages \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "你好！"}]
  }'
```

#### OpenAI API

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer any" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "你好！"}]
  }'
```

## 模型映射

| 请求模型 | 实际模型 |
|---------|---------|
| `claude-sonnet-4-20250514` | claude-sonnet-4-20250514 |
| `claude-sonnet-4.5` | claude-sonnet-4.5 |
| `claude-haiku-4.5` | claude-haiku-4.5 |
| `claude-opus-4.5` | claude-opus-4.5 |
| `gpt-4o`, `gpt-4` | claude-sonnet-4-20250514 |
| `gpt-3.5-turbo` | claude-sonnet-4-20250514 |

## API 端点

| 端点 | 说明 |
|-----|------|
| `GET /health` | 健康检查 |
| `GET /v1/models` | 模型列表 |
| `POST /v1/messages` | Claude Messages API |
| `POST /v1/messages/count_tokens` | Token 计数 |
| `POST /v1/chat/completions` | OpenAI Chat API |
| `GET /admin` | 管理面板 |

## 项目结构

```
kiro-api-proxy/
├── main.go              # 入口
├── config/              # 配置管理
├── pool/                # 账号池 & 负载均衡
├── proxy/               # API 处理 & Kiro 客户端
│   ├── handler.go       # HTTP 路由 & 管理 API
│   ├── kiro.go          # Kiro API 客户端
│   ├── kiro_api.go      # Kiro REST API（用量、模型）
│   └── translator.go    # 请求/响应转换
├── auth/                # 认证
│   ├── iam_sso.go       # IAM SSO 登录
│   ├── oidc.go          # OIDC Token 刷新
│   └── sso_token.go     # SSO Token 导入
├── web/                 # 管理面板前端
├── Dockerfile
└── docker-compose.yml
```

## 免责声明

本项目仅供学习研究使用，请遵守 Kiro 服务条款。

## 许可证

[MIT](LICENSE)
