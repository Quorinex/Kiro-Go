# Repository Guidelines

## 项目结构与模块组织

Kiro-Go 是 Go 1.21 服务，入口文件为 `main.go`。核心代码按职责拆分：`auth/` 处理 AWS Builder ID、SSO 与 HTTP 客户端认证；`proxy/` 实现 Anthropic/OpenAI 兼容接口、请求转换、缓存与 Kiro API 调用；`pool/` 管理账号池；`config/` 管理运行配置和存储中间层；`logger/` 负责日志。`web/` 存放内置管理后台静态资源、脚本、样式和 `web/locales/` 国际化 JSON。Docker 与发布相关文件位于根目录和 `.github/workflows/docker.yml`。

## 构建、测试与本地开发命令

- `go test ./...`：运行全部 Go 单元测试，提交前必须通过。
- `go build -o kiro-go .`：构建本地可执行文件。
- `./kiro-go`：启动服务；未配置 `DATABASE_URL` 时读取或创建 `data/config.json`。
- `docker-compose up -d`：构建应用并启动 PostgreSQL，在 `8080` 端口运行服务。
- `docker build -t kiro-go .`：验证 Dockerfile 构建是否可用。

## 编码风格与命名规范

Go 代码必须使用 `gofmt`/`go fmt ./...` 格式化，包名保持短小小写，文件按功能命名，例如 `kiro_api.go`、`cache_tracker.go`。导出标识符使用 PascalCase，非导出标识符使用 camelCase。测试文件与被测文件同包放置，命名为 `*_test.go`。Web 静态资源保持原生 HTML/CSS/JavaScript 风格，修改文案时同步维护 `web/locales/en.json` 与 `web/locales/zh.json`。

## 测试指南

项目使用 Go 标准测试框架。新增或修改 `auth/`、`pool/`、`proxy/` 中的业务逻辑时，应补充表驱动测试，覆盖成功路径、错误响应、重试、认证刷新和请求转换边界。测试名称建议使用 `TestFunctionScenario`，例如 `TestEstimateTokensWithImages`。涉及网络的测试应使用本地 fake server 或 mock transport，避免依赖真实外部服务。

## 提交与 Pull Request 规范

提交历史采用 Conventional Commits 风格，优先使用 `fix:`、`feat:`、`docs:`、`test:`、`refactor:` 前缀，例如 `fix: sanitize tool schemas for Kiro`。Pull Request 应说明变更目的、关键实现、测试结果和兼容性影响；涉及管理后台 UI 时附截图或录屏；关联 Issue 时使用 `Closes #123`。不要在 PR 中提交真实账号、令牌、`data/config.json` 或本地缓存文件。

## 安全与配置提示

默认管理员密码仅用于本地验证，生产部署必须通过 `ADMIN_PASSWORD` 或后台设置修改。存储由 `STORE_BACKEND=auto|json|postgres` 控制；`DATABASE_URL` 使用 `postgres://` 或 `postgresql://` 时启用 PostgreSQL，数据库为空会从 `CONFIG_PATH` 自动迁移一次。出站代理配置支持 HTTP/SOCKS5，提交前确认日志中没有敏感认证信息。
