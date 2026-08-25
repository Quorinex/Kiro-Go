# Kiro-Go

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Chuyển tài khoản Kiro thành dịch vụ API tương thích OpenAI / Anthropic.

[English](README.md) | [中文](README_CN.md) | [Tiếng Việt](README_VI.md)

Nếu dự án này hữu ích với bạn, một Star sẽ rất có ý nghĩa.

## Tính năng

- Anthropic `/v1/messages`, OpenAI `/v1/chat/completions` & OpenAI `/v1/responses`
- Pool nhiều tài khoản với cân bằng tải round-robin
- Tự làm mới token, SSE streaming, bảng quản trị Web
- Nhiều cách xác thực: AWS Builder ID, IAM Identity Center (Enterprise SSO), Microsoft Enterprise SSO, SSO Token, cache cục bộ, credentials JSON, Kiro API Key
- Theo dõi mức dùng, nhập/xuất tài khoản, đa ngôn ngữ (CN / EN / VI)
- Ánh xạ mô hình phía ứng dụng khách có thể cấu hình và được công khai qua `/v1/models`
- Hỗ trợ cấu hình proxy ra ngoài (SOCKS5 / HTTP)

## Bắt đầu nhanh

### Docker Compose (Khuyến nghị)

```bash
git clone https://github.com/Quorinex/Kiro-Go.git
cd Kiro-Go
mkdir -p data
docker-compose up -d
```

### Docker Run

```bash
docker run -d \
  --name kiro-go \
  -p 8080:8080 \
  -e ADMIN_PASSWORD=your_secure_password \
  -v /path/to/data:/app/data \
  --restart unless-stopped \
  ghcr.io/quorinex/kiro-go:latest
```

### Build từ mã nguồn

```bash
git clone https://github.com/Quorinex/Kiro-Go.git
cd Kiro-Go
go build -o kiro-go .
./kiro-go
```

### Triển khai trên Zeabur

Repo đã có `Dockerfile`, nên có thể build và chạy trên Zeabur ngay.

**Cách 1: Dashboard (một cú nhấp)**

1. Fork repo này về tài khoản GitHub của bạn.
2. Trên Zeabur, tạo service mới, chọn **Deploy from GitHub**, rồi chọn fork của bạn.
3. Zeabur tự nhận `Dockerfile` và build image.
4. Trong tab **Networking**, mở cổng `8080` và gắn domain.
5. Trong tab **Variables**, đặt ít nhất `ADMIN_PASSWORD` (mật khẩu bảng quản trị).
6. Mount Volume tại `/app/data` nếu muốn tài khoản / cấu hình tồn tại sau khi redeploy.

**Cách 2: CLI**

```bash
npm i -g zeabur
zeabur auth login
zeabur deploy
```

> Chạy lệnh từ thư mục gốc dự án. CLI sẽ ghi `.zeabur/context.json` để nhớ project / service đích — file này chứa ID cá nhân, đừng commit.

Khi service đã chạy, mở `https://<your-domain>/admin` để đăng nhập.

Cấu hình được tạo tự động tại `data/config.json`. Mount `/app/data` để lưu bền. Mật khẩu quản trị mặc định là `changeme` — hãy ghi đè bằng biến môi trường `ADMIN_PASSWORD` hoặc đổi trong bảng quản trị trước khi đưa vào production.

## Cách dùng

Mở `http://localhost:8080/admin`, đăng nhập, thêm tài khoản, rồi gọi API:

```bash
# Claude
curl http://localhost:8080/v1/messages \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{"model":"claude-sonnet-4.5","max_tokens":1024,"messages":[{"role":"user","content":"Xin chào!"}]}'

# OpenAI
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer any" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Xin chào!"}]}'
```

### Thêm tài khoản Kiro API Key

Trong bảng quản trị, chọn **API Key** khi thêm tài khoản và dán `ksk_...` (hoặc `ksk_...|region`).

Bạn cũng có thể import qua API credentials:

```bash
curl -X POST http://localhost:8080/admin/api/auth/credentials \
  -H "Content-Type: application/json" \
  -H "Cookie: <admin-session>" \
  -d '{"kiroApiKey":"ksk_your_key|us-east-1","authMethod":"api_key","nickname":"cli-key"}'
```

Tài khoản API Key gọi Kiro CLI runtime (`https://runtime.{region}.kiro.dev/`) với `tokentype: API_KEY`. Chúng bỏ qua OAuth refresh và không dùng `profileArn`.

### Ánh xạ mô hình

Cấu hình bí danh phía ứng dụng khách tại **Cài đặt - Ánh xạ mô hình**, ví dụ `kiro-opus-5` → `claude-opus-5`. Ánh xạ áp dụng cho các API Anthropic, OpenAI Chat Completions và OpenAI Responses; mỗi bí danh và biến thể có hậu tố thinking đã cấu hình đều xuất hiện trong `/v1/models`. ID nguồn được so khớp không phân biệt chữ hoa chữ thường và phân giải trực tiếp đến một ID mô hình upstream; chuỗi ánh xạ không được phép.

## Chế độ Thinking

Thêm hậu tố (mặc định `-thinking`) vào tên mô hình, ví dụ `claude-sonnet-4.5-thinking`. Các yêu cầu tương thích Claude có cấu hình `thinking` ở top-level như `{"type":"enabled","budget_tokens":2048}` hoặc `{"type":"adaptive"}` cũng tự bật chế độ thinking. Cấu hình định dạng đầu ra trong bảng quản trị tại Cài đặt - Chế độ Thinking.

## Proxy ra ngoài

Với người dùng ở khu vực mạng bị hạn chế, cấu hình proxy ra ngoài trong bảng quản trị tại **Cài đặt - Cài đặt proxy ra ngoài**. Hỗ trợ SOCKS5 và HTTP.

Cài đặt có hiệu lực ngay, không cần khởi động lại.

## Biến môi trường

| Biến | Mô tả | Mặc định |
|------|-------|----------|
| `CONFIG_PATH` | Đường dẫn file cấu hình | `data/config.json` |
| `ADMIN_PASSWORD` | Mật khẩu bảng quản trị (ghi đè config) | - |

## Đóng góp

Hoan nghênh thảo luận thân thiện. Nếu gặp vấn đề, hãy thử nhờ Claude Code, Codex hoặc công cụ tương tự trước — hầu hết vấn đề có thể tự giải quyết. PR càng tốt.

## Liên kết hữu ích

- [LINUX DO](https://linux.do)

## Tuyên bố miễn trừ

Chỉ dùng cho mục đích học tập và nghiên cứu. Không liên kết với Amazon, AWS hay Kiro. Người dùng tự chịu trách nhiệm tuân thủ điều khoản dịch vụ và luật áp dụng. Sử dụng với rủi ro của riêng bạn.

## Giấy phép

[MIT](LICENSE)
