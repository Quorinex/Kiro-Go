# Adapter "Add credential JSON" cho account external_idp

- **Ngày:** 2026-06-27
- **Trạng thái:** Chờ duyệt (design)
- **Branch:** `feat/azure-tenant-sso`
- **Tác giả:** brainstorming session

## 1. Bối cảnh & vấn đề

kiro-go hỗ trợ 3 loại auth method cho account: `idc` (AWS Builder ID / IdC), `social`
(GitHub/Google), và `external_idp` (Enterprise SSO — Microsoft 365 / Entra ID / Azure AD).
Loại `external_idp` đã được thêm gần đây cho luồng **đăng nhập SSO tương tác**
(`auth/kiro_sso.go`) và **chạy bình thường** khi đăng nhập qua trình duyệt — record thật
đang hoạt động trong `data/config.json`.

Tuy nhiên **luồng "Add credential JSON"** (paste JSON credential vào admin panel để thêm
account) **chưa được cập nhật** cho `external_idp`. Khi paste một credential JSON
`external_idp`, request bị từ chối với lỗi `"Token refresh failed"`.

## 2. Root cause

**Backend `proxy/handler.go` `apiImportCredentials` (line ~3008):**
- Request struct (3009–3017) chỉ có `accessToken/refreshToken/clientId/clientSecret/
  authMethod/provider/region` — **thiếu `tokenEndpoint`, `issuerUrl`, `scopes`** (và
  không đọc `id/email/profileArn` cho trường hợp paste full record).
- Khối chuẩn hóa `authMethod` (3042–3053) chỉ nhận `idc`/`social`. `external_idp` rơi
  vào nhánh `default`: có `clientId` nhưng **không có `clientSecret`** → bị ép thành
  `social` → `auth.RefreshToken` dispatch sai sang `refreshSocialToken` → POST refresh
  token lên endpoint AWS social → upstream trả lỗi → `"Token refresh failed"`.
- `tempAccount` (3058–3064) không mang `TokenEndpoint`/`Scopes`, nên ngay cả khi
  `authMethod` đúng thì `refreshExternalIdpToken` cũng nhận `tokenEndpoint=""` và fail.
- Account được tạo (3079–3093) không set `TokenEndpoint/IssuerURL/Scopes/Provider` →
  ngay cả khi import được thì account không có vật liệu refresh → chết sau khi access
  token hết hạn.

**Frontend `web/app.js` `importCredentials` (line ~2281):**
- Map `json.accounts` (2289–2299) không đọc `tokenEndpoint/issuerUrl/scopes` → các
  field này bị drop ngay từ đầu (kể cả khi user paste Kiro export có sẵn chúng).
- Chuẩn hóa `authMethod` (2319–2322): `external_idp` có `clientId` nhưng không có
  `clientSecret` → rơi nhánh cuối → `toLowerCase()!=='idc'` → `"social"`.
- Payload (2326–2333) không gửi `tokenEndpoint/issuerUrl/scopes`.

→ Kết quả: credential `external_idp` không thể thêm qua UI, dù đã hoạt động qua SSO flow.

## 3. Mục tiêu & non-goals

**Mục tiêu:**
- "Add credential JSON" nhận và import được account `external_idp` ở **mọi dạng JSON**
  (xem mục 4), persist đủ vật liệu refresh (`tokenEndpoint/issuerUrl/scopes/clientId`)
  để account sống sót qua các lần refresh tiếp theo.
- Giữ nguyên contract hiện tại: import phải **refresh thành công** trước khi persist
  (phù hợp regression test `TestApiImportCredentialsRejectsWhenRefreshFails`).

**Non-goals (YAGNI):**
- Không thêm trust-on-import (parse JWT `exp` để bỏ qua refresh).
- Không thay đổi `auth.RefreshToken` / `refreshExternalIdpToken`.
- Không mở rộng `parseLineCredentials` (external_idp không vừa định dạng dòng cột).
- Không thêm IdP mới ngoài allow-list hiện tại.

## 4. Các dạng JSON đầu vào phải hỗ trợ

User chọn "tất cả các dạng" → adapter phải linh hoạt:

**A. Object credential đơn lẻ** (chỉ vật liệu refresh — sẽ refresh để lấy accessToken):
```json
{ "authMethod": "external_idp", "refreshToken": "...",
  "clientId": "fa6d79bf-...", "tokenEndpoint": "https://login.microsoftonline.com/<t>/oauth2/v2.0/token",
  "issuerUrl": "https://login.microsoftonline.com/<t>/v2.0", "scopes": "...", "region": "eu-central-1" }
```

**B. Nguyên record account** (như trong `config.json`: có sẵn `id/email/accessToken/
profileArn/expiresAt`):
```json
{ "id": "...", "email": "...", "accessToken": "eyJ...(JWT)", "refreshToken": "...",
  "clientId": "...", "authMethod": "external_idp", "provider": "AzureAD", "region": "eu-central-1",
  "profileArn": "arn:aws:codewhisperer:eu-central-1:...:profile/...",
  "tokenEndpoint": "...", "issuerUrl": "...", "scopes": "..." }
```

**C. Kiro Account Manager export** (`{version, accounts:[{credentials:{...}}]}`) — frontend
đã xử lý `a.credentials` ở dòng 2288; chỉ cần bổ sung các field mới vào cùng map đó.

Dạng mảng `[{...},{...}]` và object đơn đều đi qua nhánh `Array.isArray(json) ? json : [json]`.

## 5. Thiết kế

### 5.1 Backend — `proxy/handler.go` `apiImportCredentials`

**(a) Mở rộng request struct** thêm field external_idp + optional identity:
```go
var req struct {
    AccessToken  string `json:"accessToken"`
    RefreshToken string `json:"refreshToken"`
    ClientID     string `json:"clientId"`
    ClientSecret string `json:"clientSecret"`
    AuthMethod   string `json:"authMethod"`
    Provider     string `json:"provider"`
    Region       string `json:"region"`
    // external_idp refresh material
    TokenEndpoint string `json:"tokenEndpoint"`
    IssuerURL     string `json:"issuerUrl"`
    Scopes        string `json:"scopes"`
    // full-record preservation (optional, only used when provided)
    ID         string `json:"id"`
    Email      string `json:"email"`
    ProfileArn string `json:"profileArn"`
}
```

**(b) Thay khối chuẩn hóa authMethod** bằng helper có thể unit-test, đặt detection
`external_idp` **trước** logic `clientId+clientSecret→idc`:
```go
req.AuthMethod = normalizeImportAuthMethod(req.AuthMethod, req.ClientID, req.ClientSecret, req.TokenEndpoint)
```
```go
// normalizeImportAuthMethod chuẩn hóa auth method cho import. Quan trọng: external_idp
// phải được phát hiện TRƯỚC nhánh clientId+clientSecret→idc, vì external_idp có
// clientId nhưng không có clientSecret.
func normalizeImportAuthMethod(authMethod, clientID, clientSecret, tokenEndpoint string) string {
    am := strings.ToLower(strings.TrimSpace(authMethod))
    switch {
    case am == "external_idp" || am == "azuread" || am == "azure" || am == "entra" ||
        am == "entra-id" || am == "microsoft" || am == "m365" || am == "office365" ||
        am == "external":
        return "external_idp"
    case tokenEndpoint != "":            // inference khi không khai báo rõ
        return "external_idp"
    case am == "social" || am == "google" || am == "github":
        return "social"
    case am == "idc" || am == "builderid" || am == "enterprise":
        return "idc"
    default:                             // chưa khai báo
        if clientID != "" && clientSecret != "" {
            return "idc"
        }
        if clientID != "" {
            return "idc" // có clientId nhưng không clientSecret → vẫn là idc (public client IdC)
        }
        return "social"
    }
}
```
> **Lưu ý naming collision:** alias `"enterprise"` hiện ánh xạ sang `idc` (Kiro Account
> Manager gán provider `"Enterprise"` cho account IdC có `clientId+clientSecret`). Giữ
> nguyên contract đó để không phá import idc hiện có. Phân biệt `external_idp` bằng alias
> tường minh + inference `tokenEndpoint`.

**(c) Validate (mới — bảo mật, xem mục 7):** sau khi chuẩn hóa, nếu `external_idp`:
- Yêu cầu `clientID != ""` và `tokenEndpoint != ""` (đúng yêu cầu của
  `refreshExternalIdpToken`) — thiếu → 400.
- Validate `tokenEndpoint` (và `issuerUrl` nếu có) bằng allow-list
  `auth.ValidateExternalIdpEndpoint(...)` — ngoài allow-list → 400.

**(d) tempAccount** mang đủ vật liệu để `auth.RefreshToken` dispatch đúng:
```go
tempAccount := &config.Account{
    RefreshToken:  req.RefreshToken,
    ClientID:      req.ClientID,
    ClientSecret:  req.ClientSecret,
    AuthMethod:    req.AuthMethod,
    Region:        req.Region,
    TokenEndpoint: req.TokenEndpoint,
    Scopes:        req.Scopes,
}
```

**(e) Account được tạo:** set các field external_idp, default provider, bảo lưu identity
khi được cung cấp:
```go
provider := req.Provider
if provider == "" && req.AuthMethod == "external_idp" {
    provider = "AzureAD"
}
email := email // từ auth.GetUserInfo(accessToken)
if email == "" {
    email = req.Email // fallback từ full record
}
// Reuse id nếu được cung cấp và chưa tồn tại (tránh duplicate khi import lại backup).
id := req.ID
if id == "" || idTaken(id) {
    id = auth.GenerateAccountID()
}
profileArn := newProfileArn
if profileArn == "" {
    profileArn = req.ProfileArn // external_idp refresh không trả profileArn
}
account := config.Account{
    ID:            id,
    Email:         email,
    AccessToken:   accessToken,
    RefreshToken:  req.RefreshToken,
    ClientID:      req.ClientID,
    ClientSecret:  req.ClientSecret,
    AuthMethod:    req.AuthMethod,
    Provider:      provider,
    Region:        req.Region,
    ExpiresAt:     expiresAt,
    Enabled:       true,
    MachineId:     config.GenerateMachineId(),
    ProfileArn:    profileArn,
    TokenEndpoint: req.TokenEndpoint,
    IssuerURL:     req.IssuerURL,
    Scopes:        req.Scopes,
}
```
> `idTaken(id)` duyệt `config.GetAccounts()` xem id đã tồn tại chưa. Helper nhỏ,
> cùng file hoặc trong package `config`.

### 5.2 Frontend — `web/app.js` `importCredentials`

**(a) Map `json.accounts`** (2289–2299) — bổ sung field mới:
```js
items = json.accounts.map(a => {
  const c = a.credentials || {};
  return {
    refreshToken:  c.refreshToken  || a.refreshToken,
    accessToken:   c.accessToken   || a.accessToken,
    clientId:      c.clientId      || a.clientId,
    clientSecret:  c.clientSecret  || a.clientSecret,
    region:        c.region        || a.region,
    authMethod:    c.authMethod    || a.authMethod,
    provider:      c.provider      || a.provider || a.idp,
    tokenEndpoint: c.tokenEndpoint || a.tokenEndpoint,
    issuerUrl:     c.issuerUrl     || a.issuerUrl,
    scopes:        c.scopes        || a.scopes,
    id:            a.id,
    email:         c.email         || a.email,
    profileArn:    c.profileArn    || a.profileArn,
  };
});
```

**(b) Chuẩn hóa authMethod** (2319–2322) — nhận `external_idp` trước:
```js
const EXTERNAL_IDP = ['external_idp','azuread','azure','entra','entra-id','microsoft','m365','office365','external'];
let authMethod = (item.authMethod || '').toLowerCase();
if (EXTERNAL_IDP.includes(authMethod) || item.tokenEndpoint) {
  authMethod = 'external_idp';
} else if (item.clientId && item.clientSecret) {
  authMethod = 'idc';
} else if (!authMethod || authMethod === 'social') {
  authMethod = 'social';
} else {
  authMethod = authMethod === 'idc' ? 'idc' : 'social';
}
```

**(c) Default provider** (2323–2325) — thêm nhánh external_idp:
```js
let provider = item.provider || '';
if (!provider && authMethod === 'external_idp') provider = 'AzureAD';
if (!provider && authMethod === 'social') provider = 'Google';
if (!provider && authMethod === 'idc') provider = 'BuilderId';
```

**(d) Payload** (2326–2333) — thêm field mới + optional identity:
```js
const payload = {
  refreshToken: item.refreshToken,
  accessToken: item.accessToken || '',
  clientId: item.clientId || '',
  clientSecret: item.clientSecret || '',
  authMethod, provider,
  region: item.region || 'us-east-1',
  tokenEndpoint: item.tokenEndpoint || '',
  issuerUrl: item.issuerUrl || '',
  scopes: item.scopes || '',
  ...(item.id ? { id: item.id } : {}),
  ...(item.email ? { email: item.email } : {}),
  ...(item.profileArn ? { profileArn: item.profileArn } : {}),
};
```

> **Parity (thứ cấp):** `web/index-legacy.html` cũng có `importCredentials` (line ~2843)
> với logic tương đương. Cập nhật tương tự để giữ nhất quán, nhưng ưu tiên thấp hơn
> (UI hiện hành dùng `app.js`).

## 6. Luồng dữ liệu

```
paste JSON → app.js: gom field (gồm tokenEndpoint/issuerUrl/scopes + optional id)
           → chuẩn hóa authMethod → POST /auth/credentials
           → handler: decode + validate refreshToken
           → normalizeImportAuthMethod → "external_idp"
           → validate TokenEndpoint/IssuerURL qua allow-list
           → tempAccount(đủ vật liệu) → auth.RefreshToken
              → dispatch theo AuthMethod == "external_idp"
              → refreshExternalIdpToken → POST login.microsoftonline.com (refresh_token grant)
           → persist account (TokenEndpoint/IssuerURL/Scopes/Provider=AzureAD)
           → pool.Reload() → 200
```

## 7. Bảo mật (SSRF / credential exfiltration)

Đường import là **trust boundary mới cho `tokenEndpoint`**: user paste endpoint tùy ý,
`postExternalIdpToken` (auth/oidc.go) POST thẳng `client_id + refresh_token + scope` tới
endpoint đó mà **không validate** (luôn dựa vào caller đã validate — đúng cho luồng SSO,
vì endpoint đến từ OIDC discovery đã qua `validateExternalIdpEndpoint`). Với import, một
JSON credential không tin cậy (vd. gói account chia sẻ) có thể chỉ `tokenEndpoint` vào host
nội bộ / do kẻ tấn công kiểm soát → **rò rỉ refresh token**.

→ **Bắt buộc:** import path phải validate `tokenEndpoint` (+ `issuerUrl` nếu có) bằng cùng
allow-list mà SSO discovery dùng: `auth.validateExternalIdpEndpoint` (kiro_sso.go:512). Hàm
này kiểm tra: parse OK, **bắt buộc https**, **không chấp nhận host dạng IP literal**
(`net.ParseIP`), và host phải khớp một suffix trong `allowedExternalIdpIssuerSuffixes`
(allow-list Microsoft: `login.microsoftonline.com` …) — đủ cho mọi record thật.

**Export + test seam:** hàm chưa export và package `proxy` cần gọi chéo, nên thêm:
- `auth.ValidateExternalIdpEndpoint(u string) error` — exported, gọi qua package var
  `var externalIdpEndpointValidator = validateExternalIdpEndpoint` (mặc định = hàm thật).
  2 call site nội bộ trong `kiro_sso.go` giữ nguyên gọi `validateExternalIdpEndpoint` trực
  tiếp (không đổi → giảm churn); handler import gọi `auth.ValidateExternalIdpEndpoint`.
- `auth.SetExternalIdpValidatorForTest(fn func(string) error) func(string) error` trong
  `auth/testhooks.go` (thay `externalIdpEndpointValidator`, trả về giá trị cũ để restore).
  Khớp pattern `SetOIDCTokenURLForTest` / `SetGlobalAuthClientForTest` sẵn có.

Test happy-path POST lên `http://127.0.0.1:<port>` (httptest) sẽ bị validator thật chặn
(http + IP literal + ngoài allow-list), nên test override validator bằng no-op rồi restore.

## 8. Xử lý lỗi

| Tình huống | Mã | Thông báo |
|---|---|---|
| JSON sai | 400 | `"Invalid JSON"` |
| Thiếu `refreshToken` | 400 | `"refreshToken is required"` |
| `external_idp` thiếu `clientId`/`tokenEndpoint` | 400 | `"external_idp requires clientId and tokenEndpoint"` |
| `tokenEndpoint`/`issuerUrl` ngoài allow-list | 400 | `"external IdP endpoint rejected: ..."` |
| Refresh fail | 400 | `"Token refresh failed: ..."` + **không persist** |
| `config.AddAccount` fail | 500 | lỗi từ config |

Refresh-fail không persist là cố ý — giữ regression test
`TestApiImportCredentialsRejectsWhenRefreshFails`.

## 9. Testing

**Backend (Go, thêm vào `proxy/import_credentials_test.go` hoặc file mới):**
1. **Happy path external_idp:** dựng `httptest` fake token endpoint trả
   `{accessToken, refreshToken, expiresIn}`. Body:
   `{"authMethod":"external_idp","refreshToken":"rt","clientId":"c",
     "tokenEndpoint":"<fakeURL>","scopes":"s","region":"eu-central-1"}`. Assert 200 +
   account persist có `TokenEndpoint/Scopes/Provider="AzureAD"/AuthMethod="external_idp"` +
   ExpiresAt ≈ now+expiresIn.
   - *Test seam (đã xác định):* fakeURL là `http://127.0.0.1:...`, bị validator thật chặn
     (http + IP literal + ngoài allow-list). Dùng `restore := auth.SetExternalIdpValidatorForTest(
     func(string) error { return nil }); defer auth.SetExternalIdpValidatorForTest(restore)`
     để bypass rồi restore — không cần seam mới ngoài chính hàm đó.
2. **Reject khi tokenEndpoint ngoài allow-list:** body với `tokenEndpoint:"http://evil/"`
   → 400, error chứa "endpoint rejected", không persist.
3. **Reject khi refresh fail** cho external_idp (fake endpoint trả 400 `invalid_grant`)
   → 400 "Token refresh failed", không persist.
4. **Unit test `normalizeImportAuthMethod`** bảng sự thật: alias → method,
   inference theo `tokenEndpoint`, fallback `clientId`/`clientId+clientSecret`.

**Frontend:** verify thủ công qua UI (không có test JS tự động hiện có) — paste cả 3 dạng
A/B/C, kiểm toast success và account xuất hiện trong list với đầy đủ field.

## 10. File ảnh hưởng

| File | Thay đổi |
|---|---|
| `proxy/handler.go` | `apiImportCredentials`: struct + normalization + validate + tempAccount + created account; thêm `normalizeImportAuthMethod` (+ `idTaken` helper) |
| `proxy/import_credentials_test.go` (hoặc file mới) | test happy/reject external_idp + unit test normalization |
| `auth/oidc.go` | không đổi (refresh logic đã đúng) |
| `auth/kiro_sso.go` | thêm `var externalIdpEndpointValidator = validateExternalIdpEndpoint` + `func ValidateExternalIdpEndpoint(u string) error` (exported, gọi qua var). 2 call site nội bộ giữ nguyên. |
| `auth/testhooks.go` | thêm `SetExternalIdpValidatorForTest(fn) func(string) error` (thay + restore `externalIdpEndpointValidator`) |
| `web/app.js` | `importCredentials`: map field + normalization + provider default + payload |
| `web/index-legacy.html` | parity update (thứ cấp) |

## 11. Rủi ro & cân nhắc

- **Naming collision `"enterprise"`:** giữ `enterprise → idc` (contract cũ); document rõ.
- **Refresh-on-import cần egress mạng ra Microsoft:** nếu triển khai sau firewall chặn
  `login.microsoftonline.com`, import sẽ fail (giống idc/social — chấp nhận được).
- **id reuse / duplicate:** chỉ reuse `id` khi chưa tồn tại; nếu trùng → sinh id mới (không
  upsert) để giữ thay đổi tối thiểu. Upsert theo email ra khỏi scope (YAGNI).
- **Allow-list hẹp:** chỉ cho phép host Microsoft. Nếu sau này cần IdP khác, mở rộng
  allow-list (riêng biệt, có thể tái sử dụng cho cả SSO discovery).
