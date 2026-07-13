package config

import (
	"strings"
	"testing"
)

// TestDeriveClientProfileNeverReturnsLinux là tính chất quan trọng nhất của pool: một tài khoản
// không bao giờ được gán dấu vân tay Linux — dấu hiệu nhận diện mạnh nhất cho việc "không phải
// người dùng Kiro IDE thực sự" khi triển khai trên máy chủ Linux. Bất kể accountID là gì (kể cả
// rỗng), kết quả phải luôn là mac/win.
func TestDeriveClientProfileNeverReturnsLinux(t *testing.T) {
	for _, id := range []string{"", "a", "acct-1", "acct-2", "some-long-account-id-xyz"} {
		p := DeriveClientProfile(id)
		if strings.HasPrefix(p.systemVersion, "linux") {
			t.Fatalf("accountID=%q derived Linux systemVersion %q — must never happen", id, p.systemVersion)
		}
	}
}

// TestDeriveClientProfileStable xác nhận hàm thuần xác định: cùng accountID → cùng bộ ba dấu vân
// tay, qua nhiều lần gọi (một tài khoản trông như một desktop cố định trên các yêu cầu/khởi động lại).
func TestDeriveClientProfileStable(t *testing.T) {
	a := DeriveClientProfile("acct-stable")
	b := DeriveClientProfile("acct-stable")
	if a != b {
		t.Fatalf("same accountID must yield identical profile:\n a=%+v\n b=%+v", a, b)
	}
}

// TestDeriveClientProfileDistributionMatchesWeights xác nhận việc phân bổ theo trọng số đạt được:
// tính toán các lựa chọn cho một loạt các accountID và kỳ vọng tỷ lệ thô khớp với trọng số pool
// (mac được ưu tiên, một số ít dùng win). Sử dụng các ID được băm, không phải ngẫu nhiên, để
// không bị sai lệch (flaky).
func TestDeriveClientProfileDistributionMatchesWeights(t *testing.T) {
	mac, win := 0, 0
	n := 5000
	for i := 0; i < n; i++ {
		p := DeriveClientProfile("acct-" + string(rune('a'+i%26)) + string(rune('0'+i%10)) + "x")
		if strings.HasPrefix(p.systemVersion, "darwin") {
			mac++
		} else if strings.HasPrefix(p.systemVersion, "win32") {
			win++
		}
	}
	// Trọng số pool: mac=85, win=15 → mac nên chiếm phần lớn. Chấp nhận sai số ±5%.
	if mac < int(float64(n)*0.80) {
		t.Fatalf("mac share too low: %d/%d (expected ~85%%)", mac, n)
	}
	if win < int(float64(n)*0.10) {
		t.Fatalf("win share too low: %d/%d (expected ~15%%)", win, n)
	}
	if mac+win != n {
		t.Fatalf("all profiles must be mac or win, got other: %d", n-mac-win)
	}
}

// TestDeriveClientProfileUsesVerifiedVersions xác nhận mỗi cấu hình pool mang theo đúng bộ Kiro
// 0.11.107 / node 22.22.0 đã được xác minh (chỉ đa dạng hóa nền tảng; đồng nhất phiên bản là
// được kỳ vọng cho người dùng thực tế tự động cập nhật).
func TestDeriveClientProfileUsesVerifiedVersions(t *testing.T) {
	for _, id := range []string{"a", "b", "c"} {
		p := DeriveClientProfile(id)
		if p.kiroVersion != "0.11.107" {
			t.Fatalf("kiroVersion must be the verified 0.11.107, got %q", p.kiroVersion)
		}
		if p.nodeVersion != "22.22.0" {
			t.Fatalf("nodeVersion must be the verified 22.22.0, got %q", p.nodeVersion)
		}
	}
}

// TestGetKiroClientConfigOperatorOverrideWinsPerField xác nhận các ghi đè từ config
// (KiroVersion/SystemVersion/NodeVersion) có mức ưu tiên cao hơn cho mỗi trường, giữ nguyên đường
// dẫn ghi đè thủ công. Các trường không được đặt sẽ lấy từ cấu hình được dẫn xuất.
func TestGetKiroClientConfigOperatorOverrideWinsPerField(t *testing.T) {
	cfgLock.Lock()
	old := cfg
	cfg = &Config{SystemVersion: "win32#10.0.19045"} // chỉ ghi đè system
	cfgLock.Unlock()
	t.Cleanup(func() {
		cfgLock.Lock()
		cfg = old
		cfgLock.Unlock()
	})

	got := GetKiroClientConfig("any-account")
	if got.SystemVersion != "win32#10.0.19045" {
		t.Fatalf("operator SystemVersion override must win, got %q", got.SystemVersion)
	}
	// Các trường chưa được đặt vẫn dùng các phiên bản đã được xác minh.
	if got.KiroVersion != "0.11.107" || got.NodeVersion != "22.22.0" {
		t.Fatalf("unset fields must fall back to verified versions, got %+v", got)
	}
}
