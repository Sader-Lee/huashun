package engine_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Sader-Lee/huashun/internal/engine"
	"github.com/Sader-Lee/huashun/internal/model"
	"github.com/Sader-Lee/huashun/internal/rules"
)

// newEngine 使用编译期内嵌的规则构造引擎。
func newEngine(t *testing.T) *engine.Engine {
	t.Helper()
	rs, src, err := rules.Load("")
	if err != nil {
		t.Fatalf("加载内嵌规则失败: %v", err)
	}
	if len(rs) == 0 {
		t.Fatal("内嵌规则为空")
	}
	return engine.New(rs, src)
}

// TestIdentifyProtocolCoverage 覆盖题目要求的五类协议（含 HTTP 的三个产品分支）。
func TestIdentifyProtocolCoverage(t *testing.T) {
	eng := newEngine(t)

	cases := []struct {
		name       string
		banner     string
		wantProto  string
		wantProd   string
		wantVer    string
		wantOS     string
		wantConfid float64
	}{
		{
			name:       "SSH / OpenSSH on Ubuntu",
			banner:     "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
			wantProto:  "SSH",
			wantProd:   "OpenSSH",
			wantVer:    "8.9p1",
			wantOS:     "Ubuntu",
			wantConfid: 0.95,
		},
		{
			name:       "HTTP / nginx",
			banner:     "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\n\r\n<html>Welcome to nginx!</html>",
			wantProto:  "HTTP",
			wantProd:   "nginx",
			wantVer:    "1.24.0",
			wantConfid: 0.9,
		},
		{
			name:       "HTTP / Apache on Ubuntu",
			banner:     "HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\nServer: Apache/2.4.57 (Ubuntu)\r\nContent-Type: text/html",
			wantProto:  "HTTP",
			wantProd:   "Apache",
			wantVer:    "2.4.57",
			wantOS:     "Ubuntu",
			wantConfid: 0.9,
		},
		{
			name:       "HTTP / Jetty",
			banner:     "HTTP/1.1 404 Not Found\r\nServer: Jetty(9.4.51.v20230217)\r\nContent-Length: 0",
			wantProto:  "HTTP",
			wantProd:   "Jetty",
			wantVer:    "9.4.51.v20230217",
			wantConfid: 0.85,
		},
		{
			name:       "MySQL / handshake greeting",
			banner:     "8.0.32-caching_sha2_password\x00" + strings.Repeat("\x00", 8) + "mysql_native_password\x00",
			wantProto:  "MySQL",
			wantProd:   "MySQL",
			wantVer:    "8.0.32",
			wantConfid: 0.9,
		},
		{
			name:       "MariaDB / 5.5.5 prefix",
			banner:     "\x0a5.5.5-10.11.2-MariaDB\x00mysql_native_password",
			wantProto:  "MySQL",
			wantProd:   "MariaDB",
			wantVer:    "10.11.2",
			wantConfid: 0.9,
		},
		{
			name:       "Redis / NOAUTH 弱特征（无版本）",
			banner:     "-NOAUTH Authentication required.",
			wantProto:  "Redis",
			wantProd:   "Redis",
			wantVer:    "",
			wantConfid: 0.7,
		},
		{
			name:       "Redis / INFO 输出带版本",
			banner:     "# Server\r\nredis_version:7.0.11\r\nredis_mode:standalone\r\n",
			wantProto:  "Redis",
			wantProd:   "Redis",
			wantVer:    "7.0.11",
			wantConfid: 0.92,
		},
		{
			name:       "FTP / ProFTPD",
			banner:     "220 ProFTPD 1.3.7 Server (Debian)",
			wantProto:  "FTP",
			wantProd:   "ProFTPD",
			wantVer:    "1.3.7",
			wantOS:     "Debian",
			wantConfid: 0.9,
		},
		{
			name:       "FTP / vsftpd",
			banner:     "220 (vsFTPd 3.0.3)",
			wantProto:  "FTP",
			wantProd:   "vsftpd",
			wantVer:    "3.0.3",
			wantConfid: 0.9,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := eng.Identify("1.2.3.4", 0, tc.banner)
			if got.Protocol != tc.wantProto {
				t.Errorf("protocol = %q, 期望 %q", got.Protocol, tc.wantProto)
			}
			if got.Product != tc.wantProd {
				t.Errorf("product = %q, 期望 %q", got.Product, tc.wantProd)
			}
			if got.Version != tc.wantVer {
				t.Errorf("version = %q, 期望 %q", got.Version, tc.wantVer)
			}
			if got.OSHint != tc.wantOS {
				t.Errorf("os_hint = %q, 期望 %q", got.OSHint, tc.wantOS)
			}
			if got.Confidence != tc.wantConfid {
				t.Errorf("confidence = %v, 期望 %v", got.Confidence, tc.wantConfid)
			}
		})
	}
}

// TestIdentifyUnknownNeverFails 验证"认不出来不算错、服务不能崩"。
func TestIdentifyUnknownNeverFails(t *testing.T) {
	eng := newEngine(t)

	banners := []string{
		"",
		"   ",
		"\x00\x01\x02\x03",
		"some totally unrelated text that matches nothing",
		strings.Repeat("A", 200<<10), // 超长输入（> 64KB 截断上限）
		"%%%\\d+(?P<broken>",
		"\r\n\r\n",
	}
	for _, b := range banners {
		got := eng.Identify("10.0.0.1", 12345, b)
		if got.Protocol != model.UnknownProtocol {
			t.Errorf("banner=%q 期望 unknown，实际 %q", truncate(b), got.Protocol)
		}
		if got.Confidence != 0 {
			t.Errorf("banner=%q unknown 的 confidence 应为 0，实际 %v", truncate(b), got.Confidence)
		}
		if got.IP != "10.0.0.1" || got.Port != 12345 {
			t.Errorf("banner=%q 未回填 ip/port: %+v", truncate(b), got)
		}
	}
}

// TestIdentifyBatchKeepsOrderAndIsolatesFailures 验证批量识别保序且单条异常不扩散。
func TestIdentifyBatchKeepsOrderAndIsolatesFailures(t *testing.T) {
	eng := newEngine(t)

	recs := []model.Record{
		{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"},
		{IP: "1.2.3.5", Port: 80, Banner: "Server: nginx/1.24.0"},
		{IP: "1.2.3.6", Port: 21, Banner: "220 ProFTPD 1.3.7 Server"},
		{IP: "1.2.3.7", Port: 9999, Banner: "\xde\xad\xbe\xef"},
	}

	got := eng.IdentifyBatch(context.Background(), recs)
	if len(got) != len(recs) {
		t.Fatalf("结果条数 = %d, 期望 %d", len(got), len(recs))
	}
	for i := range recs {
		if got[i].IP != recs[i].IP || got[i].Port != recs[i].Port {
			t.Errorf("第 %d 条顺序错乱: %+v", i, got[i])
		}
	}
	if got[0].Protocol != "SSH" || got[1].Protocol != "HTTP" || got[2].Protocol != "FTP" {
		t.Errorf("前三条识别异常: %+v", got[:3])
	}
	if got[3].Protocol != model.UnknownProtocol {
		t.Errorf("第 4 条应为 unknown，实际 %q", got[3].Protocol)
	}
}

// TestIdentifyBatchEmpty 验证空批次返回空切片而不是 nil。
func TestIdentifyBatchEmpty(t *testing.T) {
	eng := newEngine(t)
	if got := eng.IdentifyBatch(context.Background(), nil); len(got) != 0 {
		t.Fatalf("空批次应返回空结果，实际 %d 条", len(got))
	}
}

// TestIdentifyBatchCancelledContext 验证上下文取消时不会挂起。
func TestIdentifyBatchCancelledContext(t *testing.T) {
	eng := newEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	recs := []model.Record{
		{IP: "1.1.1.1", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1"},
		{IP: "1.1.1.2", Port: 80, Banner: "Server: nginx/1.24.0"},
	}
	got := eng.IdentifyBatch(ctx, recs)
	if len(got) != len(recs) {
		t.Fatalf("结果条数 = %d, 期望 %d", len(got), len(recs))
	}
}

func truncate(s string) string {
	if len(s) > 48 {
		return s[:48] + "..."
	}
	return s
}
