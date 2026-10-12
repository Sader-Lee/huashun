package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sader-Lee/huashun/internal/api"
	"github.com/Sader-Lee/huashun/internal/engine"
	"github.com/Sader-Lee/huashun/internal/model"
	"github.com/Sader-Lee/huashun/internal/rules"
)

func newRouter(t *testing.T, maxBody int64) http.Handler {
	t.Helper()
	rs, src, err := rules.Load("")
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	return api.NewRouter(api.Options{
		Engine:       engine.New(rs, src),
		MaxBodyBytes: maxBody,
	})
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealth(t *testing.T) {
	rec := do(t, newRouter(t, 0), http.MethodGet, "/health", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, 期望 200", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if got["status"] != "ok" {
		t.Errorf("status 字段 = %v", got["status"])
	}
	if n, _ := got["rules"].(float64); n <= 0 {
		t.Errorf("rules 字段异常: %v", got["rules"])
	}
}

// TestFingerprintArrayInput 是最主要的用法：顶层数组进、顶层数组出，
// 响应结构与题目给出的示例响应一致。
func TestFingerprintArrayInput(t *testing.T) {
	body := `[
	  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"},
	  {"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
	  {"ip":"1.2.3.7","port":3306,"banner":"8.0.32-caching_sha2_password\u0000mysql_native_password"},
	  {"ip":"1.2.3.9","port":21,"banner":"220 ProFTPD 1.3.7 Server"},
	  {"ip":"1.2.3.99","port":9999,"banner":"\u0000\u0001garbage"}
	]`

	rec := do(t, newRouter(t, 0), http.MethodPost, "/fingerprint", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var got []model.Fingerprint
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是 JSON 数组: %v (body=%s)", err, rec.Body.String())
	}
	if len(got) != 5 {
		t.Fatalf("结果条数 = %d, 期望 5", len(got))
	}

	want := []struct{ proto, product, version string }{
		{"SSH", "OpenSSH", "8.9p1"},
		{"HTTP", "nginx", "1.24.0"},
		{"MySQL", "MySQL", "8.0.32"},
		{"FTP", "ProFTPD", "1.3.7"},
		{model.UnknownProtocol, "", ""},
	}
	for i, w := range want {
		if got[i].Protocol != w.proto || got[i].Product != w.product || got[i].Version != w.version {
			t.Errorf("第 %d 条 = %+v, 期望 protocol=%s product=%s version=%s", i, got[i], w.proto, w.product, w.version)
		}
		if got[i].IP == "" || got[i].Port == 0 {
			t.Errorf("第 %d 条未回填 ip/port: %+v", i, got[i])
		}
	}
}

// TestFingerprintAcceptsWrapperObject 验证兼容 {"records":[...]} 形式的输入。
func TestFingerprintAcceptsWrapperObject(t *testing.T) {
	for _, key := range []string{"records", "data", "items"} {
		body := `{"` + key + `":[{"ip":"1.2.3.5","port":80,"banner":"Server: Apache/2.4.57 (Ubuntu)"}]}`
		rec := do(t, newRouter(t, 0), http.MethodPost, "/fingerprint", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("[%s] status = %d, body = %s", key, rec.Code, rec.Body.String())
		}
		var got []model.Fingerprint
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("[%s] 解析失败: %v", key, err)
		}
		if len(got) != 1 || got[0].Product != "Apache" {
			t.Errorf("[%s] 结果异常: %+v", key, got)
		}
	}
}

// TestFingerprintEnvelope 验证可选的信封响应（含统计信息）。
func TestFingerprintEnvelope(t *testing.T) {
	body := `[{"ip":"1.1.1.1","port":80,"banner":"Server: nginx/1.24.0"},{"ip":"1.1.1.2","port":9,"banner":"nothing here"}]`
	rec := do(t, newRouter(t, 0), http.MethodPost, "/fingerprint?envelope=true", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var env model.Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("解析失败: %v (body=%s)", err, rec.Body.String())
	}
	if env.Summary.Total != 2 || env.Summary.Known != 1 || env.Summary.Unknown != 1 {
		t.Errorf("summary 异常: %+v", env.Summary)
	}
	if env.Summary.ByProto["HTTP"] != 1 || env.Summary.ByProto[model.UnknownProtocol] != 1 {
		t.Errorf("by_protocol 异常: %+v", env.Summary.ByProto)
	}
}

// TestFingerprintEmptyArray 验证空批次返回 []（而不是 null）。
func TestFingerprintEmptyArray(t *testing.T) {
	rec := do(t, newRouter(t, 0), http.MethodPost, "/fingerprint", "[]")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("空批次响应 = %s, 期望 []", rec.Body.String())
	}
}

// TestFingerprintBadRequests 验证各种畸形输入都返回 4xx 而不是 5xx / panic。
func TestFingerprintBadRequests(t *testing.T) {
	h := newRouter(t, 0)
	cases := []struct {
		name string
		body string
	}{
		{"空请求体", ""},
		{"非法 JSON", `{"ip":`},
		{"非数组非对象", `"just a string"`},
		{"对象里没有记录数组", `{"foo":"bar"}`},
		{"数组元素类型错误", `[123]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, h, http.MethodPost, "/fingerprint", tc.body)
			if rec.Code < 400 || rec.Code >= 500 {
				t.Errorf("status = %d, 期望 4xx; body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestFingerprintRejectsOversizeBody 验证请求体上限生效，返回 413。
func TestFingerprintRejectsOversizeBody(t *testing.T) {
	h := newRouter(t, 512)
	huge := `[{"ip":"1.2.3.4","port":22,"banner":"` + strings.Repeat("A", 4096) + `"}]`
	rec := do(t, h, http.MethodPost, "/fingerprint", huge)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, 期望 413; body = %s", rec.Code, rec.Body.String())
	}
}

// TestNoRoute 验证未知路径返回结构化 JSON。
func TestNoRoute(t *testing.T) {
	rec := do(t, newRouter(t, 0), http.MethodGet, "/nope", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, 期望 404", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("not_found")) {
		t.Errorf("响应体异常: %s", rec.Body.String())
	}
}
