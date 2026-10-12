package rules_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Sader-Lee/huashun/internal/rules"
)

// TestLoadBuiltin 验证内嵌规则可正常加载与编译。
func TestLoadBuiltin(t *testing.T) {
	rs, source, err := rules.Load("")
	if err != nil {
		t.Fatalf("加载内嵌规则失败: %v", err)
	}
	if source != "builtin" {
		t.Errorf("source = %q, 期望 builtin", source)
	}
	if len(rs) < 10 {
		t.Errorf("内嵌规则条数偏少: %d", len(rs))
	}
	// 规则应按 priority 降序排列，保证引擎裁决结果稳定。
	for i := 1; i < len(rs); i++ {
		if rs[i-1].Priority < rs[i].Priority {
			t.Fatalf("规则未按 priority 降序排列: %d < %d", rs[i-1].Priority, rs[i].Priority)
		}
	}
}

// TestLoadExternalOverrides 验证规则与代码解耦：外部目录可以覆盖内嵌规则。
func TestLoadExternalOverrides(t *testing.T) {
	dir := t.TempDir()
	content := `- id: custom-proto
  protocol: CUSTOM
  product: MyProduct
  priority: 200
  confidence: 0.99
  match:
    any:
      - 'MAGIC-HELLO'
  version:
    - 'MyProduct/([0-9.]+)'
`
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	rs, source, err := rules.Load(dir)
	if err != nil {
		t.Fatalf("加载外部规则失败: %v", err)
	}
	if source != "external:"+dir {
		t.Errorf("source = %q", source)
	}
	if len(rs) != 1 || rs[0].Protocol != "CUSTOM" {
		t.Fatalf("外部规则未生效: %+v", rs)
	}
}

// TestLoadRejectsInvalidRule 验证非法规则在启动阶段就被拦下，而不是运行期静默失败。
func TestLoadRejectsInvalidRule(t *testing.T) {
	cases := map[string]string{
		"非法正则": `- id: bad
  protocol: X
  priority: 1
  confidence: 0.5
  match:
    any:
      - '([0-9'
`,
		"缺少匹配条件": `- id: bad
  protocol: X
  priority: 1
  confidence: 0.5
`,
		"置信度越界": `- id: bad
  protocol: X
  priority: 1
  confidence: 1.5
  match:
    any:
      - 'x'
`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, _, err := rules.Load(dir); err == nil {
				t.Fatal("期望报错，实际通过")
			}
		})
	}
}
