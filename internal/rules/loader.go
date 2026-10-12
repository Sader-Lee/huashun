package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	builtin "github.com/Sader-Lee/huashun/rules"
)

// Load 加载并编译指纹规则。
//
// 若 dir 为空或目录不存在，则使用编译期内嵌的规则（rules/*.yaml）；
// 否则从 dir 读取所有 *.yaml，实现"不改代码、不重编译即可调整规则"。
func Load(dir string) ([]Rule, string, error) {
	files, source, err := collect(dir)
	if err != nil {
		return nil, "", err
	}
	if len(files) == 0 {
		return nil, "", fmt.Errorf("未找到任何规则文件（来源: %s）", source)
	}

	var (
		all  []Rule
		seen = make(map[string]string, 64)
	)
	for _, f := range files {
		var rs []Rule
		if err := yaml.Unmarshal(f.data, &rs); err != nil {
			return nil, "", fmt.Errorf("解析规则文件 %s 失败: %w", f.path, err)
		}
		if len(rs) == 0 {
			return nil, "", fmt.Errorf("规则文件 %s 中没有任何规则", f.path)
		}
		for i := range rs {
			if err := rs[i].Compile(); err != nil {
				return nil, "", fmt.Errorf("%s: %w", f.path, err)
			}
			if prev, dup := seen[rs[i].ID]; dup {
				return nil, "", fmt.Errorf("规则 id 重复: %q 同时出现在 %s 与 %s", rs[i].ID, prev, f.path)
			}
			seen[rs[i].ID] = f.path
			all = append(all, rs[i])
		}
	}

	// 优先级高的排在前面，便于引擎快速裁决（同优先级按 id 稳定排序，保证结果可复现）。
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Priority != all[j].Priority {
			return all[i].Priority > all[j].Priority
		}
		return all[i].ID < all[j].ID
	})
	return all, source, nil
}

type ruleFile struct {
	path string
	data []byte
}

// collect 返回待加载的规则文件列表以及来源描述。
func collect(dir string) ([]ruleFile, string, error) {
	if strings.TrimSpace(dir) != "" {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return nil, "", fmt.Errorf("读取规则目录 %s 失败: %w", dir, err)
			}
			var files []ruleFile
			for _, e := range entries {
				if e.IsDir() || !isYAML(e.Name()) {
					continue
				}
				p := filepath.Join(dir, e.Name())
				b, err := os.ReadFile(p)
				if err != nil {
					return nil, "", fmt.Errorf("读取规则文件 %s 失败: %w", p, err)
				}
				files = append(files, ruleFile{path: p, data: b})
			}
			sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
			return files, "external:" + dir, nil
		}
	}

	entries, err := fs.ReadDir(builtin.FS, ".")
	if err != nil {
		return nil, "", fmt.Errorf("读取内嵌规则失败: %w", err)
	}
	var files []ruleFile
	for _, e := range entries {
		if e.IsDir() || !isYAML(e.Name()) {
			continue
		}
		b, err := fs.ReadFile(builtin.FS, e.Name())
		if err != nil {
			return nil, "", fmt.Errorf("读取内嵌规则 %s 失败: %w", e.Name(), err)
		}
		files = append(files, ruleFile{path: "builtin:" + e.Name(), data: b})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	return files, "builtin", nil
}

func isYAML(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml")
}
