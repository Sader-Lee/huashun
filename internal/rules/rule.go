// Package rules 负责指纹规则的描述、编译与加载。
//
// 规则是纯数据（YAML），本包只做"编译成正则"和"校验"，
// 具体的匹配/裁决逻辑在 internal/engine 中，二者职责分离。
package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// MatchSpec 描述一条规则的命中条件。
type MatchSpec struct {
	// Any 任一命中即视为匹配。
	Any []string `yaml:"any"`
	// All 必须全部命中。
	All []string `yaml:"all"`
	// None 任一命中则否决本条规则。
	None []string `yaml:"none"`
}

// OSHint 描述一条操作系统线索。
//
// 若 Value 非空则直接使用 Value（其中 $1..$9 会被替换为正则捕获组）；
// 否则使用正则的第一个捕获组，无捕获组时使用整体匹配。
type OSHint struct {
	Regex string `yaml:"regex"`
	Value string `yaml:"value"`
}

// Rule 是一条指纹规则（编译后的形态）。
type Rule struct {
	ID         string    `yaml:"id"`
	Protocol   string    `yaml:"protocol"`
	Product    string    `yaml:"product"`
	Priority   int       `yaml:"priority"`
	Confidence float64   `yaml:"confidence"`
	Match      MatchSpec `yaml:"match"`
	Version    []string  `yaml:"version"`
	OSHint     []OSHint  `yaml:"os_hint"`

	matchAny   []*regexp.Regexp
	matchAll   []*regexp.Regexp
	matchNone  []*regexp.Regexp
	versionREs []*regexp.Regexp
	osREs      []*regexp.Regexp
}

// Compile 把规则中的正则字符串编译为 regexp，并做基本校验。
func (r *Rule) Compile() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("rule id 不能为空")
	}
	if strings.TrimSpace(r.Protocol) == "" {
		return fmt.Errorf("rule %q: protocol 不能为空", r.ID)
	}
	if r.Confidence < 0 || r.Confidence > 1 {
		return fmt.Errorf("rule %q: confidence 必须在 0~1 之间，当前 %v", r.ID, r.Confidence)
	}
	if len(r.Match.Any) == 0 && len(r.Match.All) == 0 {
		return fmt.Errorf("rule %q: match.any 与 match.all 不能同时为空", r.ID)
	}

	var err error
	if r.matchAny, err = compileAll(r.ID, "match.any", r.Match.Any); err != nil {
		return err
	}
	if r.matchAll, err = compileAll(r.ID, "match.all", r.Match.All); err != nil {
		return err
	}
	if r.matchNone, err = compileAll(r.ID, "match.none", r.Match.None); err != nil {
		return err
	}
	if r.versionREs, err = compileAll(r.ID, "version", r.Version); err != nil {
		return err
	}
	for i, h := range r.OSHint {
		re, cerr := regexp.Compile(h.Regex)
		if cerr != nil {
			return fmt.Errorf("rule %q: os_hint[%d] 正则非法: %w", r.ID, i, cerr)
		}
		r.osREs = append(r.osREs, re)
	}
	return nil
}

func compileAll(id, field string, exprs []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(exprs))
	for i, e := range exprs {
		re, err := regexp.Compile(e)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %s[%d] 正则非法: %w", id, field, i, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// Matches 判断 banner 是否命中本规则。
func (r *Rule) Matches(banner string) bool {
	for _, re := range r.matchNone {
		if re.MatchString(banner) {
			return false
		}
	}
	for _, re := range r.matchAll {
		if !re.MatchString(banner) {
			return false
		}
	}
	if len(r.matchAny) == 0 {
		return len(r.matchAll) > 0
	}
	for _, re := range r.matchAny {
		if re.MatchString(banner) {
			return true
		}
	}
	return false
}

// ExtractVersion 依次尝试版本正则，返回第一个成功提取到的版本号。
// 有捕获组时取第 1 个非空捕获组，否则取整体匹配。
func (r *Rule) ExtractVersion(banner string) string {
	for _, re := range r.versionREs {
		if v := extract(re, banner); v != "" {
			return v
		}
	}
	return ""
}

// ExtractOSHint 依次尝试操作系统线索，返回第一个成功提取到的值。
func (r *Rule) ExtractOSHint(banner string) string {
	for i, re := range r.osREs {
		m := re.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		v := ""
		if i < len(r.OSHint) && r.OSHint[i].Value != "" {
			v = expandCaptures(r.OSHint[i].Value, m)
		} else {
			v = firstGroup(m)
		}
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func extract(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	if len(m) == 1 {
		return strings.TrimSpace(m[0])
	}
	return firstGroup(m)
}

func firstGroup(m []string) string {
	for i := 1; i < len(m); i++ {
		if g := strings.TrimSpace(m[i]); g != "" {
			return g
		}
	}
	return ""
}

// expandCaptures 把 "$1"、"${1}" 替换为对应的捕获组内容，其余字符原样保留。
func expandCaptures(tpl string, m []string) string {
	var sb strings.Builder
	for i := 0; i < len(tpl); {
		if tpl[i] != '$' || i+1 >= len(tpl) || (!isDigit(tpl[i+1]) && tpl[i+1] != '{') {
			sb.WriteByte(tpl[i])
			i++
			continue
		}
		j := i + 1
		braced := tpl[j] == '{'
		if braced {
			j++
		}
		start := j
		for j < len(tpl) && isDigit(tpl[j]) {
			j++
		}
		if start == j || (braced && (j >= len(tpl) || tpl[j] != '}')) {
			// 不是合法的 $N / ${N} 占位符，原样输出
			sb.WriteByte(tpl[i])
			i++
			continue
		}
		idx := 0
		for k := start; k < j; k++ {
			idx = idx*10 + int(tpl[k]-'0')
		}
		if braced {
			j++
		}
		if idx < len(m) {
			sb.WriteString(m[idx])
		}
		i = j
	}
	return sb.String()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
