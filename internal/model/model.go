// Package model 定义对外暴露的请求/响应数据结构。
package model

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Record 表示一条网络扫描原始数据。
//
// 对外约定的字段是 ip / port / banner；为了兼容不同扫描器导出的字段命名，
// UnmarshalJSON 额外接受 response / raw / data / service_banner 作为 banner 别名，
// 并允许 port 以数字或字符串形式出现（如 22 或 "22" 或 "22/tcp"）。
type Record struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// UnmarshalJSON 实现宽松解析，保证"输入格式略有差异时不至于整批失败"。
func (r *Record) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	r.IP = firstString(raw, "ip", "host", "target", "address")
	r.Port = parsePort(firstString(raw, "port", "portid"))
	r.Banner = firstString(raw, "banner", "response", "raw", "data", "service_banner", "banner_text")
	return nil
}

// MarshalJSON 保证序列化时字段名与对外约定一致。
func (r Record) MarshalJSON() ([]byte, error) {
	type alias Record
	return json.Marshal(alias(r))
}

func firstString(raw map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		v, ok := raw[k]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			return s
		}
		// 兼容数字类型的字段（例如 port 以数字给出）
		var n json.Number
		if err := json.Unmarshal(v, &n); err == nil {
			return n.String()
		}
	}
	return ""
}

// parsePort 从形如 "22"、"22/tcp"、" 22 " 的字符串中提取端口号，失败返回 0。
func parsePort(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil || n < 0 || n > 65535 {
		return 0
	}
	return n
}

// Fingerprint 表示一条识别结果。
//
// 认不出时统一返回 Protocol = "unknown"，其余字段为空、置信度为 0，
// 绝不返回错误——"识别不出来"是一种正常结果，而不是失败。
type Fingerprint struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// UnknownProtocol 是识别失败时的协议占位符。
const UnknownProtocol = "unknown"

// NewUnknown 构造一条"未识别"结果。
func NewUnknown(ip string, port int) Fingerprint {
	return Fingerprint{IP: ip, Port: port, Protocol: UnknownProtocol}
}

// Summary 是批量识别的统计信息（仅在 envelope 模式下返回）。
type Summary struct {
	Total   int            `json:"total"`
	Known   int            `json:"known"`
	Unknown int            `json:"unknown"`
	ByProto map[string]int `json:"by_protocol"`
}

// Summarize 汇总一批识别结果。
func Summarize(results []Fingerprint) Summary {
	s := Summary{Total: len(results), ByProto: make(map[string]int, 8)}
	for _, r := range results {
		s.ByProto[r.Protocol]++
		if r.Protocol == UnknownProtocol {
			s.Unknown++
			continue
		}
		s.Known++
	}
	return s
}

// Envelope 是可选的外层包装响应（POST /fingerprint?envelope=true）。
type Envelope struct {
	Results []Fingerprint `json:"results"`
	Summary Summary       `json:"summary"`
}
