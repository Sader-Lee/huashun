// Command client 是 Banner 指纹识别系统的独立客户端。
//
// 它读取本地 JSON 文件（扫描原始数据），批量提交给 server 的 /fingerprint 接口，
// 并把识别结果格式化展示出来。
//
// 用法示例：
//
//	client -server http://server:8080 -file /data/input.json
//	client -server http://127.0.0.1:8080 -file testdata/input.json -output json
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Sader-Lee/huashun/internal/model"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n[client] 执行失败: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	server := fs.String("server", envOr("SERVER_URL", "http://127.0.0.1:8080"), "server 地址")
	file := fs.String("file", envOr("INPUT_FILE", "testdata/input.json"), "本地扫描数据 JSON 文件")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP 请求超时")
	output := fs.String("output", "table", "输出格式: table | json")
	_ = fs.Parse(os.Args[1:])

	// 1) 读取本地文件
	blob, err := os.ReadFile(*file)
	if err != nil {
		return fmt.Errorf("读取输入文件失败: %w", err)
	}
	records, err := decodeRecords(blob)
	if err != nil {
		return fmt.Errorf("解析输入文件失败: %w", err)
	}
	fmt.Printf("[client] 输入文件 %s 解析出 %d 条记录\n", *file, len(records))

	// 2) 打包并提交
	payload, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("序列化请求失败: %w", err)
	}

	url := strings.TrimRight(*server, "/") + "/fingerprint"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: *timeout}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求 %s 失败: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}
	cost := time.Since(start)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server 返回 %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	results, err := decodeResults(respBody)
	if err != nil {
		return fmt.Errorf("解析响应失败: %w", err)
	}

	// 3) 展示结果
	if strings.EqualFold(*output, "json") {
		pretty, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(pretty))
	} else {
		printTable(results)
	}

	printSummary(results, *server, cost)
	return nil
}

func printTable(results []model.Fingerprint) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			r.IP, r.Port, orDash(r.Protocol), orDash(r.Product),
			orDash(r.Version), orDash(r.OSHint), r.Confidence)
	}
	_ = w.Flush()
	fmt.Println()
}

func printSummary(results []model.Fingerprint, server string, cost time.Duration) {
	summary := model.Summarize(results)

	fmt.Printf("[client] server=%s 用时=%s 总计=%d 已识别=%d 未识别=%d\n",
		server, cost.Round(time.Millisecond), summary.Total, summary.Known, summary.Unknown)

	protos := make([]string, 0, len(summary.ByProto))
	for p := range summary.ByProto {
		protos = append(protos, p)
	}
	sort.Slice(protos, func(i, j int) bool {
		if summary.ByProto[protos[i]] != summary.ByProto[protos[j]] {
			return summary.ByProto[protos[i]] > summary.ByProto[protos[j]]
		}
		return protos[i] < protos[j]
	})

	parts := make([]string, 0, len(protos))
	for _, p := range protos {
		parts = append(parts, fmt.Sprintf("%s=%d", p, summary.ByProto[p]))
	}
	fmt.Printf("[client] 协议分布: %s\n", strings.Join(parts, ", "))
}

// decodeRecords 从本地文件内容中解析记录，兼容数组与 {"records":[...]} 两种形态。
func decodeRecords(blob []byte) ([]model.Record, error) {
	trimmed := bytes.TrimSpace(blob)
	if len(trimmed) == 0 {
		return nil, errors.New("文件内容为空")
	}
	switch trimmed[0] {
	case '[':
		var recs []model.Record
		if err := json.Unmarshal(trimmed, &recs); err != nil {
			return nil, fmt.Errorf("记录数组解析失败: %w", err)
		}
		return recs, nil
	case '{':
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil, fmt.Errorf("JSON 对象解析失败: %w", err)
		}
		for _, key := range []string{"records", "data", "items", "banners"} {
			if raw, ok := obj[key]; ok {
				var recs []model.Record
				if err := json.Unmarshal(raw, &recs); err != nil {
					return nil, fmt.Errorf("字段 %q 解析失败: %w", key, err)
				}
				return recs, nil
			}
		}
		var rec model.Record
		if err := json.Unmarshal(trimmed, &rec); err != nil {
			return nil, err
		}
		return []model.Record{rec}, nil
	default:
		return nil, errors.New("文件内容必须是 JSON 数组或 JSON 对象")
	}
}

// decodeResults 解析 server 响应，兼容裸数组与信封两种形态。
func decodeResults(blob []byte) ([]model.Fingerprint, error) {
	trimmed := bytes.TrimSpace(blob)
	if len(trimmed) == 0 {
		return nil, errors.New("响应体为空")
	}
	if trimmed[0] == '[' {
		var out []model.Fingerprint
		if err := json.Unmarshal(trimmed, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	var env model.Envelope
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return nil, err
	}
	return env.Results, nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
