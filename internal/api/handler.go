package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Sader-Lee/huashun/internal/buildinfo"
	"github.com/Sader-Lee/huashun/internal/engine"
	"github.com/Sader-Lee/huashun/internal/model"
)

// Handler 持有识别引擎与运行期元信息。
type Handler struct {
	eng     *engine.Engine
	log     *slog.Logger
	started time.Time
}

// Health 是健康检查接口。
//
// 只有规则成功加载并编译（否则进程根本起不来）才会返回 200，
// 因此它足以作为 compose 的 healthcheck 判据与 depends_on 的前置条件。
func (h *Handler) Health(c *gin.Context) {
	c.Header("X-Rule-Count", fmt.Sprint(h.eng.RuleCount()))
	c.JSON(http.StatusOK, gin.H{
		"status":         "ok",
		"version":        buildinfo.Version,
		"commit":         buildinfo.Commit,
		"build_time":     buildinfo.Date,
		"rules":          h.eng.RuleCount(),
		"rule_source":    h.eng.RuleSource(),
		"uptime_seconds": int(time.Since(h.started).Seconds()),
	})
}

// Fingerprint 是批量识别接口。
//
// 请求体接受两种形态：
//   - 顶层数组：      [{"ip":"1.2.3.4","port":22,"banner":"..."}]
//   - 顶层对象：      {"records":[ ... ]}（也接受 data/items/results/banners 作为键名）
//   - 单条对象：      {"ip":"1.2.3.4","port":22,"banner":"..."}
//
// 默认响应体是识别结果数组，与题目给出的示例响应保持一致；
// 附带 ?envelope=true 时额外返回统计信息（{"results":[...],"summary":{...}}）。
func (h *Handler) Fingerprint(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":   "payload_too_large",
				"message": fmt.Sprintf("请求体超过上限 %d 字节", maxErr.Limit),
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "read_body_failed",
			"message": err.Error(),
		})
		return
	}

	records, err := decodeRecords(body)
	if err != nil {
		h.log.Warn("请求体解析失败", slog.String("err", err.Error()))
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": err.Error(),
			"hint":    `期望 JSON 数组 [{"ip":..,"port":..,"banner":..}] 或 {"records":[...]}`,
		})
		return
	}

	results := h.eng.IdentifyBatch(c.Request.Context(), records)

	c.Header("X-Record-Count", fmt.Sprint(len(results)))
	c.Header("X-Rule-Count", fmt.Sprint(h.eng.RuleCount()))

	if isTruthy(c.Query("envelope")) {
		c.JSON(http.StatusOK, model.Envelope{
			Results: results,
			Summary: model.Summarize(results),
		})
		return
	}

	// 空批次也返回 []，而不是 null，方便客户端直接遍历。
	if results == nil {
		results = []model.Fingerprint{}
	}
	c.JSON(http.StatusOK, results)
}

// batchKeys 是可能的"记录数组"字段名，兼容不同导出工具的习惯命名。
var batchKeys = []string{"records", "data", "items", "results", "banners", "targets"}

func decodeRecords(body []byte) ([]model.Record, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errors.New("请求体为空")
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
			return nil, fmt.Errorf("请求体不是合法 JSON 对象: %w", err)
		}
		for _, key := range batchKeys {
			raw, ok := obj[key]
			if !ok {
				continue
			}
			v := bytes.TrimSpace(raw)
			if len(v) == 0 {
				continue
			}
			if v[0] != '[' {
				continue
			}
			var recs []model.Record
			if err := json.Unmarshal(v, &recs); err != nil {
				return nil, fmt.Errorf("字段 %q 不是合法的记录数组: %w", key, err)
			}
			return recs, nil
		}

		// 退化为"单条记录对象"。
		var rec model.Record
		if err := json.Unmarshal(trimmed, &rec); err != nil {
			return nil, fmt.Errorf("单条记录解析失败: %w", err)
		}
		if rec.IP == "" && rec.Banner == "" && rec.Port == 0 {
			return nil, fmt.Errorf("未在请求体中找到记录数组（可用键名: %v）", batchKeys)
		}
		return []model.Record{rec}, nil

	default:
		return nil, errors.New("请求体必须是 JSON 数组或 JSON 对象")
	}
}

func isTruthy(s string) bool {
	switch s {
	case "1", "true", "TRUE", "True", "yes", "on":
		return true
	}
	return false
}
