// Package engine 实现指纹识别引擎。
//
// 引擎本身不含任何硬编码指纹：它只负责
//  1. 用规则的 match 条件筛选候选规则；
//  2. 用规则的 version / os_hint 正则提取字段；
//  3. 按 (priority, confidence) 裁决出唯一结果；
//  4. 一条都命中不了时返回 unknown。
//
// 置信度完全来自规则配置，因此调整置信度属于"改数据"，不属于"改代码"。
package engine

import (
	"context"
	"math"
	"runtime"
	"strings"
	"sync"

	"github.com/Sader-Lee/huashun/internal/model"
	"github.com/Sader-Lee/huashun/internal/rules"
)

// MaxBannerBytes 是单条 banner 参与匹配的最大长度。
// 超出部分会被截断（而不是报错），避免超长输入拖垮正则回溯。
const MaxBannerBytes = 64 * 1024

// Engine 是并发安全的识别引擎（规则在构造后只读）。
type Engine struct {
	rules  []rules.Rule
	source string
}

// New 用已编译的规则构造引擎。
func New(rs []rules.Rule, source string) *Engine {
	return &Engine{rules: rs, source: source}
}

// RuleCount 返回已加载的规则条数（/health 会暴露该指标）。
func (e *Engine) RuleCount() int { return len(e.rules) }

// RuleSource 返回规则来源（builtin 或 external:<dir>）。
func (e *Engine) RuleSource() string { return e.source }

// Identify 识别单条数据。
//
// 任何情况下都不会 panic、不会返回错误：识别不出来就是 unknown。
func (e *Engine) Identify(ip string, port int, banner string) model.Fingerprint {
	fp := model.NewUnknown(ip, port)

	banner = strings.TrimSpace(banner)
	if banner == "" {
		return fp
	}
	if len(banner) > MaxBannerBytes {
		banner = banner[:MaxBannerBytes]
	}

	var (
		best      *rules.Rule
		bestScore float64
		bestVer   string
		bestOS    string
	)

	// 规则已按 priority 降序、id 升序排列，因此"先到者优先"是确定性的。
	for i := range e.rules {
		r := &e.rules[i]
		if !r.Matches(banner) {
			continue
		}
		if best != nil && !outranks(r, best, bestScore) {
			continue
		}
		best = r
		bestScore = r.Confidence
		bestVer = r.ExtractVersion(banner)
		bestOS = r.ExtractOSHint(banner)
	}

	if best == nil {
		return fp
	}

	fp.Protocol = best.Protocol
	fp.Product = best.Product
	fp.Version = bestVer
	fp.OSHint = bestOS
	// 置信度完全取自规则配置，不做任何隐式加权——
	// 想调整置信度只需要改 YAML，行为完全可预测、可复现。
	fp.Confidence = round2(best.Confidence)
	return fp
}

// outranks 判断候选规则 r 是否应取代当前的 best。
// 裁决顺序：priority 高者胜 → confidence 高者胜 → 规则在配置中的先后。
func outranks(r, best *rules.Rule, bestScore float64) bool {
	if r.Priority != best.Priority {
		return r.Priority > best.Priority
	}
	return r.Confidence > bestScore
}

// IdentifyRecord 识别一条扫描记录。
func (e *Engine) IdentifyRecord(rec model.Record) model.Fingerprint {
	return e.Identify(rec.IP, rec.Port, rec.Banner)
}

// IdentifyBatch 并发识别一批记录，输出顺序与输入顺序严格一致。
//
// 单条记录内部 panic 会被 recover 成 unknown，绝不影响整批结果——
// "识别不出来"是正常结果，"因为脏数据把服务搞崩"才是事故。
func (e *Engine) IdentifyBatch(ctx context.Context, recs []model.Record) []model.Fingerprint {
	out := make([]model.Fingerprint, len(recs))
	if len(recs) == 0 {
		return out
	}

	workers := runtime.GOMAXPROCS(0)
	if workers > len(recs) {
		workers = len(recs)
	}
	if workers < 1 {
		workers = 1
	}

	var (
		wg   sync.WaitGroup
		next = make(chan int, workers)
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range next {
				rec := recs[idx]
				out[idx] = safeIdentify(ctx, e, rec)
			}
		}()
	}

	for i := 0; i < len(recs); i++ {
		select {
		case next <- i:
		case <-ctx.Done():
			// 请求被取消：把剩余未处理的记录直接标记为 unknown，快速返回。
			for j := i; j < len(recs); j++ {
				out[j] = model.NewUnknown(recs[j].IP, recs[j].Port)
			}
			close(next)
			wg.Wait()
			return out
		}
	}
	close(next)
	wg.Wait()
	return out
}

func safeIdentify(ctx context.Context, e *Engine, rec model.Record) (fp model.Fingerprint) {
	defer func() {
		if r := recover(); r != nil {
			fp = model.NewUnknown(rec.IP, rec.Port)
		}
	}()
	if err := ctx.Err(); err != nil {
		return model.NewUnknown(rec.IP, rec.Port)
	}
	return e.IdentifyRecord(rec)
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
