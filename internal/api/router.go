// Package api 提供 HTTP 接口层（基于 Gin）。
package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Sader-Lee/huashun/internal/engine"
)

// Options 是构造路由所需的依赖与配置。
type Options struct {
	Engine         *engine.Engine
	Logger         *slog.Logger
	MaxBodyBytes   int64
	RequestTimeout time.Duration
}

// NewRouter 组装 Gin 路由。
//
// 对外只暴露两个接口：
//   - GET  /health       健康检查（供 compose healthcheck / LB 探活）
//   - POST /fingerprint  批量指纹识别
func NewRouter(opts Options) *gin.Engine {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 8 << 20 // 8 MiB
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 30 * time.Second
	}

	h := &Handler{
		eng:     opts.Engine,
		log:     opts.Logger,
		started: time.Now(),
	}

	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(
		recovery(opts.Logger),
		requestLogger(opts.Logger),
		bodyLimit(opts.MaxBodyBytes),
		timeout(opts.RequestTimeout),
	)

	r.GET("/health", h.Health)
	r.POST("/fingerprint", h.Fingerprint)

	// 便于排障的兜底路由：未匹配的路径返回结构化 JSON 而不是 gin 默认的纯文本。
	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "可用接口: GET /health, POST /fingerprint",
		})
	})
	r.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, gin.H{
			"error":   "method_not_allowed",
			"message": "允许的方法: GET /health, POST /fingerprint",
		})
	})
	return r
}

// recovery 捕获 panic，保证单个请求异常不会导致进程退出。
func recovery(log *slog.Logger) gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, err any) {
		log.Error("请求处理 panic 已恢复",
			slog.Any("panic", err),
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
		)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "服务内部错误，请检查请求体格式",
		})
	})
}

// requestLogger 输出结构化访问日志。
func requestLogger(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Info("http_request",
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
			slog.Int("status", c.Writer.Status()),
			slog.Duration("latency", time.Since(start)),
			slog.String("client", c.ClientIP()),
			slog.Int("resp_bytes", c.Writer.Size()),
		)
	}
}

// bodyLimit 限制请求体大小，防止超大 body 打爆内存。
func bodyLimit(n int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, n)
		}
		c.Next()
	}
}

// timeout 为每个请求挂上超时上下文，超时后引擎会快速返回未识别结果而不是长时间占用。
func timeout(d time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), d)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
