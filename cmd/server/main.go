// Command server 是 Banner 指纹识别服务端。
//
// 用法：
//
//	server                     启动 HTTP 服务
//	server healthcheck         作为容器 healthcheck 探针（distroless 镜像内无 shell）
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Sader-Lee/huashun/internal/api"
	"github.com/Sader-Lee/huashun/internal/buildinfo"
	"github.com/Sader-Lee/huashun/internal/engine"
	"github.com/Sader-Lee/huashun/internal/rules"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck())
	}
	if err := run(); err != nil {
		slog.Error("服务启动失败", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	addr := fs.String("addr", envOr("SERVER_ADDR", ":8080"), "HTTP 监听地址")
	rulesDir := fs.String("rules", os.Getenv("RULES_DIR"), "外部规则目录（留空则使用内嵌规则）")
	logLevel := fs.String("log-level", envOr("LOG_LEVEL", "info"), "日志级别: debug|info|warn|error")
	maxBody := fs.Int64("max-body-bytes", 8<<20, "请求体上限（字节）")
	reqTimeout := fs.Duration("request-timeout", 30*time.Second, "单请求处理超时")
	_ = fs.Parse(os.Args[1:])

	log := newLogger(*logLevel)
	slog.SetDefault(log)

	rs, source, err := rules.Load(*rulesDir)
	if err != nil {
		return fmt.Errorf("加载指纹规则失败: %w", err)
	}
	eng := engine.New(rs, source)
	log.Info("指纹规则加载完成",
		slog.Int("rules", eng.RuleCount()),
		slog.String("source", source),
		slog.String("version", buildinfo.Version),
	)

	router := api.NewRouter(api.Options{
		Engine:         eng,
		Logger:         log,
		MaxBodyBytes:   *maxBody,
		RequestTimeout: *reqTimeout,
	})

	srv := &http.Server{
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return context.Background() },
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("监听 %s 失败: %w", *addr, err)
	}
	log.Info("服务已启动", slog.String("addr", ln.Addr().String()))

	// 优雅退出：收到 SIGTERM/SIGINT 后停止接收新连接，给在途请求留出时间。
	shutdownErr := make(chan error, 1)
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		sig := <-quit
		log.Info("收到退出信号，开始优雅关闭", slog.String("signal", sig.String()))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownErr <- srv.Shutdown(ctx)
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("HTTP 服务异常退出: %w", err)
	}
	if err := <-shutdownErr; err != nil {
		return fmt.Errorf("优雅关闭超时: %w", err)
	}
	log.Info("服务已退出")
	return nil
}

// runHealthcheck 探测本机 /health，用于容器 HEALTHCHECK。
// 因为运行镜像是 distroless（没有 shell / curl），所以把探针做进二进制里。
func runHealthcheck() int {
	target := os.Getenv("HEALTHCHECK_URL")
	if target == "" {
		target = "http://" + localAddr(envOr("SERVER_ADDR", ":8080")) + "/health"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck 失败: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck 状态码异常: %d\n", resp.StatusCode)
		return 1
	}
	fmt.Println("healthcheck ok")
	return 0
}

// localAddr 把 ":8080" / "0.0.0.0:8080" 归一成可直连的本机地址。
func localAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "127.0.0.1:8080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv}))
}
