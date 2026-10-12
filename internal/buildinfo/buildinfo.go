package buildinfo

// 由构建时通过 -ldflags "-X ..." 注入。
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
