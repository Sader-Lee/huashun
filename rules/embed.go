// Package rules 以嵌入式文件系统的方式提供内置指纹规则。
//
// 设计要点：识别规则与程序代码解耦。
// 所有指纹都写在同目录的 *.yaml 文件里，编译时通过 go:embed 打进二进制，
// 因此容器镜像不需要额外携带规则文件即可独立运行；
// 同时 server 支持 -rules / RULES_DIR 指向外部目录，
// 在不重新编译、不重建镜像的前提下覆盖或扩展规则（compose 中演示了只读挂载方式）。
//
// 新增一个协议/软件的指纹 = 新增或修改这里的 YAML，无需改动任何 Go 代码。
package rules

import "embed"

//go:embed *.yaml
var FS embed.FS
