// Package version 保存由发布构建注入的工具版本。
package version

// Version 在正式构建中通过 -ldflags 注入版本标签。
var Version = "dev"
