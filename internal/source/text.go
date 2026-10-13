package source

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// ValidateText 检查已取得字节是否满足规则文本边界。
func ValidateText(data []byte) error {
	if !utf8.Valid(data) {
		return NewError("SOURCE_INVALID_TEXT", "source is not valid UTF-8", false, nil)
	}
	if bytes.HasPrefix(data, utf8BOM) && bytes.HasPrefix(data[len(utf8BOM):], utf8BOM) {
		return NewError("SOURCE_INVALID_TEXT", "source has more than one UTF-8 BOM", false, nil)
	}
	if bytes.IndexByte(data, 0) >= 0 || hasArchiveMagic(data) {
		return NewError("SOURCE_INVALID_TEXT", "source is not plain text", false, nil)
	}
	firstContent := ""
	for _, line := range strings.Split(strings.TrimPrefix(string(data), string(utf8BOM)), "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		firstContent = trimmed
		break
	}
	lower := strings.ToLower(firstContent)
	for _, prefix := range []string{"<!doctype", "<html", "<?xml", "{", "[", "payload:"} {
		if strings.HasPrefix(lower, prefix) {
			return NewError("SOURCE_UNSUPPORTED_DOCUMENT", "unsupported document container", false, nil)
		}
	}
	return nil
}

func hasArchiveMagic(data []byte) bool {
	magics := [][]byte{
		{0x1f, 0x8b},
		{'P', 'K', 0x03, 0x04},
		{0x28, 0xb5, 0x2f, 0xfd},
		{'B', 'Z', 'h'},
		{0xfd, '7', 'z', 'X', 'Z', 0x00},
	}
	for _, magic := range magics {
		if bytes.HasPrefix(data, magic) {
			return true
		}
	}
	return false
}
