package normalize

import (
	"errors"
	"net/netip"
	"strings"
)

var (
	ErrInvalidIP      = errors.New("invalid IP prefix")
	ErrInvalidDomain  = errors.New("invalid domain")
	ErrInvalidKeyword = errors.New("invalid keyword")
)

// IPPrefix 接受地址或 CIDR，并返回掩码后的规范前缀。
func IPPrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, ErrInvalidIP
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// Domain 将受支持的 ASCII 域名规范化为小写形式。
func Domain(value string) (string, error) {
	if strings.HasSuffix(value, ".") {
		value = value[:len(value)-1]
	}
	if len(value) == 0 || len(value) > 253 {
		return "", ErrInvalidDomain
	}

	var normalized strings.Builder
	normalized.Grow(len(value))
	labelLength := 0
	labelStart := 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == '.':
			if labelLength == 0 || labelLength > 63 || value[labelStart] == '-' || value[i-1] == '-' {
				return "", ErrInvalidDomain
			}
			normalized.WriteByte(c)
			labelStart = i + 1
			labelLength = 0
		case c >= 'A' && c <= 'Z':
			normalized.WriteByte(c + ('a' - 'A'))
			labelLength++
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			normalized.WriteByte(c)
			labelLength++
		default:
			return "", ErrInvalidDomain
		}
	}
	if labelLength == 0 || labelLength > 63 || value[labelStart] == '-' || value[len(value)-1] == '-' {
		return "", ErrInvalidDomain
	}
	return normalized.String(), nil
}

// Keyword 仅接受可打印、非空白 ASCII，并执行 ASCII 小写化。
func Keyword(value string) (string, error) {
	if len(value) == 0 || len(value) > 253 {
		return "", ErrInvalidKeyword
	}
	var normalized strings.Builder
	normalized.Grow(len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < 0x21 || c > 0x7e {
			return "", ErrInvalidKeyword
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		normalized.WriteByte(c)
	}
	return normalized.String(), nil
}
