package frs

import (
	"errors"
	"fmt"
)

const (
	CodeInvalidHeader = "FRS_INVALID_HEADER"
	CodeUnsupported   = "FRS_UNSUPPORTED"
	CodeChecksum      = "FRS_CHECKSUM"
	CodeDirectory     = "FRS_DIRECTORY"
	CodeSection       = "FRS_SECTION"
	CodeSet           = "FRS_SET"
	CodeIndex         = "FRS_INDEX"
	CodeStringPool    = "FRS_STRING_POOL"
	CodeNonCanonical  = "FRS_NON_CANONICAL"
	CodeOverflow      = "FRS_OVERFLOW"
	CodeWrite         = "FRS_WRITE"
)

// Error 是稳定分类的 FRS 编码或验证错误。
type Error struct {
	Code    string
	Message string
	Err     error
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Message
}

func (e *Error) Unwrap() error {
	return e.Err
}

func frsError(code, message string, err error) *Error {
	return &Error{Code: code, Message: message, Err: err}
}

// ErrorCode 返回稳定错误代码。
func ErrorCode(err error) string {
	var value *Error
	if errors.As(err, &value) {
		return value.Code
	}
	return ""
}

// SectionSummary 是验证后的 section 结构摘要。
type SectionSummary struct {
	Type   uint32
	Flags  uint32
	Offset uint64
	Length uint64
	Count  uint64
	Stride uint32
}

// SetSummary 是验证后的集合元数据，不暴露规则载荷。
type SetSummary struct {
	ID          uint32
	Kind        uint16
	Label       string
	RecordCount uint64
}

// Summary 只在整份文件严格验证后返回。
type Summary struct {
	Major            uint16
	Minor            uint16
	RequiredFeatures uint32
	FileBytes        uint64
	Checksum         uint64
	Sections         []SectionSummary
	Sets             []SetSummary
}

func checkedAdd(left, right uint64) (uint64, error) {
	if left > ^uint64(0)-right {
		return 0, frsError(CodeOverflow, "integer addition overflow", nil)
	}
	return left + right, nil
}

func checkedMultiply(left, right uint64) (uint64, error) {
	if left != 0 && right > ^uint64(0)/left {
		return 0, frsError(CodeOverflow, "integer multiplication overflow", nil)
	}
	return left * right, nil
}

func intSize(value uint64) (int, error) {
	converted := int(value)
	if converted < 0 || uint64(converted) != value {
		return 0, frsError(CodeOverflow, "value does not fit platform int", nil)
	}
	return converted, nil
}

func uint32Size(value int, field string) (uint32, error) {
	if value < 0 || uint64(value) > uint64(^uint32(0)) {
		return 0, frsError(CodeOverflow, fmt.Sprintf("%s exceeds uint32", field), nil)
	}
	return uint32(value), nil
}

func align8(value uint64) (uint64, error) {
	added, err := checkedAdd(value, 7)
	if err != nil {
		return 0, err
	}
	return added &^ 7, nil
}
