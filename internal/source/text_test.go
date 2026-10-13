package source

import "testing"

func TestValidateText(t *testing.T) {
	t.Parallel()
	valid := [][]byte{
		[]byte("example.com"),
		append([]byte{0xef, 0xbb, 0xbf}, []byte("example.com")...),
		{},
	}
	for _, data := range valid {
		if err := ValidateText(data); err != nil {
			t.Errorf("valid text rejected: %v", err)
		}
	}
	invalid := [][]byte{
		{0xff},
		{0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf, 'a'},
		{'a', 0, 'b'},
		{0x1f, 0x8b, 0x08},
		[]byte("<!doctype html><html>"),
		[]byte("# generated response\n<html>"),
		[]byte("{payload}"),
		[]byte("payload:" + string(byte(10)) + " - example.com"),
	}
	for _, data := range invalid {
		if err := ValidateText(data); err == nil {
			t.Errorf("invalid text accepted: %x", data)
		}
	}
}
