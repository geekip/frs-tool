package normalize

import "testing"

func TestIPPrefix(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"192.168.1.7/24": "192.168.1.0/24",
		"192.0.2.1":      "192.0.2.1/32",
		"2001:db8::1":    "2001:db8::1/128",
		"2001:db8::7/64": "2001:db8::/64",
	}
	for input, expected := range tests {
		prefix, err := IPPrefix(input)
		if err != nil {
			t.Fatalf("IPPrefix(%q): %v", input, err)
		}
		if prefix.String() != expected {
			t.Errorf("IPPrefix(%q) = %q, want %q", input, prefix, expected)
		}
	}
	if _, err := IPPrefix("not-an-ip"); err == nil {
		t.Fatal("invalid address was accepted")
	}
}

func TestDomain(t *testing.T) {
	t.Parallel()
	valid := map[string]string{
		"Example.COM.": "example.com",
		"localhost":    "localhost",
		"a-b.example":  "a-b.example",
	}
	for input, expected := range valid {
		actual, err := Domain(input)
		if err != nil {
			t.Fatalf("Domain(%q): %v", input, err)
		}
		if actual != expected {
			t.Errorf("Domain(%q) = %q, want %q", input, actual, expected)
		}
	}
	invalid := []string{"", ".", "example.com..", "-bad.example", "bad-.example", "bad_name", "例子.example", "has space.example"}
	for _, input := range invalid {
		if _, err := Domain(input); err == nil {
			t.Errorf("Domain(%q) unexpectedly succeeded", input)
		}
	}
}

func TestKeyword(t *testing.T) {
	t.Parallel()
	actual, err := Keyword("Media,Video")
	if err != nil {
		t.Fatal(err)
	}
	if actual != "media,video" {
		t.Fatalf("Keyword result = %q", actual)
	}
	for _, input := range []string{"", "has space", string([]byte{'t', 'a', 'b', 9, 'v'}), "媒体"} {
		if _, err := Keyword(input); err == nil {
			t.Errorf("Keyword(%q) unexpectedly succeeded", input)
		}
	}
}
