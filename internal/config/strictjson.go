package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

func validateJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := validateJSONValue(decoder, "$"); err != nil {
		return configErr("CONFIG_JSON", "", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return configErr("CONFIG_JSON", "", errors.New("trailing JSON value"))
		}
		return configErr("CONFIG_JSON", "", fmt.Errorf("trailing content: %w", err))
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("%s: null is not allowed", path)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%s: object key is not a string", path)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("%s: duplicate key %q", path, key)
			}
			seen[key] = struct{}{}
			if err := validateJSONValue(decoder, path+"."+key); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("%s: malformed object", path)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := validateJSONValue(decoder, path+"["+strconv.Itoa(index)+"]"); err != nil {
				return err
			}
			index++
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("%s: malformed array", path)
		}
	default:
		return fmt.Errorf("%s: unexpected delimiter %q", path, delimiter)
	}
	return nil
}

func validateExactKeys(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return configErr("CONFIG_JSON", "", err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		return configErr("CONFIG_SCHEMA", "$", errors.New("top-level value must be an object"))
	}
	if err := checkKeys(root, "$", "output", "ipv6", "download", "extract", "build", "groups"); err != nil {
		return err
	}
	if object, ok := root["download"].(map[string]any); ok {
		if err := checkKeys(object, "download", "concurrency", "per-host-concurrency", "timeout", "connect-timeout", "retries", "proxy"); err != nil {
			return err
		}
		if proxy, ok := object["proxy"].(map[string]any); ok {
			if err := checkKeys(proxy, "download.proxy", "enable", "url"); err != nil {
				return err
			}
		}
	}
	if object, ok := root["extract"].(map[string]any); ok {
		if err := checkKeys(object, "extract", "concurrency"); err != nil {
			return err
		}
	}
	if object, ok := root["build"].(map[string]any); ok {
		if err := checkKeys(object, "build", "max-line-size", "max-diagnostics"); err != nil {
			return err
		}
	}
	if groups, ok := root["groups"].([]any); ok {
		for i, item := range groups {
			if object, ok := item.(map[string]any); ok {
				if err := checkKeys(object, "groups["+strconv.Itoa(i)+"]", "name", "sources"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func checkKeys(object map[string]any, path string, allowed ...string) error {
	known := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		known[key] = struct{}{}
	}
	for key := range object {
		if _, ok := known[key]; !ok {
			return configErr("CONFIG_UNKNOWN_FIELD", path+"."+key, errors.New("unknown field"))
		}
	}
	return nil
}

func validateUnicodeEscapes(data []byte) error {
	for i := 0; i < len(data); {
		if data[i] != '"' {
			i++
			continue
		}
		i++
		for i < len(data) && data[i] != '"' {
			if data[i] != 0x5c {
				i++
				continue
			}
			i++
			if i >= len(data) {
				break
			}
			if data[i] != 'u' {
				i++
				continue
			}
			first, ok := parseHex4(data, i+1)
			if !ok {
				i++
				continue
			}
			i += 5
			switch {
			case first >= 0xd800 && first <= 0xdbff:
				if i+5 >= len(data) || data[i] != 0x5c || data[i+1] != 'u' {
					return errors.New("incomplete Unicode surrogate pair")
				}
				second, ok := parseHex4(data, i+2)
				if !ok || second < 0xdc00 || second > 0xdfff {
					return errors.New("invalid Unicode surrogate pair")
				}
				i += 6
			case first >= 0xdc00 && first <= 0xdfff:
				return errors.New("unpaired low Unicode surrogate")
			}
		}
		if i < len(data) {
			i++
		}
	}
	return nil
}

func parseHex4(data []byte, start int) (uint16, bool) {
	if start+4 > len(data) {
		return 0, false
	}
	var value uint16
	for i := start; i < start+4; i++ {
		value <<= 4
		switch c := data[i]; {
		case c >= '0' && c <= '9':
			value |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			value |= uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			value |= uint16(c-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}
