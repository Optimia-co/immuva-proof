// Package pkg implements the Immuva Protocol v2 (IMMUVAv2-ED25519-SHA256)
// in pure Go using only the standard library.
package pkg

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CanonicalJSON returns a deterministic JSON string with keys sorted
// lexicographically at every nesting level.
// This matches the @immuva/canonical algorithm exactly:
//   canonical = JSON.stringify(sorted_keys_recursively(value))
func CanonicalJSON(v any) (string, error) {
	return canonicalize(v)
}

func canonicalize(v any) (string, error) {
	if v == nil {
		return "null", nil
	}

	switch val := v.(type) {
	case bool:
		if val {
			return "true", nil
		}
		return "false", nil

	case float64:
		// Use json.Marshal for correct number representation
		b, err := json.Marshal(val)
		if err != nil {
			return "", err
		}
		return string(b), nil

	case string:
		b, err := json.Marshal(val)
		if err != nil {
			return "", err
		}
		return string(b), nil

	case []any:
		parts := make([]string, len(val))
		for i, item := range val {
			s, err := canonicalize(item)
			if err != nil {
				return "", fmt.Errorf("array[%d]: %w", i, err)
			}
			parts[i] = s
		}
		return "[" + strings.Join(parts, ",") + "]", nil

	case map[string]any:
		// Sort keys lexicographically
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		parts := make([]string, len(keys))
		for i, k := range keys {
			kJSON, err := json.Marshal(k)
			if err != nil {
				return "", err
			}
			vJSON, err := canonicalize(val[k])
			if err != nil {
				return "", fmt.Errorf("key %q: %w", k, err)
			}
			parts[i] = string(kJSON) + ":" + vJSON
		}
		return "{" + strings.Join(parts, ",") + "}", nil

	default:
		// Fallback: marshal with standard json (loses key ordering for maps)
		b, err := json.Marshal(val)
		if err != nil {
			return "", fmt.Errorf("unsupported type %T: %w", v, err)
		}
		return string(b), nil
	}
}
