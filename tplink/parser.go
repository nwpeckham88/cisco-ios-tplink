package tplink

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	topScriptRe     = regexp.MustCompile(`(?is)<script[^>]*>\s*(.*?)</script>`)
	hexLiteralRe    = regexp.MustCompile(`\b0[xX]([0-9a-fA-F]+)\b`)
	bareObjectKeyRe = regexp.MustCompile(`(?m)([{,\n\s])([A-Za-z_][A-Za-z0-9_]*)\s*:`)
)

func extractTopScript(html string) string {
	m := topScriptRe.FindStringSubmatch(html)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func jsToGo(valueStr string) any {
	valueStr = strings.TrimSpace(valueStr)
	if valueStr == "" {
		return ""
	}

	valueStr = hexLiteralRe.ReplaceAllStringFunc(valueStr, func(raw string) string {
		v, err := strconv.ParseInt(raw[2:], 16, 64)
		if err != nil {
			return raw
		}
		return strconv.FormatInt(v, 10)
	})

	if strings.HasPrefix(valueStr, "{") {
		normalized := normalizeObjectLiteral(valueStr)
		var out map[string]any
		if err := json.Unmarshal([]byte(normalized), &out); err == nil {
			return out
		}
		return nil
	}

	if strings.HasPrefix(valueStr, "[") {
		normalized := normalizeQuotedStrings(valueStr)
		var out []any
		if err := json.Unmarshal([]byte(normalized), &out); err == nil {
			return out
		}
		return nil
	}

	if len(valueStr) >= 2 {
		if (valueStr[0] == '"' && valueStr[len(valueStr)-1] == '"') ||
			(valueStr[0] == '\'' && valueStr[len(valueStr)-1] == '\'') {
			return valueStr[1 : len(valueStr)-1]
		}
	}

	if i, err := strconv.Atoi(valueStr); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(valueStr, 64); err == nil {
		return f
	}
	return valueStr
}

func normalizeObjectLiteral(raw string) string {
	raw = bareObjectKeyRe.ReplaceAllString(raw, `$1"$2":`)
	return normalizeQuotedStrings(raw)
}

func normalizeQuotedStrings(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	inSingle := false
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if ch == '\'' {
			if !inSingle {
				inSingle = true
				b.WriteByte('"')
				continue
			}
			if i > 0 && raw[i-1] == '\\' {
				b.WriteByte(ch)
				continue
			}
			inSingle = false
			b.WriteByte('"')
			continue
		}
		if inSingle && ch == '"' {
			b.WriteString(`\"`)
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func extractVar(html string, varname string) any {
	pattern := regexp.MustCompile(`\bvar\s+` + regexp.QuoteMeta(varname) + `\s*=`)
	loc := pattern.FindStringIndex(html)
	if loc == nil {
		return nil
	}

	rest := strings.TrimLeft(html[loc[1]:], " \t\r\n")
	if rest == "" {
		return nil
	}

	if newArrayPrefix(rest) {
		inner, ok := consumeDelimited(rest[strings.Index(rest, "("):], '(', ')')
		if !ok {
			return nil
		}
		return jsToGo("[" + inner + "]")
	}

	first := rest[0]
	if first == '{' || first == '[' {
		close := byte('}')
		if first == '[' {
			close = ']'
		}
		inner, ok := consumeDelimited(rest, first, close)
		if !ok {
			return nil
		}
		return jsToGo(string(first) + inner + string(close))
	}

	end := strings.IndexAny(rest, ";\n")
	if end < 0 {
		return jsToGo(strings.TrimSpace(rest))
	}
	return jsToGo(strings.TrimSpace(rest[:end]))
}

func newArrayPrefix(s string) bool {
	s = strings.TrimLeft(s, " \t\r\n")
	return strings.HasPrefix(strings.ToLower(s), "new array(")
}

func consumeDelimited(s string, open, close byte) (string, bool) {
	if len(s) == 0 || s[0] != open {
		return "", false
	}
	depth := 0
	inSingle := false
	inDouble := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\'' && !inDouble {
			if i == 0 || s[i-1] != '\\' {
				inSingle = !inSingle
			}
			continue
		}
		if ch == '"' && !inSingle {
			if i == 0 || s[i-1] != '\\' {
				inDouble = !inDouble
			}
			continue
		}
		if inSingle || inDouble {
			continue
		}
		if ch == open {
			depth++
			continue
		}
		if ch == close {
			depth--
			if depth == 0 {
				return s[1:i], true
			}
		}
	}
	return "", false
}

func mustMap(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected object")
	}
	return m, nil
}

func mustSlice(v any) ([]any, error) {
	s, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected array")
	}
	return s, nil
}

func asInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case float32:
		return int(t)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(t))
		return i
	default:
		return 0
	}
}

func asString(v any) string {
	s, ok := v.(string)
	if ok {
		return s
	}
	return ""
}

func asBool(v any) bool {
	return asInt(v) != 0
}

func asMap(v any) map[string]any {
	m, ok := v.(map[string]any)
	if ok {
		return m
	}
	return map[string]any{}
}

func asSlice(v any) []any {
	s, ok := v.([]any)
	if ok {
		return s
	}
	return []any{}
}
