package model

import (
	"encoding/json"
	"strings"
)

// SensitiveKeys are attribute names whose values must never leave the
// server unredacted (plan summaries, state views, logs, audit).
var SensitiveKeys = []string{
	"password", "secret", "token", "private_key", "access_key",
	"secret_key", "api_key", "apikey", "credentials", "passwd",
}

// IsSensitiveKey reports whether a key name looks sensitive.
func IsSensitiveKey(k string) bool {
	lk := strings.ToLower(k)
	for _, s := range SensitiveKeys {
		if strings.Contains(lk, s) {
			return true
		}
	}
	return false
}

// RedactAttributes returns a copy of attrs with sensitive values replaced.
func RedactAttributes(attrs map[string]any) map[string]any {
	if attrs == nil {
		return nil
	}
	out := make(map[string]any, len(attrs))
	for k, v := range attrs {
		if IsSensitiveKey(k) {
			out[k] = "***"
			continue
		}
		out[k] = v
	}
	return out
}

// RedactedStateView parses raw state JSON and returns only
// {version, resources: [{type, name, address}]} — no attribute values
// at all. This is the only state view the API, MCP, CLI (non-runner),
// and dashboard may return. If parsing fails, it returns an empty
// resource list rather than leaking raw bytes.
func RedactedStateView(raw []byte) map[string]any {
	view := map[string]any{"resources": []map[string]string{}}
	if len(raw) == 0 {
		return view
	}
	var st struct {
		Version   int `json:"version"`
		Resources []struct {
			Type      string `json:"type"`
			Name      string `json:"name"`
			Instances []struct {
				Attributes map[string]any `json:"attributes"`
			} `json:"instances"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return view
	}
	view["version"] = st.Version
	res := []map[string]string{}
	for _, r := range st.Resources {
		res = append(res, map[string]string{
			"type": r.Type, "name": r.Name,
			"address": r.Type + "." + r.Name,
		})
	}
	view["resources"] = res
	return view
}

// RedactText replaces known sensitive-looking substrings in logs.
// Callers must still avoid logging secret values in the first place;
// this is a second line of defence, not a licence to log secrets.
func RedactText(s string, secrets ...string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "***")
		}
	}
	return s
}
