// Package redact replaces known secret patterns in text with [REDACTED].
package redact

import (
	"math"
	"regexp"
	"strings"
)

const (
	// DefaultRedacted is the placeholder used to replace detected secrets.
	DefaultRedacted = "[REDACTED]"
	// DefaultMinEntropySecret is the minimum Shannon entropy (bits/char) a
	// captured value must have to be treated as a secret.
	DefaultMinEntropySecret = 3.5
	// DefaultMinSubmatchLen is the minimum number of regex submatches required
	// before a generic match is considered for redaction.
	DefaultMinSubmatchLen = 2
)

// Options configures redaction. Zero-valued fields fall back to defaults.
type Options struct {
	// Redacted is the replacement string written in place of detected secrets.
	Redacted string
	// MinEntropySecret is the minimum Shannon entropy (bits/char) a captured
	// value must have to be redacted. Lower values redact more aggressively.
	MinEntropySecret float64
	// MinSubmatchLen is the minimum number of regex submatches required before
	// a generic match is considered for redaction.
	MinSubmatchLen int
}

func (o Options) resolve() Options {
	if o.Redacted == "" {
		o.Redacted = DefaultRedacted
	}
	if o.MinEntropySecret == 0 {
		o.MinEntropySecret = DefaultMinEntropySecret
	}
	if o.MinSubmatchLen == 0 {
		o.MinSubmatchLen = DefaultMinSubmatchLen
	}
	return o
}

// Secrets replaces known secret patterns in content using default options.
func Secrets(content string) string {
	return SecretsOpts(content, Options{})
}

// SecretsOpts replaces known secret patterns in content using opts.
func SecretsOpts(content string, opts Options) string {
	opts = opts.resolve()
	result := content
	for _, p := range secretPatterns(opts) {
		result = p.re.ReplaceAllStringFunc(result, p.fn)
	}
	result = genericSecretRE.ReplaceAllStringFunc(result, redact(opts))
	return result
}

type pattern struct {
	re *regexp.Regexp
	fn func(string) string
}

var (
	genericSecretRE = regexp.MustCompile(`[\w.\-]{0,50}?(?:access|auth|(?:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.\-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[` + "`" + `'"\s=]{0,5}([\w.\-=]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[` + "`" + `'"\s;]|\\[nr]|$)`)
	notSecretRE     = regexp.MustCompile(`^[a-zA-Z_.\-]+$`)
	uuidRE          = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	awsSecretRE     = regexp.MustCompile(`[A-Za-z0-9/+=]{40}`)
	urlCredsRE      = regexp.MustCompile(`://([^\s:]+):(.+)@`)
	quotedValueRE   = regexp.MustCompile(`["']([^"']{8,})["']`)
	querySecretRE   = regexp.MustCompile(`=([^&\s"'` + "`" + `]{6,})`)
)

func secretPatterns(opts Options) []pattern {
	red := opts.Redacted
	return []pattern{
		{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY[A-Z ]*-----`), func(string) string { return red }},
		{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), func(string) string { return red }},
		{regexp.MustCompile(`(?i)(?:secret_?access_?key|aws_secret)["'\s]*[:=]["'\s]*([A-Za-z0-9/+=]{40})`), func(m string) string {
			return awsSecretRE.ReplaceAllString(m, red)
		}},
		{regexp.MustCompile(`gh[ps]_[A-Za-z0-9_]{36,}`), func(string) string { return red }},
		{regexp.MustCompile(`glsa_[A-Za-z0-9_]{32,}`), func(string) string { return red }},
		{regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`), func(string) string { return red }},
		{regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`), func(string) string { return red }},
		{regexp.MustCompile(`Bearer\s+[A-Za-z0-9_.\-/+=]+`), func(string) string { return red }},
		{regexp.MustCompile(`Basic\s+[A-Za-z0-9+/]+=*`), func(string) string { return red }},
		{regexp.MustCompile(`btoa\(["'][^"']+:[^"']+["']\)`), func(string) string { return `btoa("` + red + `")` }},
		{regexp.MustCompile(`://([^\s:]+):(.+)@[^@\s]*[:/?)` + `]`), redactURLCredentials(opts)},
		{regexp.MustCompile(`(?i)["']?(?:passw(?:or)?d|secret|credential)[\w.\-]{0,20}["']?\s*[:=]\s*["']([^"']{8,})["']`), redactPasswordValue(opts)},
		{regexp.MustCompile(`(?i)([?&])(?:passw(?:or)?d|secret|token|key|auth)=([^&\s"'` + "`" + `]{6,})`), func(m string) string {
			return querySecretRE.ReplaceAllString(m, "="+red)
		}},
	}
}

func redactURLCredentials(opts Options) func(string) string {
	return func(m string) string {
		return urlCredsRE.ReplaceAllStringFunc(m, func(sub string) string {
			i := strings.Index(sub, "://")
			rest := sub[i+3:]
			user, _, _ := strings.Cut(rest, ":")
			return sub[:i+3] + user + ":" + opts.Redacted + "@"
		})
	}
}

func redactPasswordValue(opts Options) func(string) string {
	return func(m string) string {
		delimIdx := strings.IndexAny(m, ":=")
		if delimIdx < 0 {
			return m
		}
		rhs := m[delimIdx+1:]
		loc := quotedValueRE.FindStringIndex(rhs)
		if loc == nil {
			return m
		}
		val := rhs[loc[0]+1 : loc[1]-1]
		if isVarExpansion(val) || hasStopword(val) {
			return m
		}
		lhs := m[:delimIdx+1]
		newRHS := rhs[:loc[0]+1] + opts.Redacted + rhs[loc[1]-1:]
		return lhs + newRHS
	}
}

func redact(opts Options) func(string) string {
	return func(m string) string {
		subs := genericSecretRE.FindStringSubmatch(m)
		if len(subs) < opts.MinSubmatchLen {
			return m
		}
		captured := subs[1]
		if isVarExpansion(captured) || hasStopword(captured) {
			return m
		}
		if notSecretRE.MatchString(captured) || uuidRE.MatchString(captured) {
			return m
		}
		if shannonEntropy(captured) < opts.MinEntropySecret {
			return m
		}
		return strings.Replace(m, captured, opts.Redacted, 1)
	}
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]int{}
	for _, ch := range s {
		freq[ch]++
	}
	n := float64(len(s))
	var entropy float64
	for _, count := range freq {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func hasStopword(s string) bool {
	lower := strings.ToLower(s)
	for _, w := range redactStopwords() {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func redactStopwords() []string {
	return []string{
		"cache", "admin", "build", "config", "default", "example", "localhost",
		"template", "test", "sample", "placeholder", "changeme", "undefined",
		"null", "true", "false", "error", "warning", "message", "request",
		"response", "header", "content", "value",
	}
}

func isVarExpansion(s string) bool {
	return strings.Contains(s, "${") || strings.Contains(s, "$(")
}
