// Package redact replaces known secret patterns in text with [REDACTED].
package redact

import (
	"math"
	"regexp"
	"strings"
)

const (
	// DefaultMask is the placeholder used to replace detected secrets.
	DefaultMask = "[REDACTED]"
	// DefaultMinEntropy is the minimum Shannon entropy (bits/char) a
	// captured value must have to be treated as a secret.
	DefaultMinEntropy = 3.5
	// DefaultMinSubmatch is the minimum number of regex submatches required
	// before a generic match is considered for redaction.
	DefaultMinSubmatch = 2
)

// Options configures redaction. Zero-valued fields fall back to defaults.
type Options struct {
	// Mask is the replacement string written in place of detected secrets.
	Mask string
	// MinEntropy is the minimum Shannon entropy (bits/char) a captured
	// value must have to be redacted. Lower values redact more aggressively.
	MinEntropy float64
	// MinSubmatch is the minimum number of regex submatches required before
	// a generic match is considered for redaction.
	MinSubmatch int
}

// DefaultOptions holds the default redaction settings. Pass to String when no
// overrides are needed.
var DefaultOptions = Options{
	Mask:        DefaultMask,
	MinEntropy:  DefaultMinEntropy,
	MinSubmatch: DefaultMinSubmatch,
}

func (o Options) resolve() Options {
	if o.Mask == "" {
		o.Mask = DefaultMask
	}
	if o.MinEntropy == 0 {
		o.MinEntropy = DefaultMinEntropy
	}
	if o.MinSubmatch == 0 {
		o.MinSubmatch = DefaultMinSubmatch
	}
	return o
}

// String replaces known secret patterns in content using opts.
func String(content string, opts Options) string {
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
	red := opts.Mask
	constFn := func(string) string { return red }
	return []pattern{
		{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY[A-Z ]*-----`), constFn},

		{regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b`), constFn},
		{regexp.MustCompile(`(?i)(?:secret_?access_?key|aws_secret)["'\s]*[:=]["'\s]*([A-Za-z0-9/+=]{40})`), func(m string) string {
			return awsSecretRE.ReplaceAllString(m, red)
		}},
		{regexp.MustCompile(`\bbedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t[A-Za-z0-9+/=]*`), constFn},

		{regexp.MustCompile(`\bgh[oprsu]_[A-Za-z0-9_]{36,}`), constFn},
		{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82}`), constFn},

		{regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}`), constFn},
		{regexp.MustCompile(`\bglptt-[a-f0-9]{40}`), constFn},
		{regexp.MustCompile(`\bgldt-[A-Za-z0-9_\-]{20,}`), constFn},
		{regexp.MustCompile(`\bglcbt-[A-Za-z0-9]{1,5}_[A-Za-z0-9_\-]{20,}`), constFn},
		{regexp.MustCompile(`\bglffct-[A-Za-z0-9_\-]{20,}`), constFn},
		{regexp.MustCompile(`\bglft-[A-Za-z0-9_\-]{20,}`), constFn},
		{regexp.MustCompile(`\bglimt-[A-Za-z0-9_\-]{25,}`), constFn},
		{regexp.MustCompile(`\bglagent-[A-Za-z0-9_\-]{50,}`), constFn},
		{regexp.MustCompile(`\bgloas-[A-Za-z0-9_\-]{64,}`), constFn},
		{regexp.MustCompile(`\bglrt-[A-Za-z0-9_\-]{20,}`), constFn},
		{regexp.MustCompile(`\bglsoat-[A-Za-z0-9_\-]{20,}`), constFn},
		{regexp.MustCompile(`\bGR1348941[A-Za-z0-9_\-]{20,}`), constFn},
		{regexp.MustCompile(`\bglsa_[A-Za-z0-9_]{32,}`), constFn},
		{regexp.MustCompile(`\bglc_[A-Za-z0-9+/]{32,400}={0,3}`), constFn},

		{regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`), constFn},
		{regexp.MustCompile(`\bxox[abeoprs]-[A-Za-z0-9-]{8,}`), constFn},
		{regexp.MustCompile(`\bxapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+`), constFn},
		{regexp.MustCompile(`(?i)\bxoxe\.xox[bp]-\d-[A-Z0-9]{40,}`), constFn},

		{regexp.MustCompile(`https://(?:discord|discordapp)\.com/api/webhooks/\d{17,21}/[A-Za-z0-9_\-]{60,}`), constFn},
		{regexp.MustCompile(`https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9\-]+/IncomingWebhook/[a-z0-9]{32}/[a-z0-9\-]+`), constFn},

		{regexp.MustCompile(`\bAIza[A-Za-z0-9_\-]{35}\b`), constFn},

		{regexp.MustCompile(`\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]+T3BlbkFJ[A-Za-z0-9_\-]+\b`), constFn},
		{regexp.MustCompile(`\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b`), constFn},
		{regexp.MustCompile(`\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93}AA\b`), constFn},

		{regexp.MustCompile(`(?i)\b(?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b`), constFn},

		{regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`), constFn},
		{regexp.MustCompile(`\beyJrIjoi[A-Za-z0-9]{70,400}={0,3}`), constFn},
		{regexp.MustCompile(`Bearer\s+[A-Za-z0-9_.\-/+=]+`), constFn},
		{regexp.MustCompile(`Basic\s+[A-Za-z0-9+/]+=*`), constFn},
		{regexp.MustCompile(`btoa\(["'][^"']+:[^"']+["']\)`), func(string) string { return `btoa("` + red + `")` }},

		{regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), constFn},
		{regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}`), constFn},
		{regexp.MustCompile(`\brubygems_[a-f0-9]{48}\b`), constFn},

		{regexp.MustCompile(`\bSG\.[A-Za-z0-9=_\-\.]{66}\b`), constFn},
		{regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`), constFn},
		{regexp.MustCompile(`\bhf_[A-Za-z]{34}\b`), constFn},
		{regexp.MustCompile(`\bapi_org_[A-Za-z]{34}\b`), constFn},
		{regexp.MustCompile(`\bPMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}\b`), constFn},
		{regexp.MustCompile(`\bdp\.pt\.[A-Za-z0-9]{43}\b`), constFn},
		{regexp.MustCompile(`\bdo[opr]_v1_[a-f0-9]{64}\b`), constFn},
		{regexp.MustCompile(`\bdapi[a-f0-9]{32}(?:-\d)?\b`), constFn},
		{regexp.MustCompile(`\blin_api_[A-Za-z0-9]{40}\b`), constFn},
		{regexp.MustCompile(`\bntn_[0-9]{11}[A-Za-z0-9]{35}\b`), constFn},
		{regexp.MustCompile(`\b(?:EAAA|sq0atp-)[A-Za-z0-9_\-]{22,60}\b`), constFn},
		{regexp.MustCompile(`\bsq0csp-[A-Za-z0-9_\-]{43}\b`), constFn},
		{regexp.MustCompile(`\bATATT3[A-Za-z0-9_\-=]{186}\b`), constFn},
		{regexp.MustCompile(`\bHRKU-AA[A-Za-z0-9_\-]{58}\b`), constFn},
		{regexp.MustCompile(`\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b`), constFn},

		{regexp.MustCompile(`\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b`), constFn},

		{regexp.MustCompile(`\bsntryu_[a-f0-9]{64}\b`), constFn},
		{regexp.MustCompile(`\bdt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}\b`), constFn},
		{regexp.MustCompile(`\b(?:pub)?key-[a-f0-9]{32}\b`), constFn},

		{regexp.MustCompile(`\bNRAK-[A-Z0-9]{27}\b`), constFn},
		{regexp.MustCompile(`\bNRJS-[a-f0-9]{19}\b`), constFn},
		{regexp.MustCompile(`\bNRII-[A-Za-z0-9\-]{32}\b`), constFn},

		{regexp.MustCompile(`\bpscale_(?:tkn|oauth|pw)_[A-Za-z0-9=\.\-_]{32,64}\b`), constFn},
		{regexp.MustCompile(`\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b`), constFn},
		{regexp.MustCompile(`\b[0-9]{5,16}:A[A-Za-z0-9_\-]{34}\b`), constFn},
		{regexp.MustCompile(`\bhv[bs]\.[A-Za-z0-9_\-]{90,}\b`), constFn},
		{regexp.MustCompile(`(?i)\b[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}\b`), constFn},

		{regexp.MustCompile(`\bp8e-[A-Za-z0-9]{32}\b`), constFn},
		{regexp.MustCompile(`\bfo1_[A-Za-z0-9_\-]{43}\b`), constFn},
		{regexp.MustCompile(`\bfm[12][ar]?_[A-Za-z0-9+/]{100,}={0,3}`), constFn},
		{regexp.MustCompile(`\bsl\.[A-Za-z0-9\-=_]{135}\b`), constFn},
		{regexp.MustCompile(`\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b`), constFn},
		{regexp.MustCompile(`\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b`), constFn},
		{regexp.MustCompile(`\bops_eyJ[A-Za-z0-9+/]{250,}={0,3}`), constFn},
		{regexp.MustCompile(`\bpk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9]{22}\b`), constFn},
		{regexp.MustCompile(`\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b`), constFn},
		{regexp.MustCompile(`\bLTAI[A-Za-z0-9]{20}\b`), constFn},
		{regexp.MustCompile(`\bAKCp[A-Za-z0-9]{69}\b`), constFn},
		{regexp.MustCompile(`\bcmVmd[A-Za-z0-9]{59}\b`), constFn},
		{regexp.MustCompile(`(?i)\bCLOJARS_[a-z0-9]{60}\b`), constFn},
		{regexp.MustCompile(`\bpul-[a-f0-9]{40}\b`), constFn},
		{regexp.MustCompile(`\bpnu_[A-Za-z0-9]{36}\b`), constFn},
		{regexp.MustCompile(`\bpplx-[A-Za-z0-9]{48}\b`), constFn},
		{regexp.MustCompile(`\bsgp_(?:[a-fA-F0-9]{16}_[a-fA-F0-9]{40}|[a-fA-F0-9]{40}|local_[a-fA-F0-9]{40})\b`), constFn},
		{regexp.MustCompile(`\btfp_[A-Za-z0-9\-_\.=]{59}\b`), constFn},
		{regexp.MustCompile(`\brdme_[a-z0-9]{70}\b`), constFn},
		{regexp.MustCompile(`\bEZ[AT]K[A-Za-z0-9]{54}\b`), constFn},
		{regexp.MustCompile(`\bsha256~[A-Za-z0-9_\-]{43}\b`), constFn},
		{regexp.MustCompile(`\bsm_[aps]at_[A-Za-z0-9]{16}\b`), constFn},
		{regexp.MustCompile(`\bFLW(?:PUB|SEC)K_TEST-[a-fA-F0-9]{32}-X\b`), constFn},
		{regexp.MustCompile(`\bYC[A-Za-z0-9_\-]{38}\b`), constFn},
		{regexp.MustCompile(`\bAQVN[A-Za-z0-9_\-]{35,38}\b`), constFn},
		{regexp.MustCompile(`\bt1\.[A-Z0-9a-z_\-]+={0,2}\.[A-Z0-9a-z_\-]{86}={0,2}`), constFn},
		{regexp.MustCompile(`\bEAA[MC][A-Za-z0-9]{100,}`), constFn},
		{regexp.MustCompile(`\bdnkey-[A-Za-z0-9=_\-]{26}-[A-Za-z0-9=_\-]{52}\b`), constFn},
		{regexp.MustCompile(`\bb_[A-Za-z0-9=_\-]{44}\b`), constFn},

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
			return sub[:i+3] + user + ":" + opts.Mask + "@"
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
		newRHS := rhs[:loc[0]+1] + opts.Mask + rhs[loc[1]-1:]
		return lhs + newRHS
	}
}

func redact(opts Options) func(string) string {
	return func(m string) string {
		subs := genericSecretRE.FindStringSubmatch(m)
		if len(subs) < opts.MinSubmatch {
			return m
		}
		captured := subs[1]
		if isVarExpansion(captured) || hasStopword(captured) {
			return m
		}
		if notSecretRE.MatchString(captured) || uuidRE.MatchString(captured) {
			return m
		}
		if shannonEntropy(captured) < opts.MinEntropy {
			return m
		}
		return strings.Replace(m, captured, opts.Mask, 1)
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
