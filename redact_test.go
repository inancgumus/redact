package redact_test

import (
	"strings"
	"testing"

	"github.com/inancgumus/redact"
)

func TestSecrets_Redacts(t *testing.T) {
	rep := strings.Repeat
	hex32 := "0123456789abcdef0123456789abcdef"
	hex40 := hex32 + "01234567"
	hex64 := hex32 + hex32
	alnum36 := "abcdefghijklmnopqrstuvwxyz0123456789"

	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAvJ\n-----END RSA PRIVATE KEY-----"
	awsSecret := `aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`
	urlCreds := "https://user:hunter2hunter2@example.com:8080"
	pwdAssign := `password="hunter2hunter2"`
	querySecret := "https://api.example.com/v1?token=abc12345xyz"
	bearer := "Authorization: Bearer abcdef.123456.xyz789"
	basic := "Authorization: Basic dXNlcjpwYXNzd29yZA=="
	btoaCall := `btoa("user:hunter2hunter2")`
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	grafanaJWT := "eyJrIjoi" + rep("A", 72)
	slackHook := "https://hooks.slack.com/services/T" + rep("0", 8) + "/B" + rep("0", 8) + "/" + rep("a", 24)
	discordHook := "https://discord.com/api/webhooks/123456789012345678/" + rep("a", 64)
	teamsHook := "https://abc.webhook.office.com/webhookb2/aaaa-bbbb-cccc/IncomingWebhook/" + hex32 + "/xyz-123"

	cases := []struct{ name, input, leak string }{
		{"pem private key", pem, "MIIEowIBAAKCAQEAvJ"},
		{"aws access key id", "AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"},
		{"aws sts access key", "ASIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE"},
		{"aws secret access key value", awsSecret, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"aws bedrock api key", "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29tABC123", "YmVkcm9jay5hbWF6b25hd3MuY29tABC123"},

		{"github classic pat", "ghp_" + alnum36, "ghp_" + alnum36},
		{"github oauth", "gho_" + alnum36, "gho_" + alnum36},
		{"github server token", "ghs_" + alnum36, "ghs_" + alnum36},
		{"github refresh", "ghr_" + alnum36, "ghr_" + alnum36},
		{"github user-to-server", "ghu_" + alnum36, "ghu_" + alnum36},
		{"github fine-grained pat", "github_pat_" + rep("a", 82), "github_pat_" + rep("a", 82)},

		{"gitlab pat", "glpat-" + alnum36, "glpat-" + alnum36},
		{"gitlab pipeline trigger", "glptt-" + hex40, "glptt-" + hex40},
		{"gitlab deploy token", "gldt-" + rep("a", 20), "gldt-" + rep("a", 20)},
		{"gitlab cicd build", "glcbt-abcde_" + rep("a", 20), "glcbt-abcde_" + rep("a", 20)},
		{"gitlab feature flag", "glffct-" + rep("a", 20), "glffct-" + rep("a", 20)},
		{"gitlab feed token", "glft-" + rep("a", 20), "glft-" + rep("a", 20)},
		{"gitlab incoming mail", "glimt-" + rep("a", 25), "glimt-" + rep("a", 25)},
		{"gitlab k8s agent", "glagent-" + rep("a", 50), "glagent-" + rep("a", 50)},
		{"gitlab oauth secret", "gloas-" + rep("a", 64), "gloas-" + rep("a", 64)},
		{"gitlab runner", "glrt-" + rep("a", 20), "glrt-" + rep("a", 20)},
		{"gitlab scim oauth", "glsoat-" + rep("a", 20), "glsoat-" + rep("a", 20)},
		{"gitlab runner registration", "GR1348941" + rep("a", 20), "GR1348941" + rep("a", 20)},

		{"grafana service account", "glsa_" + rep("a", 32), "glsa_" + rep("a", 32)},
		{"grafana cloud token", "glc_" + rep("a", 50), "glc_" + rep("a", 50)},
		{"grafana legacy api key jwt", grafanaJWT, grafanaJWT},

		{"jwt", jwt, jwt},
		{"bearer header", bearer, "abcdef.123456.xyz789"},
		{"basic auth header", basic, "dXNlcjpwYXNzd29yZA=="},
		{"btoa user pass", btoaCall, "hunter2hunter2"},
		{"url credentials", urlCreds, "hunter2hunter2"},
		{"password assignment", pwdAssign, "hunter2hunter2"},
		{"query string secret", querySecret, "abc12345xyz"},

		{"slack webhook", slackHook, slackHook},
		{"slack bot xoxb", "xoxb-1234567890-1234567890123-" + rep("a", 24), "xoxb-1234567890-1234567890123-" + rep("a", 24)},
		{"slack user xoxp", "xoxp-1-2-3-" + rep("a", 30), "xoxp-1-2-3-" + rep("a", 30)},
		{"slack workspace xoxa", "xoxa-" + rep("a", 20), "xoxa-" + rep("a", 20)},
		{"slack app-level xapp", "xapp-1-A1234567890-1234567890-abcdef0123456789", "xapp-1-A1234567890-1234567890-abcdef0123456789"},

		{"discord webhook", discordHook, discordHook},
		{"ms teams webhook", teamsHook, teamsHook},

		{"google api key", "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI", "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"},
		{"openai project key", "sk-proj-" + rep("a", 74) + "T3BlbkFJ" + rep("a", 74), "T3BlbkFJ"},
		{"openai classic", "sk-" + rep("a", 20) + "T3BlbkFJ" + rep("a", 20), "T3BlbkFJ"},
		{"anthropic api key", "sk-ant-api03-" + rep("a", 93) + "AA", "sk-ant-api03-"},
		{"anthropic admin key", "sk-ant-admin01-" + rep("a", 93) + "AA", "sk-ant-admin01-"},
		{"huggingface user", "hf_" + rep("a", 34), "hf_" + rep("a", 34)},
		{"huggingface org", "api_org_" + rep("a", 34), "api_org_" + rep("a", 34)},
		{"perplexity", "pplx-" + rep("a", 48), "pplx-" + rep("a", 48)},

		{"stripe live secret", "sk_live_" + rep("a", 24), "sk_live_" + rep("a", 24)},
		{"stripe restricted key", "rk_live_" + rep("a", 24), "rk_live_" + rep("a", 24)},
		{"sendgrid api key", "SG." + rep("A", 22) + "." + rep("B", 43), "SG." + rep("A", 22)},
		{"twilio api key sid", "SK" + hex32, "SK" + hex32},
		{"mailgun private", "key-" + hex32, "key-" + hex32},
		{"mailgun pub", "pubkey-" + hex32, "pubkey-" + hex32},
		{"sendinblue", "xkeysib-" + hex64 + "-" + rep("a", 16), "xkeysib-" + hex64},

		{"postman", "PMAK-" + rep("a", 24) + "-" + rep("b", 34), "PMAK-" + rep("a", 24)},
		{"doppler personal", "dp.pt." + rep("a", 43), "dp.pt." + rep("a", 43)},
		{"digitalocean pat", "dop_v1_" + hex64, "dop_v1_" + hex64},
		{"digitalocean oauth", "doo_v1_" + hex64, "doo_v1_" + hex64},
		{"databricks", "dapi" + hex32, "dapi" + hex32},
		{"linear", "lin_api_" + rep("a", 40), "lin_api_" + rep("a", 40)},
		{"notion", "ntn_12345678901" + rep("a", 35), "ntn_12345678901" + rep("a", 35)},
		{"square access", "EAAA" + rep("a", 40), "EAAA" + rep("a", 40)},
		{"square oauth secret", "sq0csp-" + rep("a", 43), "sq0csp-" + rep("a", 43)},
		{"atlassian token", "ATATT3" + rep("a", 186), "ATATT3" + rep("a", 186)},
		{"heroku api key", "HRKU-AA" + rep("a", 58), "HRKU-AA" + rep("a", 58)},
		{"cloudflare origin ca", "v1.0-" + rep("a", 24) + "-" + rep("b", 146), "v1.0-" + rep("a", 24)},

		{"shopify access", "shpat_" + hex32, "shpat_" + hex32},
		{"shopify shared secret", "shpss_" + hex32, "shpss_" + hex32},
		{"sentry user token", "sntryu_" + hex64, "sntryu_" + hex64},
		{"dynatrace", "dt0c01." + rep("A", 24) + "." + rep("B", 64), "dt0c01." + rep("A", 24)},

		{"new relic admin", "NRAK-" + rep("A", 27), "NRAK-" + rep("A", 27)},
		{"new relic browser", "NRJS-" + rep("a", 19), "NRJS-" + rep("a", 19)},
		{"new relic insert", "NRII-" + rep("a", 32), "NRII-" + rep("a", 32)},

		{"planetscale token", "pscale_tkn_" + rep("a", 40), "pscale_tkn_" + rep("a", 40)},
		{"telegram bot", "123456789:A" + rep("a", 34), "123456789:A" + rep("a", 34)},
		{"vault service", "hvs." + rep("a", 95), "hvs." + rep("a", 95)},
		{"hashicorp atlas", rep("a", 14) + ".atlasv1." + rep("a", 65), ".atlasv1."},

		{"adobe oauth secret", "p8e-" + rep("a", 32), "p8e-" + rep("a", 32)},
		{"flyio access", "fo1_" + rep("a", 43), "fo1_" + rep("a", 43)},
		{"dropbox short-lived", "sl." + rep("a", 135), "sl." + rep("a", 135)},
		{"airtable pat", "pat" + rep("a", 14) + "." + hex64, "pat" + rep("a", 14)},
		{"1password secret", "A3-ABCDEF-ABCDEFGHIJK-ABCDE-ABCDE-ABCDE", "A3-ABCDEF-ABCDEFGHIJK-ABCDE-ABCDE-ABCDE"},
		{"1password service", "ops_eyJ" + rep("a", 260), "ops_eyJ" + rep("a", 260)},
		{"mapbox", "pk." + rep("a", 60) + "." + rep("b", 22), "pk." + rep("a", 60)},
		{"age secret key", "AGE-SECRET-KEY-1" + rep("Q", 58), "AGE-SECRET-KEY-1" + rep("Q", 58)},
		{"alibaba access key", "LTAI" + rep("a", 20), "LTAI" + rep("a", 20)},
		{"artifactory api", "AKCp" + rep("a", 69), "AKCp" + rep("a", 69)},
		{"artifactory ref", "cmVmd" + rep("a", 59), "cmVmd" + rep("a", 59)},
		{"clojars", "CLOJARS_" + rep("a", 60), "CLOJARS_" + rep("a", 60)},
		{"pulumi", "pul-" + hex40, "pul-" + hex40},
		{"prefect", "pnu_" + rep("a", 36), "pnu_" + rep("a", 36)},
		{"sourcegraph", "sgp_" + hex40, "sgp_" + hex40},
		{"typeform", "tfp_" + rep("a", 59), "tfp_" + rep("a", 59)},
		{"readme", "rdme_" + rep("a", 70), "rdme_" + rep("a", 70)},
		{"easypost api", "EZAK" + rep("a", 54), "EZAK" + rep("a", 54)},
		{"openshift", "sha256~" + rep("a", 43), "sha256~" + rep("a", 43)},
		{"settlemint app", "sm_aat_" + rep("a", 16), "sm_aat_" + rep("a", 16)},
		{"flutterwave secret", "FLWSECK_TEST-" + hex32 + "-X", "FLWSECK_TEST-" + hex32},
		{"yandex iam", "YC" + rep("a", 38), "YC" + rep("a", 38)},
		{"yandex api", "AQVN" + rep("a", 36), "AQVN" + rep("a", 36)},
		{"yandex access", "t1.abc." + rep("a", 86), "t1.abc."},
		{"facebook access", "EAAM" + rep("a", 110), "EAAM" + rep("a", 110)},
		{"defined networking", "dnkey-" + rep("a", 26) + "-" + rep("b", 52), "dnkey-" + rep("a", 26)},

		{"npm token", "npm_" + alnum36, "npm_" + alnum36},
		{"pypi upload", "pypi-AgEIcHlwaS5vcmc" + rep("a", 60), "pypi-AgEIcHlwaS5vcmc"},
		{"rubygems", "rubygems_" + rep("a", 48), "rubygems_" + rep("a", 48)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := redact.Secrets(c.input)
			if c.leak != "" && strings.Contains(got, c.leak) {
				t.Errorf("secret leaked\n input: %q\n  leak: %q\n   got: %q", c.input, c.leak, got)
			}
			if !strings.Contains(got, redact.DefaultRedacted) {
				t.Errorf("no [REDACTED] marker in output\n input: %q\n   got: %q", c.input, got)
			}
		})
	}
}

func TestSecrets_Preserves(t *testing.T) {
	cases := []struct{ name, input string }{
		{"empty", ""},
		{"plain prose", "the quick brown fox jumps over the lazy dog"},
		{"uuid as token value", "token=550e8400-e29b-41d4-a716-446655440000"},
		{"var expansion", `password="${SECRET}"`},
		{"shell expansion", `password="$(cat /etc/secret)"`},
		{"stopword example", `api_key="example_value_here"`},
		{"stopword placeholder", `secret="placeholder_value"`},
		{"dotted property access", "client.apiClient.token.expires"},
		{"short value", `password="short"`},
		{"normal config", "log_level=debug"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := redact.Secrets(c.input)
			if strings.Contains(got, redact.DefaultRedacted) {
				t.Errorf("unexpected redaction\n input: %q\n   got: %q", c.input, got)
			}
			if got != c.input {
				t.Errorf("input mutated unexpectedly\n input: %q\n   got: %q", c.input, got)
			}
		})
	}
}

func TestSecretsOpts_CustomPlaceholder(t *testing.T) {
	in := "AKIAIOSFODNN7EXAMPLE"
	out := redact.SecretsOpts(in, redact.Options{Redacted: "<scrubbed>"})
	if strings.Contains(out, in) {
		t.Errorf("secret survived: %q", out)
	}
	if !strings.Contains(out, "<scrubbed>") {
		t.Errorf("custom placeholder missing: %q", out)
	}
	if strings.Contains(out, redact.DefaultRedacted) {
		t.Errorf("default placeholder leaked when custom set: %q", out)
	}
}

func TestSecretsOpts_ZeroFieldsUseDefaults(t *testing.T) {
	in := "AKIAIOSFODNN7EXAMPLE"
	got := redact.SecretsOpts(in, redact.Options{})
	want := redact.Secrets(in)
	if got != want {
		t.Errorf("zero Options diverged from Secrets()\n opts: %q\n bare: %q", got, want)
	}
}

func TestSecretsOpts_RaisedEntropyDisablesGenericMatch(t *testing.T) {
	in := `api_key="abcdefghij1234567890"`
	lax := redact.SecretsOpts(in, redact.Options{MinEntropySecret: 1.0})
	strict := redact.SecretsOpts(in, redact.Options{MinEntropySecret: 10.0})
	if !strings.Contains(lax, redact.DefaultRedacted) {
		t.Errorf("low entropy threshold failed to redact: %q", lax)
	}
	if strings.Contains(strict, redact.DefaultRedacted) {
		t.Errorf("high entropy threshold should suppress redaction: %q", strict)
	}
}

func TestSecrets_MultipleInOneInput(t *testing.T) {
	a := "AKIAIOSFODNN7EXAMPLE"
	b := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	in := "first: " + a + " second: " + b
	got := redact.Secrets(in)
	if strings.Contains(got, a) {
		t.Errorf("first secret survived: %q", got)
	}
	if strings.Contains(got, b) {
		t.Errorf("second secret survived: %q", got)
	}
	if strings.Count(got, redact.DefaultRedacted) < 2 {
		t.Errorf("expected at least two [REDACTED] markers: %q", got)
	}
}

func TestSecrets_PreservesSurroundingContext(t *testing.T) {
	in := "before AKIAIOSFODNN7EXAMPLE after"
	got := redact.Secrets(in)
	if !strings.HasPrefix(got, "before ") {
		t.Errorf("prefix lost: %q", got)
	}
	if !strings.HasSuffix(got, " after") {
		t.Errorf("suffix lost: %q", got)
	}
}
