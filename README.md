# redact

Replaces secrets in text with `[REDACTED]`.

## Install

```
go get github.com/inancgumus/redact
```

## Use

```go
clean := redact.Secrets(text)
```

## Catches

Private keys, AWS keys, GitHub tokens (`ghp_`, `ghs_`), Grafana service
account tokens (`glsa_`), Slack webhooks, JWTs, `Bearer`/`Basic` auth, URL
credentials, password/secret/token assignments, query-string secrets, and
generic high-entropy values near words like `key`, `secret`, `token`.

Skips variable expansions (`${...}`, `$(...)`), UUIDs, dotted property
access (`apiClient.token`), and values containing stopwords like `example`,
`test`, `placeholder`.
