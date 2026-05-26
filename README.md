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

Override defaults via `Options`:

```go
clean := redact.SecretsOpts(text, redact.Options{
    Redacted:         "***",
    MinEntropySecret: 4.0,
    MinSubmatchLen:   2,
})
```

## Catches

PEM private keys, JWTs, `Bearer` / `Basic` auth headers, URL credentials,
`btoa("user:pass")` calls, password / secret / credential assignments,
query-string secrets, and generic high-entropy values near words like
`key`, `secret`, `token`.

Provider tokens with distinctive prefixes:

- AWS access keys (`AKIA`, `ASIA`, `ABIA`, `ACCA`, `A3T...`), AWS secret keys,
  Bedrock API keys
- GitHub (`ghp_`, `ghs_`, `gho_`, `ghr_`, `ghu_`, `github_pat_`)
- GitLab (`glpat-`, `glptt-`, `gldt-`, `glcbt-`, `glffct-`, `glft-`, `glimt-`,
  `glagent-`, `gloas-`, `glrt-`, `glsoat-`, `GR1348941`)
- Grafana (`glsa_`, `glc_`, `eyJrIjoi...`), Slack webhooks and `xox*` / `xapp-`
  tokens, Discord and Microsoft Teams webhooks
- Google `AIza`, OpenAI `sk-...T3BlbkFJ...`, Anthropic `sk-ant-`,
  HuggingFace `hf_` / `api_org_`, Perplexity `pplx-`
- Stripe (`sk_live_`, `rk_live_`, `sk_test_`, `sk_prod_`), SendGrid `SG.`,
  Twilio `SK<hex>`, Mailgun `key-` / `pubkey-`, Sendinblue `xkeysib-`
- Postman `PMAK-`, Doppler `dp.pt.`, Linear `lin_api_`, Notion `ntn_`,
  Atlassian `ATATT3`, Square (`EAAA`, `sq0atp-`, `sq0csp-`),
  Heroku `HRKU-AA`, Shopify (`shpat_`, `shpca_`, `shppa_`, `shpss_`)
- DigitalOcean (`dop_v1_`, `doo_v1_`, `dor_v1_`), Cloudflare `v1.0-...`,
  Databricks `dapi`, Dynatrace `dt0c01.`, New Relic (`NRAK-`, `NRJS-`, `NRII-`),
  Sentry `sntryu_`
- PlanetScale (`pscale_tkn_`, `pscale_oauth_`, `pscale_pw_`),
  Fly.io (`fo1_`, `fm1a_`, `fm1r_`, `fm2_`), Dropbox `sl.`, Airtable `pat...`,
  1Password (`A3-`, `ops_eyJ`), Mapbox `pk.`, Adobe `p8e-`, Alibaba `LTAI`,
  Artifactory (`AKCp`, `cmVmd`), Clojars `CLOJARS_`, Pulumi `pul-`,
  Prefect `pnu_`, Sourcegraph `sgp_`, Typeform `tfp_`, Readme `rdme_`,
  Easypost `EZAK` / `EZTK`, OpenShift `sha256~`, SettleMint `sm_aat_` /
  `sm_pat_` / `sm_sat_`, Flutterwave `FLWPUBK_TEST-` / `FLWSECK_TEST-`,
  Yandex (`YC`, `AQVN`, `t1.`), Facebook `EAAM` / `EAAC`, Defined Networking
  `dnkey-`, Beamer `b_`, AGE `AGE-SECRET-KEY-1`, npm `npm_`, PyPI `pypi-`,
  RubyGems `rubygems_`, HashiCorp Vault `hvs.` / `hvb.` and Terraform
  `.atlasv1.`, Telegram bot tokens

Skips variable expansions (`${...}`, `$(...)`), UUIDs, dotted property
access (`apiClient.token`), and values containing stopwords like `example`,
`test`, `placeholder`.
