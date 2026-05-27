# redact

Replaces secrets in text with `[REDACTED]`.

## Install

```
go get github.com/inancgumus/redact
```

## Use

```go
clean := redact.String(text, redact.DefaultOptions)
```

Override defaults via `Options`:

```go
clean := redact.String(text, redact.Options{
    // Placeholder written in place of each detected secret.
    // Default: "[REDACTED]".
    Mask: "***",

    // Minimum Shannon entropy (bits/char) a captured value must have
    // to be treated as a secret by the generic detector. Lower values
    // redact more aggressively; raise it to cut false positives on
    // low-entropy strings. Default: 3.5.
    MinEntropy: 4.0,

    // Minimum number of regex submatches required before a generic
    // match is considered for redaction. Default: 2.
    MinSubmatch: 2,
})
```

## Catches

Shape-based catches:

- PEM private keys
- JWTs
- `Bearer` auth headers
- `Basic` auth headers
- URL credentials (`user:pass@host`)
- `btoa("user:pass")` calls
- `password` / `secret` / `credential` assignments
- Query-string secrets (`?token=...`, `?key=...`, etc.)
- Generic high-entropy values near words like `key`, `secret`, `token`

Provider-token catches (prefix-anchored):

- AWS access keys (`AKIA`, `ASIA`, `ABIA`, `ACCA`, `A3T...`)
- AWS secret keys (keyword-anchored 40-char base64)
- AWS Bedrock API keys
- GitHub classic PAT (`ghp_`)
- GitHub server token (`ghs_`)
- GitHub OAuth (`gho_`)
- GitHub refresh token (`ghr_`)
- GitHub user-to-server (`ghu_`)
- GitHub fine-grained PAT (`github_pat_`)
- GitLab PAT (`glpat-`)
- GitLab pipeline trigger (`glptt-`)
- GitLab deploy token (`gldt-`)
- GitLab CI/CD build token (`glcbt-`)
- GitLab feature-flag client (`glffct-`)
- GitLab feed token (`glft-`)
- GitLab incoming-mail token (`glimt-`)
- GitLab Kubernetes agent (`glagent-`)
- GitLab OAuth app secret (`gloas-`)
- GitLab runner authentication (`glrt-`)
- GitLab SCIM OAuth (`glsoat-`)
- GitLab runner registration (`GR1348941`)
- Grafana service account (`glsa_`)
- Grafana Cloud access policy (`glc_`)
- Grafana legacy API key (`eyJrIjoi...`)
- Slack webhooks (`hooks.slack.com/services/...`)
- Slack tokens (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, `xoxo-`, `xoxe-`)
- Slack app-level (`xapp-`)
- Slack config tokens (`xoxe.xoxb-`, `xoxe.xoxp-`)
- Discord webhooks
- Microsoft Teams webhooks
- Google API key (`AIza`)
- OpenAI API key (`sk-...T3BlbkFJ...`)
- OpenAI project / service-account / admin (`sk-proj-`, `sk-svcacct-`, `sk-admin-`)
- Anthropic API key (`sk-ant-api03-`)
- Anthropic admin key (`sk-ant-admin01-`)
- HuggingFace user token (`hf_`)
- HuggingFace org token (`api_org_`)
- Perplexity (`pplx-`)
- Stripe live secret (`sk_live_`)
- Stripe test key (`sk_test_`)
- Stripe restricted key (`rk_live_`)
- Stripe production key (`sk_prod_`)
- SendGrid (`SG.`)
- Twilio API key SID (`SK<hex>`)
- Mailgun private (`key-<hex>`)
- Mailgun public (`pubkey-<hex>`)
- Sendinblue / Brevo (`xkeysib-`)
- Postman API key (`PMAK-`)
- Doppler personal token (`dp.pt.`)
- Linear API key (`lin_api_`)
- Notion integration token (`ntn_`)
- Square access token (`EAAA...`, `sq0atp-`)
- Square OAuth secret (`sq0csp-`)
- Atlassian API token (`ATATT3`)
- Heroku API key (`HRKU-AA`)
- Cloudflare origin CA (`v1.0-...`)
- Shopify access token (`shpat_`)
- Shopify custom access token (`shpca_`)
- Shopify private app token (`shppa_`)
- Shopify shared secret (`shpss_`)
- DigitalOcean PAT (`dop_v1_`)
- DigitalOcean OAuth (`doo_v1_`)
- DigitalOcean refresh (`dor_v1_`)
- Databricks PAT (`dapi<hex>`)
- Dynatrace API token (`dt0c01.`)
- New Relic user API key (`NRAK-`)
- New Relic browser key (`NRJS-`)
- New Relic insert key (`NRII-`)
- Sentry user auth token (`sntryu_`)
- PlanetScale service token (`pscale_tkn_`)
- PlanetScale OAuth (`pscale_oauth_`)
- PlanetScale password (`pscale_pw_`)
- Fly.io access token (`fo1_`, `fm1a_`, `fm1r_`, `fm2_`)
- Dropbox short-lived token (`sl.`)
- Airtable PAT (`pat<...>.<hex>`)
- 1Password secret key (`A3-`)
- 1Password service account (`ops_eyJ`)
- Mapbox token (`pk.<60>.<22>`)
- Adobe OAuth client secret (`p8e-`)
- Alibaba access key (`LTAI`)
- Artifactory API key (`AKCp`)
- Artifactory reference token (`cmVmd`)
- Clojars (`CLOJARS_`)
- Pulumi access token (`pul-`)
- Prefect API token (`pnu_`)
- Sourcegraph access token (`sgp_`)
- Typeform API token (`tfp_`)
- ReadMe API token (`rdme_`)
- EasyPost (`EZAK`, `EZTK`)
- OpenShift user token (`sha256~`)
- SettleMint app access (`sm_aat_`)
- SettleMint personal (`sm_pat_`)
- SettleMint service (`sm_sat_`)
- Flutterwave (`FLWPUBK_TEST-`, `FLWSECK_TEST-`)
- Yandex Cloud IAM (`YC`)
- Yandex API key (`AQVN`)
- Yandex access token (`t1.`)
- Facebook access token (`EAAM`, `EAAC`)
- Defined Networking (`dnkey-`)
- Beamer (`b_`)
- AGE secret key (`AGE-SECRET-KEY-1`)
- npm token (`npm_`)
- PyPI upload token (`pypi-AgEIcHlwaS5vcmc`)
- RubyGems (`rubygems_`)
- HashiCorp Vault service token (`hvs.`)
- HashiCorp Vault batch token (`hvb.`)
- HashiCorp Terraform (`<id>.atlasv1.<...>`)
- Telegram bot token

## Skips

- Variable expansions (`${...}`, `$(...)`)
- UUIDs
- Dotted property access (`apiClient.token`)
- Values containing stopwords (`example`, `test`, `placeholder`, etc.)
