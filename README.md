# redact

Hide secrets in text.

## Usage

Pipe a file:

```
$ redact < ~/.aws/credentials
[default]
aws_access_key_id = ********************
aws_secret_access_key = ****************************************
```

Pass text inline with `-string`:

```
$ redact -string 'user=alice token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 status=ok'
user=alice token=**************************************** status=ok
```

Custom mask character:

```
$ redact -mask=# -string 'token: ghp_abcdefghijklmnopqrstuvwxyz0123456789'
token: ########################################
```

Catch a wider net of unknown-looking values in a config file:

```
$ redact -entropy=2.0 < config.yaml
```

Check for secrets without printing anything. Exits 1 if found, 0 if not:

```
$ redact -detect -string 'token=ghp_abcdefghijklmnopqrstuvwxyz0123456789' && echo clean || echo dirty
dirty

$ redact -detect -string 'log_level=debug' && echo clean || echo dirty
clean
```

## Use as a package

```go
import "github.com/inancgumus/redact"

clean := redact.String(text, redact.DefaultOptions)

if redact.HasSecrets(text, redact.DefaultOptions) {
    // text contains at least one detected secret
}
```

Tune the defaults:

```go
clean := redact.String(text, redact.Options{
    Mask:        '#',  // Character repeated for each byte. Default '*'.
    MinEntropy:  4.0,  // Raise to cut false positives. Default 3.5.
    MinSubmatch: 2,    // Raise to be more cautious on unknown patterns. Default 2.
})
```

Any zero field falls back to the default.

## What it catches

### Patterns by shape

- PEM private keys
- JWTs
- `Bearer` and `Basic` auth headers
- URL credentials (`user:pass@host`)
- `btoa("user:pass")` calls
- `password` / `secret` / `credential` assignments
- Query-string secrets (`?token=...`, `?key=...`)
- High-entropy values near words like `key`, `secret`, `token`

### Provider tokens (prefix-anchored)

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

### What it skips

- Variable expansions like `${SECRET}` or `$(cat secret)`
- UUIDs
- Dotted property access like `apiClient.token`
- Values containing words like `example`, `test`, `placeholder`
