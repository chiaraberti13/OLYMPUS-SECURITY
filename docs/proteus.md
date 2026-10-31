# Proteus awareness campaigns

Proteus creates training artifacts; it does not send email, host a landing page,
or collect credentials. Campaign creation is still people-directed sensitive work,
so both the CLI application service and the lower-level builder require an explicit
`ExecutionPolicy(authorized=True)`.

## Scope

The scope binds one engagement to recipient/sender domains and to exact HTTPS
origins that may carry tracking tokens:

```json
{
  "engagement": "awareness-2026",
  "allowed_domains": ["example.com"],
  "allowed_landing_origins": ["https://training.example.com"]
}
```

All three keys are required and unknown keys fail closed. Sender and recipient
addresses use conservative mailbox validation. Landing URLs must be absolute HTTPS,
must not contain credentials, and must match an exact allowed origin. The command's
engagement must equal the scope engagement. Out-of-scope audit records retain a
domain/origin and a SHA-256 correlation value, never the complete recipient address.

## Artifact contract and handling

Campaign files use `olympus.proteus-campaign` version `1.0.0`. The loader validates
the exact top-level/target fields, compatible SemVer, unique valid addresses and
unique URL-safe tokens. It has one explicit migration for the previous exact
unversioned shape; partially versioned or unknown-field documents are rejected.

Campaign tokens are bearer identifiers. Export is atomic and sets mode `0600` on
POSIX filesystems. The campaign command prints only counts and the output path, not
addresses or tokens. `proteus email` necessarily renders the selected token into its
training link, so treat that output as sensitive and deliver it only through the
separately authorized mail workflow.

## Reproducible flow

```bash
olympus proteus campaign \
  --engagement awareness-2026 \
  --targets recipients.txt \
  --landing-url https://training.example.com/lesson \
  --sender awareness@example.com \
  --scope proteus-scope.json \
  --output campaign.json \
  --i-am-authorized

olympus proteus page --engagement awareness-2026 --output training.html
olympus proteus email --campaign campaign.json --token '<authorized-token>'
olympus proteus report --campaign campaign.json --clicked '<recorded-token>'
```

Unknown click tokens are ignored and cannot alter campaign metrics. The training
page is static HTML with no form, input, script, or collection endpoint.
