# SEC-4.5 — signed release, end-to-end verification

First tagged, signed release of Olympus, verifying that
`.github/workflows/release.yml` builds, SLSA-provenances and Cosign-keyless-signs
the distribution artifacts with no stored secrets.

## Release under test

- **Tag:** `v0.2.0_on_publish` at `eec75be3326bd6cf386e6d276420accc145f49fa`
  (the `v0.2.0` release; the tag carries a stray `_on_publish` suffix from the
  GitHub UI "create tag on publish" field — kept as-is, it does not affect the
  signatures, which bind the artifact bytes and the workflow OIDC identity, not
  the tag name).
- **Release:** <https://github.com/chiaraberti13/OLYMPUS-SECURITY/releases/tag/v0.2.0_on_publish>
- **Workflow run:** `release` #45039818935 — conclusion **success**.

## Attached, signed artifacts

| Artifact | SHA-256 (signed subject) |
| --- | --- |
| `olympus_security-0.2.0-py3-none-any.whl` | `c8d3dea9ec5dbd0f991567908b12a6abff451e5424c751abb4886104c9fa248b` |
| `olympus_security-0.2.0.tar.gz` | `55c66773f1d41549f411b911333a11795d9f933452a24404c747bdccff77b752` |
| `olympus-security-sbom.cyclonedx.json` | `3988bbd409f62aee608b23fa946d6386f059ea6d855a371626c5ca1b0d57bbec` |

Each artifact ships a Sigstore bundle (`*.sigstore.json`); SLSA build provenance
for all subjects is `multiple.intoto.jsonl`.

## Verification (cosign, keyless)

The downloaded wheel's SHA-256 matched the signed subject above. Verified with
`cosign` against the Sigstore transparency log:

```
cosign verify-blob \
  --bundle olympus_security-0.2.0-py3-none-any.whl.sigstore.json \
  --certificate-identity-regexp '^https://github.com/chiaraberti13/OLYMPUS-SECURITY/\.github/workflows/release\.yml@refs/tags/v0\.2\.0_on_publish$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  olympus_security-0.2.0-py3-none-any.whl
# -> Verified OK

cosign verify-blob \
  --bundle olympus_security-0.2.0.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github.com/chiaraberti13/OLYMPUS-SECURITY/\.github/workflows/release\.yml@refs/tags/v0\.2\.0_on_publish$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  olympus_security-0.2.0.tar.gz
# -> Verified OK

cosign verify-blob-attestation \
  --bundle multiple.intoto.jsonl --type slsaprovenance \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --certificate-identity-regexp 'slsa-framework/slsa-github-generator' \
  olympus_security-0.2.0-py3-none-any.whl
# -> Verified OK
```

| Check | Result |
| --- | --- |
| Wheel keyless signature → workflow OIDC identity | **Verified OK** |
| sdist keyless signature → workflow OIDC identity | **Verified OK** |
| SLSA provenance (wheel) → `slsa-github-generator` identity | **Verified OK** |

## Result

The release pipeline builds, provenances and signs the Python distribution
without stored secrets, and the signatures and provenance verify against the
Sigstore transparency log and the pipeline's OIDC identity. `SEC-4.5` signing
is demonstrated end-to-end. PyPI publishing stays off (no `release` environment
approval, `PYPI_PUBLISH` unset); container-image publication remains gated by
`SEC-4.4`, which has no publishing workflow to guard yet.
