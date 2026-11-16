# Release pipeline — signed, keyless (`SEC-4.5` / `CICD-3`)

Olympus builds and signs its release artifacts with **no stored secrets**. The
pipeline (`.github/workflows/release.yml`) is **passive by default**: it does
nothing until a `vX.Y.Z` tag is pushed, and it publishes to PyPI **only** once
the owner has turned on the two switches below. Signing and publishing both use
short-lived OIDC credentials (Sigstore keyless, PyPI Trusted Publishing), so
there is never an API token or private key in the repository.

## What the pipeline does on a `vX.Y.Z` tag

1. **build** — builds the wheel and sdist (Hatchling) and a reproducible
   CycloneDX SBOM (`olympus core sbom --reproducible --engines`).
2. **provenance** — generates SLSA build provenance for the artifacts (keyless,
   OIDC) and attaches it to the GitHub Release.
3. **sign** — signs each artifact and the SBOM with Cosign **keyless**
   (Sigstore bundles, `*.sigstore.json`) and attaches everything to the GitHub
   Release.
4. **publish-pypi** — *only if* the tag build is approved and `PYPI_PUBLISH` is
   `true` — uploads the wheel and sdist to PyPI via **Trusted Publishing**
   (OIDC). No token.

Any one of the three gates missing (not a tag, variable not set, environment
not approved) means **nothing is published**.

## Owner setup — a one-time checklist (no secrets shared)

Do these once; none of them require giving a credential to anyone.

1. **Create the protected environment.**
   GitHub → *Settings* → *Environments* → **New environment** named exactly
   `release`. Add yourself under **Required reviewers** so every publish waits
   for your click. (Optionally restrict it to the `main` branch / tags.)

2. **Register the PyPI Trusted Publisher.**
   On <https://pypi.org> → your project → *Manage* → *Publishing* (or, for the
   first upload, *Your projects* → *Publishing* → *Add a pending publisher*),
   add a **GitHub Actions** trusted publisher with:
   - Owner / repository: `chiaraberti13/OLYMPUS-SECURITY`
   - Workflow name: `release.yml`
   - Environment: `release`

3. **Turn publishing on.**
   GitHub → *Settings* → *Secrets and variables* → *Actions* → *Variables* →
   **New repository variable** `PYPI_PUBLISH` = `true`. (Leave it unset, or set
   to anything else, to keep the pipeline build-and-sign only.)

4. **Confirm OIDC is allowed.**
   GitHub → *Settings* → *Actions* → *General* → *Workflow permissions*: the
   default already allows `id-token: write` requested per-job. Nothing to change
   unless your org tightened it.

## Cutting a release

```bash
git switch main && git pull
git tag -s v0.3.0 -m "Olympus v0.3.0"   # signed tag recommended
git push origin v0.3.0
```

The workflow starts, builds and signs, then **pauses at the `release`
environment** for your approval before the PyPI step. Approve it in the run's
page to publish; decline to stop at build-and-sign.

## Verifying a published artifact

```bash
# SLSA provenance (from the Release assets)
cosign verify-blob-attestation --bundle <artifact>.intoto.jsonl <artifact>

# Keyless signature bundle
cosign verify-blob --bundle <artifact>.sigstore.json <artifact>
```

Both verify against the Sigstore transparency log and the workflow's OIDC
identity (`https://github.com/chiaraberti13/OLYMPUS-SECURITY/.github/workflows/release.yml`),
so a consumer can prove an artifact was built and signed by this pipeline — not
re-uploaded by someone else.

> Container images are a separate gate (`SEC-4.4`): no workflow publishes an
> image today, and that gate must be in place *before* one does. This pipeline
> covers the Python distribution only.
