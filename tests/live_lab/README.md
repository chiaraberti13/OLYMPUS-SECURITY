# Authorized live-lab test suite

Reserved for network-active tests against disposable, isolated targets for
which explicit authorization and a declared scope exist. This suite currently
has no executable cases and is not run by default CI. Before adding one, require
a scope check and bounded timeout/rate; use `make test-live-lab` only after
setting both explicit opt-in variables documented in `docs/testing.md`.
