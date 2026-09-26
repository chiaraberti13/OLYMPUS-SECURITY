# Container test suite

Reserved for tests that exercise actual container-runtime or kernel isolation
behavior. Static Dockerfile/Compose checks remain contract or unit tests. This
suite currently has no executable cases; add a test marked `container` and run
it explicitly with `make test-container`. Do not claim scanner containment from
configuration-only tests.
