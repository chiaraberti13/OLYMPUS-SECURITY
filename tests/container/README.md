# Container test suite

`test_themis_native_image.py` builds the native wheel-based image and exercises
migration, a real loopback API, HTTPS Web and a native worker with live scanning
disabled. It runs non-root, read-only, with dropped capabilities and no external
network. Run explicitly with `make test-container` on a Docker host; CI runs it
in `native-container`. Static deployment checks remain contract/unit tests.

This verifies the native runtime boundary (SEC-A); it does not claim scanner
egress confinement or completed seccomp/AppArmor isolation (SEC-B).
