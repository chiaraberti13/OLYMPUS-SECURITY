# Run status, coverage and exit codes

A scanner that drops the requests it could not make reports a clean result for
a target it never actually looked at. That is the most dangerous failure mode a
security tool has: the operator reads an empty findings list and concludes the
target is fine.

`olympus.core.coverage` gives every scanning module one vocabulary for saying
what it actually covered, and `olympus.core.exit_codes` maps that onto the
process exit code so a pipeline can act on it without parsing output.

## Status

| Status | Meaning |
|---|---|
| `clean` | every planned unit completed and nothing was found |
| `findings` | every planned unit completed and something was found |
| `partial` | some units completed, some did not — findings are not exhaustive |
| `failed` | nothing completed; the result carries no information |
| `cancelled` | the operator stopped the run before it could finish |

`partial` deliberately outranks `findings`. A run that both found something and
lost coverage is incomplete first: the findings are still printed and exported,
but the exit code has to say the run cannot be read as exhaustive.

## Coverage

Every run reports `planned`, `completed`, `failed`, `skipped` and `unattempted`
counters plus a tally of `FailureKind` reasons, and up to ten redacted error
samples (secret-bearing URL query values are removed before a sample is kept):

| Reason | When |
|---|---|
| `scope_denied` | the target was outside the authorized scope (blocked and audited) |
| `policy_denied` | an execution policy or engagement restriction refused the unit |
| `dns_failure` | the name could not be resolved |
| `timeout` | the connection or response timed out |
| `unreachable` | routing failure — no route to the host or network |
| `transport_error` | the connection failed or was reset below the protocol layer |
| `protocol_error` | a response arrived but was malformed |
| `limit_exceeded` | a configured bound (body size, redirects, expansion ratio) was hit |
| `deadline_exceeded` | the overall budget ran out before the unit was reached |
| `cancelled` | cancellation was requested before the unit finished |
| `error` | anything else, kept explicit rather than silently dropped |

A unit that was never dispatched — refused by policy, or out of budget — is
counted as `skipped`; one that was dispatched and failed is `failed`. Both
break `complete`, so neither can be mistaken for a clean answer.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | success: full coverage, nothing to report |
| `1` | findings to act on |
| `2` | usage or input error |
| `3` | blocked: target out of the authorized scope (and logged) |
| `4` | refused: an authorization flag was required and missing |
| `5` | partial: coverage was lost, findings are not exhaustive |
| `6` | failed: nothing completed |
| `7` | cancelled before finishing |

Codes `5` and `6` are what let a caller tell "we looked everywhere and found
nothing" from "we could not look".

`RunStatus`, `ExitCode`, `classify_run_status()` and `exit_code_for()` are the
only first-party source of this mapping. Module-specific state machines remain
free to retain details such as `timed_out`, `unavailable` or `policy_denied`, but
must reduce them to the table above at the process boundary. Unknown exit values
from legacy Click applications or vendored subprocesses are normalized to `6`
instead of leaking an undocumented code through the public CLI.

The contract suite parses every first-party `cli.py` and rejects numeric
`typer.Exit` literals. It also verifies Athena assessment states, AEGIS execution
states and durable AEGIS job states end to end against this mapping.

## Helios port states

Helios reports a state per port instead of a boolean, because "closed" and
"we never got an answer" are opposite conclusions:

| State | Meaning | Coverage |
|---|---|---|
| `open` | the handshake completed | conclusive |
| `closed` | the peer actively refused | conclusive |
| `filtered` | no answer within the timeout | `timeout` |
| `unreachable` | no route to the host or network | `unreachable` |
| `dns_failure` | the name could not be resolved | `dns_failure` |
| `denied` | scope or `allowed_ports` refused this probe | `policy_denied` (skipped) |
| `deadline_exceeded` | the run's budget was spent before this port | `deadline_exceeded` (skipped) |
| `error` | anything else | `transport_error` |

A Helios scope file may narrow an engagement to specific ports; anything outside
that list is reported as `denied` and never touched:

```json
{
  "allowed_networks": ["192.0.2.0/24"],
  "allowed_ports": [22, 80, 443]
}
```

The refused ports are written once to the audit log with
`"reason": "port_not_allowed"`. Omitting `allowed_ports` authorizes any port
the operator asks for, as before.

### Optional banner identification

`olympus helios scan --banner` reads — and only reads — the greeting of
services that speak first (SSH, SMTP, FTP, POP3, IMAP, MySQL), so the reported
service is evidence rather than a guess from the port number. Nothing is ever
sent, the read is bounded to 256 bytes with its own short timeout, a silent
service is not an error, and the text is stripped of control characters before
it reaches a report or a terminal. Protocols where the *client* speaks first
(HTTP, TLS) are deliberately not identified this way: that would require
sending application data, which Helios does not do.

## Artemis coverage

Every Artemis command that touches a live target prints its status and coverage
to stderr and exits accordingly:

```
artemis: content status=partial findings=1 coverage=97/100 (transport_error=3)
artemis: content could not check transport_error: /backup: connection reset by peer
```

* `content` counts every wordlist candidate, so a run whose requests all failed
  exits `6`, not `0` with an empty list;
* `xss` counts every parameter it was asked to test, and a probe that never
  reached the parameter is a failure, not "no reflection";
* `metabase` separates "the host answered and is not Metabase" (clean) from
  "the host never answered" (failed) and "the instance was identified but the
  second endpoint could not be checked" (partial);
* `fingerprint` and `fetch` report the single request they exist to make.

### Pacing

`content` is rate-limited with `--rate` and spreads each wait over `--jitter`
(a fraction of the rate, `0.2` by default), so paced discovery is not a
metronome that is trivially fingerprinted or that lands in lockstep with
another client. `--deadline` bounds the whole run; the derived default scales
with the wordlist but is capped at one hour rather than multiplying the
per-request timeout by the wordlist length.
