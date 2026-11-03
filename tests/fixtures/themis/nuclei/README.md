# nuclei fixtures

Real output of nuclei **v3.11.1** with the templates **v10.5.1 @ 79fb682** (`projectdiscovery/nuclei-templates`),
run against a local Python `http.server` on `127.0.0.1:8099` serving one static page. No other system was contacted.
Command, exactly what the Olympus adapter builds from `engine.toml`:

    nuclei -target http://127.0.0.1:8099 -jsonl -silent -no-color -disable-update-check \
      -no-interactsh -omit-raw -omit-template -templates <one template>

(stdin closed: nuclei reads targets from stdin when it is not a terminal and otherwise hangs.)
The only edit is that the capture directory prefix in `template-path` is replaced by `/opt/nuclei-templates`.

| File | Template | Records |
| --- | --- | --- |
| `multiple.jsonl` | `http/misconfiguration/http-missing-security-headers.yaml` | 10 |
| `tech-detect.jsonl` | `http/technologies/tech-detect.yaml` | 2 |
| `none.jsonl` | `http/exposed-panels/wordpress-login.yaml` | 0 (nuclei exits 0 with empty stdout) |
| `malformed.jsonl` | derived | **synthetic**: 5 real records of `multiple.jsonl` with a truncated JSON record (counted, makes the run partial) and a non-JSON line (ignored as stdout noise, by design) inserted |
