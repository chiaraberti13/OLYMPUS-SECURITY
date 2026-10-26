# Olympus terminal interface

`olympus ui` is the keyboard-first interface for the complete Olympus command
tree. It uses the same Typer/Click objects as the CLI, so newly registered tools
and leaf commands appear without maintaining a second execution catalogue.

![Olympus terminal interface](images/olympus-tui.png)

## Operation

- **Arrow keys** select tools and commands.
- **Tab** moves between the tool and command panes.
- **Enter** opens the selected command.
- **F5** runs it with the arguments entered in the execution view.
- **Ctrl+C** requests termination of the child process.
- **Escape** returns to the command browser when no process is running.
- **F1** opens the help screen and **F10** returns focus to the tool menu.

The execution view launches `python -m olympus.cli` with a fixed argument
vector and no shell. Standard output and error stream into a bounded log; the
real process exit code remains visible. The TUI therefore does not reinterpret
results or replace the CLI's machine-readable outputs.

## Security boundary

The interface cannot bypass authorization, scope, SSRF, deadline, cancellation
or resource-limit controls. Commands that require `--scope` and
`--i-am-authorized` still require those arguments. Secrets remain environment
variables and should never be pasted into the argument field.

The palette follows the supplied Norton Utilities reference: blue work area,
ivory borders, black/yellow selection, white menu strip and red status text. A
true-colour terminal is recommended. Environments that deliberately set
`NO_COLOR` receive a readable grayscale fallback.

## Dynamic forms derived from the CLI (`UX-A`)

A guided form must not be a single free-text argument box. `olympus.cli_forms`
derives, from the real Typer/Click command tree, an **interface-agnostic** form
schema so a TUI and a future web UI render the *same* fields instead of each
re-deriving the CLI's shape (`UX-A` bullet 4):

- `form_for("themis scan")` returns a `CommandForm` whose `fields` are typed
  `FormField`s — one per option/argument — each with a `kind` (`text`,
  `integer`, `number`, `boolean`, `choice`, `path`), its `required` flag, a
  stable `default`, `choices` (from enums), numeric `minimum`/`maximum` (from
  Click ranges), the `multiple` (repeatable) flag and the help text. So a UI
  knows to draw a checkbox, a select, a path picker or a ranged number input
  rather than a text box.
- `forms_for_app()` returns the schema for every runnable command, sorted and
  deterministic.
- `validate_values(form, values)` validates entered values **locally, before any
  run**: missing required fields, values outside a choice set, non-numeric input
  for a numeric field, and out-of-range numbers — returning human-readable errors.
- Defaults that are computed/absolute paths are omitted (no machine-specific
  value leaks into the schema), the same determinism discipline as the CLI
  reference.

Rendering these fields as live Textual widgets, and the separate "raw arguments"
expert mode, build on this schema and are tracked in
[`ROADMAP.md`](../ROADMAP.md) under `UX-A`.
