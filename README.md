# keysweep

Find and lock down AI tool API keys on your laptop.

Coding agents, MCP servers and editor plugins each keep model-provider keys somewhere: a JSON file
in a dot folder, a `.env` in a repo, an `export` in `~/.zshrc`. keysweep knows where those places
are, shows every key it finds with the risks attached, and moves keys into the macOS Keychain.
It never prints a key. You see fingerprints like `sk-ant-api03-…46bb6130` (public prefix plus the
first 8 hex chars of a SHA-256).

Example output (illustrative, trimmed for width):

```
┌────────┬──────────┬───────────────────────────┬──────────────────┬────────────────────────┬──────────────────────────────┬───────────────────────────┬───────┐
│ ID     ┆ SEVERITY ┆ TOOL                      ┆ PROVIDER         ┆ KEY                    ┆ FILE                         ┆ RISKS                     ┆ AGE   │
╞════════╪══════════╪═══════════════════════════╪══════════════════╪════════════════════════╪══════════════════════════════╪═══════════════════════════╪═══════╡
│ 4d9c99 ┆ critical ┆ dotenv (webapp)           ┆ Groq             ┆ gsk_…55add8ca          ┆ ~/code/webapp/.env:1         ┆ committed to git          ┆ 3mo   │
│ 14e8be ┆ critical ┆ Cursor MCP project (side) ┆ Google / Gemini  ┆ AIza…ac594b15          ┆ ~/Dropbox/side/.cursor/mcp…  ┆ synced: Dropbox           ┆ 41d   │
│ 961947 ┆ high     ┆ Shell profile             ┆ Anthropic        ┆ sk-ant-api03-…7704b009 ┆ ~/.zshrc:2                   ┆ exported to all processes ┆ 1y    │
│ 7bb7bd ┆ low      ┆ OpenCode auth store       ┆ OpenAI           ┆ sk-proj-…15792136      ┆ ~/.local/share/opencode/a…   ┆ plaintext                 ┆ 12d   │
└────────┴──────────┴───────────────────────────┴──────────────────┴────────────────────────┴──────────────────────────────┴───────────────────────────┴───────┘
4 key(s) in 4 file(s): 2 critical, 1 high, 0 medium, 1 low
```

## Install

```bash
cargo install --path .
```

## Usage

```bash
keysweep scan                       # known tool locations + common code folders
keysweep scan -p ~/work -p ~/oss    # choose project folders to walk
keysweep scan -f json               # or -f sarif for code-scanning dashboards
keysweep scan --fail-on high        # exit 1 if anything high or critical (CI / pre-commit)

keysweep fix --id 961947            # dry run: show what would change
keysweep fix --id 961947 --apply    # chmod 600 + move to Keychain + rewrite the file
keysweep fix --all --perms --apply  # only tighten permissions everywhere

keysweep env                        # export lines for keys keysweep moved; put this in ~/.zshrc:
                                    #   eval "$(keysweep env)"
keysweep locations [--all]          # which known locations exist on this machine
keysweep links                      # revoke / spend-limit pages for every provider
```

Try it without touching your real files:

```bash
cargo build && scripts/demo.sh            # scans a throwaway fake home with random fake keys
scripts/demo.sh fix --all                 # dry-run fix plan for the same fixture
```

## What it checks

| Risk | Severity | Meaning |
|---|---|---|
| committed to git / in git history | critical | the exact key is in a commit (matched in-process against `git log -p`) |
| synced: iCloud / Dropbox / Google Drive / OneDrive / Box | critical | the file leaves your machine |
| world-readable | high | any local user or process can read it |
| exported to all processes | high | set in a shell profile, inherited by everything you launch |
| group-readable | medium | readable by your group |
| plaintext | low | stored as a literal value in a file |

Key age is the file's modification time, since the key itself carries no date.

Locations live in [`src/registry.toml`](src/registry.toml). Add your own with `--registry extra.toml`
using the same format.

## What `fix` does

`fix` is a dry run unless you pass `--apply`. Before changing a file it re-checks that the key is
still on the reported line, writes the key to the login Keychain (service `keysweep`, account =
env var name), reads it back through `security` to confirm, and saves a 0600 backup under
`~/.keysweep/backups/<run>/`. The backup holds the original key, so delete it once things work.

| File | Rewrite |
|---|---|
| shell profile, `.envrc` | `export K="$(security find-generic-password -s keysweep -a K -w)"` |
| `.env` | line commented out; `eval "$(keysweep env)"` supplies the variable (dotenv libraries don't override existing env vars) |
| `.mcp.json` (Claude Code), Cursor `mcp.json`, OpenCode config | literal replaced with the tool's env reference: `${K}`, `${env:K}`, `{env:K}` |
| everything else | stored in Keychain, file left alone, with instructions |

If a key was committed or synced, moving it is not enough. `fix` prints the provider's revoke page.

## Safety properties

- Keys are held in a `Secret` type with no `Display` or `Serialize`; its `Debug` prints `<redacted>`, and it is zeroed on drop.
- Keys never go on a command line. The Keychain is written through the Security framework, and git history is searched in-process.
- No network access.
- The tests generate fake keys at runtime, so no key-shaped strings live in this repo. Integration tests check that no key or key suffix appears in table, JSON, SARIF or stderr output.

## Limitations

- Keychain migration is macOS only. `--perms` and scanning work anywhere Unix-like.
- GUI apps started from the Dock don't read `~/.zshrc`, so `${env:K}` references need the app launched from a terminal (or `launchctl setenv`).
- Not yet built: TUI, 1Password backend, canary decoy files, live key validation.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```
