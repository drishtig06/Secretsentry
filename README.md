# SecretSentry

SecretSentry is a lightweight, local-first command-line tool that scans files and directories for common accidentally committed credentials. It is written in Python, has no runtime dependencies, and redacts detected values in terminal and JSON output.

> This is an educational starter project, not a replacement for mature tools such as [Gitleaks](https://github.com/gitleaks/gitleaks). Pattern-based scanning can miss secrets and produce false positives. Use it as one layer in a broader security process.

## Features

- Scans a file or directory recursively without network access.
- Detects AWS access-key IDs, GitHub token formats, private-key headers, and likely credential assignments.
- Redacts secret values in console and JSON reports.
- Skips common generated/dependency directories, symlinks, and files above a configurable size.
- Returns exit code `1` if a possible secret is found, making it usable in CI.
- No third-party runtime dependencies; Python 3.10+.

## Install from source

```bash
git clone https://github.com/drishtig06/secretsentry.git
cd secretsentry
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

On Windows PowerShell, activate with:

```powershell
.venv\Scripts\Activate.ps1
```

To work on the source and get the `secretsentry` command:

```bash
python -m pip install -e .
```

Or run it without installing:

```bash
PYTHONPATH=src python -m secretsentry .
```

## Usage

Scan the current directory:

```bash
secretsentry
```

Scan a specific path:

```bash
secretsentry ./src
secretsentry ./config/.env
```

Save a redacted JSON report:

```bash
secretsentry . --json --output secretsentry-report.json
```

Exclude a file or directory by name (repeatable):

```bash
secretsentry . --exclude fixtures --exclude vendor
```

Set the maximum file size in bytes (default 1,000,000):

```bash
secretsentry . --max-file-size 500000
```

Show the version or help:

```bash
secretsentry --version
secretsentry --help
```

### Exit codes

- `0`: no findings.
- `1`: one or more possible secrets were found.
- `2`: invalid arguments or report-writing error.

### Example output

```text
.env:3: credential-assignment: Possible hard-coded credential assignment [supe…1234 (16 chars)]

Found 1 possible secret(s). Values are redacted.
```

The tool does not print full detected values. Reports can still disclose paths, line numbers, rule names, and partial values, so treat them as sensitive.

## Supported detections

| Rule | What it looks for |
| --- | --- |
| `aws-access-key` | AWS access key ID format (`AKIA` followed by 16 uppercase alphanumeric characters) |
| `github-token` | Common GitHub token prefixes and token-like values |
| `private-key` | PEM private key header markers |
| `credential-assignment` | Password, token, secret, and API-key assignments with a value of at least 8 characters |

These are heuristic patterns, not validation of a credential or provider API. Add new patterns carefully and test both intended matches and false positives.

## GitHub Actions

A CI workflow in `.github/workflows/ci.yml` runs the unit tests and builds the package on Python 3.10, 3.11, and 3.12. To scan a repository as a CI step after installing the package, add:

```yaml
- name: Scan for secrets
  run: secretsentry .
```

A finding fails the command with exit code `1`. Do not upload reports as public artifacts without reviewing them.

## Pre-commit hook

After installing SecretSentry in the same environment used for commits, add a local hook to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: secretsentry
        name: Scan for possible secrets
        entry: secretsentry
        language: system
        pass_filenames: false
        always_run: true
```

Then install and run the hook:

```bash
pre-commit install
pre-commit run --all-files
```

SecretSentry scans the working directory on each run. Keep `secretsentry` available on the hook's `PATH`.

## Limitations and safe response

- This version scans the current filesystem only; it does not inspect Git history, archives, binary formats, or remote repositories.
- Pattern matching is incomplete. A clean scan does not prove there are no credentials.
- Findings are not verified against cloud or provider services.
- If a real credential is detected, revoke or rotate it immediately, remove it from the repository, and review Git history and logs. Deleting a value in a later commit does not erase it from earlier commits.
- Never commit real secrets to demonstrate detection. Use synthetic test values.

For historical scanning and broader detection coverage, use an established scanner such as [Gitleaks](https://github.com/gitleaks/gitleaks).

## Development and tests

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

Optional lint check, if Ruff is installed:

```bash
ruff check .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and [SECURITY.md](SECURITY.md) for security reporting guidance.

## License

MIT. See [LICENSE](LICENSE).
