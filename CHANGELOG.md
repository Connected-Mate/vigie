# Changelog

## 1.0.0 — 2026-11-25

First public version.

- **Engine**: cross-checks OSV.dev, CISA KEV, EPSS and CERT-FR; one prioritized report (ACT NOW, HIGH, MEDIUM, LOW) with the version to upgrade to. The recommended version is itself checked; a major version change is flagged.
- **New source — deps.dev**: versions deprecated by their author, versions published in the last 3 days, and the packages an install pulls in.
- **Command line**: `vigie check <folder>` and `vigie check <eco>:<name>[@version]`, `--json`, `--fail-on`, exit codes for CI. `vigie setup <claude|gemini|cursor>` writes and removes the agent configuration.
- **Hook**: works out the version an install would really bring (ranges, tags), checks what it pulls in, blocks dangerous installs, checks the project after installs and edits, says each problem once per session, never runs longer than its time budget. Reads the events of Claude Code, Codex, Gemini CLI, Cursor, Copilot and Devin/Windsurf.
- **Dependency files**: npm, pnpm (v5 to v9), yarn (v1 and berry), bun, pip requirements (includes, hashes), poetry, uv, Pipfile, pyproject, Cargo, Go modules (with the standard library), Composer, Bundler, Gradle, Maven, NuGet, Dart. Sub-folders of monorepos are read.
- **Versions**: PyPI (PEP 440), Maven and RubyGems ordering rules besides semver. Severity computed from the CVSS 3 or CVSS 4 vector when the advisory has no severity word (CVSS 4 scoring checked against the reference calculator on every base vector).
- **Robustness**: time budget, one retry, atomic cache with corrupt-file detection, shared downloads between concurrent calls, 30-day cache cleaning, withdrawn advisories ignored.
- **`.vigieignore`**: risks accepted by the user stop blocking and stay listed in every report.
- **Setup**: nothing is written when one existing settings file is not valid JSON; a folder chosen with `VIGIE_HOME` is honoured and Vigie warns when it runs from another one; `setup` prints where Vigie's code is; Windows paths are written with forward slashes in hook commands and MCP entries. The install guide clones the program only (about 0.5 MB instead of about 40 MB; git 2.25+).
- **Tested**: offline tests run on Linux, macOS and Windows with Node 18 and 22 on every change. The agent setup and the hook were run inside real Claude Code sessions on macOS only; the other agents' configurations are built from their documentation.
