# Changelog

## 1.0.0 — 2026-11-22

First public version.

- **Engine**: cross-checks OSV.dev, CISA KEV, EPSS and CERT-FR; one prioritized report (ACT NOW, HIGH, MEDIUM, LOW) with the version to upgrade to. The recommended version is itself checked; a major version change is flagged.
- **New source — deps.dev**: versions deprecated by their author, versions published in the last 3 days, and the packages an install pulls in.
- **Command line**: `vigie check <folder>` and `vigie check <eco>:<name>[@version]`, `--json`, `--fail-on`, exit codes for CI. `vigie setup <claude|gemini|cursor>` writes and removes the agent configuration.
- **Hook**: works out the version an install would really bring (ranges, tags), checks what it pulls in, blocks dangerous installs, checks the project after installs and edits, says each problem once per session, never runs longer than its time budget. Reads the events of Claude Code, Codex, Gemini CLI, Cursor, Copilot and Devin/Windsurf.
- **Dependency files**: npm, pnpm (v5 to v9), yarn (v1 and berry), bun, pip requirements (includes, hashes), poetry, uv, Pipfile, pyproject, Cargo, Go modules (with the standard library), Composer, Bundler, Gradle, Maven, NuGet, Dart. Sub-folders of monorepos are read.
- **Versions**: PyPI (PEP 440), Maven and RubyGems ordering rules besides semver. Severity computed from the CVSS 3 vector when the advisory has no severity word.
- **Robustness**: time budget, one retry, atomic cache with corrupt-file detection, shared downloads between concurrent calls, 30-day cache cleaning, withdrawn advisories ignored.
- **`.vigieignore`**: risks accepted by the user stop blocking and stay listed in every report.
