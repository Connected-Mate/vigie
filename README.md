# Vigie

**A lookout for known vulnerabilities. It makes your coding agent check before it installs anything, every time, across several public databases.**

A *vigie* is the lookout who watches the forest from the tower and calls the fire in while it is still small. Vigie does that for the packages your project is built on: your agent gives it names and versions, Vigie cross-checks the public databases and answers what is wrong, how urgent it is, and what to do.

- No account, no API key, free.
- No dependency: plain Node.js (18+), nothing to `npm install`. Small enough to read before you trust it.
- Several sources, one report. A source that is down is named in the report; Vigie never says "all clear" when it could not check.
- Three ways in, one engine: tools for the agent (MCP), a hook that stops a dangerous install, a command line for people and CI.

*Français plus bas.*

## Set it up with your agent

Paste this into Claude Code, Codex, Cursor, Gemini CLI, Copilot or Windsurf, in the folder of your project:

```
Install Vigie for me by following https://github.com/Connected-Mate/vigie/blob/main/AGENT-SETUP.md
Start from the folder you are in: if it is a project with dependency files, set Vigie up on top of it
without changing my code and show me the report for my own project. If it is not, tell me, and offer
me a demonstration check instead. Ask me before anything sensitive.
```

The agent installs, configures and proves it works by following [AGENT-SETUP.md](AGENT-SETUP.md). By hand, it is three commands:

```sh
git clone --depth 1 https://github.com/Connected-Mate/vigie ~/.vigie
node ~/.vigie/bin/vigie.mjs check .               # the report for the project you are in
node ~/.vigie/bin/vigie.mjs setup claude          # connect it to Claude Code in this project (also: gemini, cursor)
```

## What a report looks like

```
VERDICT: 4 known vulnerabilities in 1 of 1 package version(s) — 1 high priority.

## [HIGH] lodash@4.17.20 (npm)
What to do: Upgrade lodash to 4.18.1, the current release (fixes 4 of 4; the first fixed version 4.18.0 still has other known vulnerabilities).
- GHSA-35jh-r3h4-6jhm (CVE-2021-23337) · severity HIGH · fixed in 4.17.21 · exploit probability 20%
  Command Injection in lodash
  https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm
…
Sources:
- OSV.dev (Google / OpenSSF): ok
- CISA Known Exploited Vulnerabilities: ok
…
```

Priorities: **ACT NOW** (exploited in real attacks, malicious package, or open CERT-FR alert), **HIGH** (critical or high severity, or exploit probability of 10 % and more), **MEDIUM**, **LOW**. The version Vigie recommends is itself checked before it is recommended.

## Sources

| Source | What it brings |
|---|---|
| [OSV.dev](https://osv.dev) (Google / OpenSSF) | Known vulnerabilities and malicious packages in open source packages, matched on the exact version. Aggregates GitHub advisories, PyPA, RustSec, Go and others. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Whether a vulnerability is exploited in real attacks. |
| [EPSS](https://www.first.org/epss/) (FIRST.org) | Probability that a vulnerability gets exploited soon. |
| [CERT-FR](https://www.cert.ssi.gouv.fr) (ANSSI, French government) | Latest French government alerts and advisories. |
| [deps.dev](https://deps.dev) (Google Open Source Insights) | Not vulnerabilities, signals: a version deprecated by its author, a version published in the last 3 days, and the packages an install pulls in. Asked when single packages are checked or installed (up to 40 at a time), not for whole-project scans. |

Adding a source is one file in `src/providers/`. Looked at and left out: the GitHub Advisory API without a key (60 requests an hour, and its advisories are already in OSV), NVD without a key (5 requests per 30 seconds, and OSV already carries the severity), and the npm / PyPI registries as vulnerability sources (deps.dev gives the same signals for seven ecosystems in one place; the registries are only asked which version an install would bring).

## 1. Tools for the agent (MCP)

- `check_packages` — exact package versions (npm, PyPI, Maven, Go, crates.io, NuGet, Packagist, RubyGems, Pub, Hex).
- `check_project` — reads a project folder and its sub-folders: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `package.json`, `requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pyproject.toml`, `Cargo.lock`, `go.mod`, `composer.lock`, `Gemfile.lock`, `gradle.lockfile`, `pom.xml`, `packages.lock.json`, `pubspec.lock`.
- `check_technologies` — keyword watch for what is not a package ("PostgreSQL", "nginx", "Windows Server"): CERT-FR bulletins and exploited vulnerabilities.
- `vulnerability_details` — everything known about one id (CVE, GHSA…).
- `list_sources`.

The server is `node ~/.vigie/src/server.mjs` (stdio). Any MCP client works.

## 2. The hook: checking is not optional

Instructions can be forgotten; a hook cannot. `vigie setup` registers it for you.

- **Before** a command that installs or runs a package (`npm install x`, `pnpm add`, `yarn add`, `bun add`, `npx x`, `pnpm dlx`, `pip install`, `uv add`, `uvx`, `pipx`, `poetry add`, `cargo add`, `go get`, `gem install`, `composer require`, `dotnet add package`): the version the command would really bring is worked out (ranges and tags included), checked together with what it pulls in, and the command is **blocked** when the package has a high-priority known vulnerability or is malicious. A package it only pulls in blocks when it is malicious or exploited in real attacks; otherwise the agent gets a warning. The agent receives the report and the fix.
- **After** an install (`npm install`, `npm ci`, `pip install -r …`, `uv sync`…) or an edit of a dependency file: the project is checked and the agent is told what to fix. Each problem is said once per session.
- It never hangs the agent: 20 seconds at most (`VIGIE_HOOK_BUDGET_MS`). If the databases are unreachable it lets the command through and says so. Set `VIGIE_STRICT=1` to block instead.
- A risk you decide to accept goes in `.vigieignore` at the project root (one advisory id or `name@version` per line). It stops blocking, and stays listed in every report. Malicious packages cannot be accepted.

It understands the hook events of Claude Code, Codex, Gemini CLI, Cursor, Copilot and Devin/Windsurf. Proven inside real Claude Code sessions; the others are built from their documentation (see [AGENT-SETUP.md](AGENT-SETUP.md) for what was run and what was not).

## 3. Command line, for people and CI

```sh
vigie check                          # this folder and its sub-folders
vigie check path/to/project --json
vigie check npm:lodash@4.17.20 pypi:django@3.2.1
vigie check npm:express              # the version a plain install would bring today
```

Exit code `0`: nothing high-priority · `1`: high-priority findings (`--fail-on any` for any finding, `--fail-on none` to only report) · `2`: the check could not be completed. In CI:

```yaml
- run: git clone --depth 1 https://github.com/Connected-Mate/vigie /tmp/vigie && node /tmp/vigie/bin/vigie.mjs check .
```

## Limits — read this

- Vigie only knows **publicly disclosed** vulnerabilities in **published packages**. It does not find flaws in your own code, misconfiguration, or vulnerabilities nobody has reported yet. A clean verdict means "nothing known today", not "safe".
- A brand-new malicious release is not in any database yet. Vigie tells you when a version is less than 3 days old; it cannot tell you it is hostile.
- CERT-FR only exposes its latest bulletins: `check_technologies` matches product names, not your exact version, and an empty answer proves nothing.
- Without a lockfile (`package.json`, `pyproject.toml`, `pom.xml` alone), only the versions written in the file are checked, not what they pull in. Vigie says so in the report.
- The hook reads shell commands; it is a guardrail, not a sandbox. An install hidden in a script (`make deps`, `./setup.sh`) is not seen before it runs — the check after an edit and `vigie check` in CI are there for that. Before an install, what a package pulls in is computed for a fresh install and can differ slightly from what your lockfile ends up with; the check after the install reads the real lockfile.
- Severity comes from the advisory. Advisories that only carry a CVSS 4 vector and no severity word show as `UNKNOWN` and are treated as medium.
- Sub-folders are read down to 4 levels and 300 dependency files; installed code (`node_modules`, `.venv`, `vendor`…) is skipped.
- Tested on macOS with Node 22. Written for Node 18+ and for Windows paths, not yet run there.
- What leaves your machine: package names and versions, sent to the public APIs above. Never your code or your paths. Results are cached in `~/.cache/vigie` (`VIGIE_CACHE_DIR`), cleaned after 30 days.

## Tests

```sh
npm test
```

Offline: no test touches the network.

---

## En français

Vigie est un guetteur de failles connues. Comme la vigie qui surveille la forêt depuis sa tour et signale le départ de feu tant qu'il est petit, elle surveille les briques sur lesquelles votre projet est construit.

Votre agent de code lui donne les noms et les versions ; Vigie recoupe plusieurs bases publiques — OSV.dev (Google), CISA KEV (failles réellement exploitées), EPSS (probabilité d'exploitation), le CERT-FR (ANSSI) et deps.dev — et répond ce qui ne va pas, à quel point c'est urgent et quoi faire. Sans compte, sans clé, gratuit, sans aucune dépendance.

**Pour l'installer**, collez ceci dans votre agent (Claude Code, Codex, Cursor, Gemini CLI, Copilot, Windsurf), depuis le dossier de votre projet :

```
Installe Vigie en suivant https://github.com/Connected-Mate/vigie/blob/main/AGENT-SETUP.md
Pars du dossier où tu es : si c'est un projet avec des fichiers de dépendances, installe Vigie par-dessus
sans toucher à mon code et montre-moi le rapport de mon propre projet. Sinon, dis-le-moi et propose-moi
une vérification de démonstration. Demande-moi avant toute action sensible.
```

Trois usages, un seul moteur :
1. **Des outils pour l'agent** : vérifier des versions précises, un projet entier, ou des technologies par mot-clé.
2. **Un crochet qui rend la vérification obligatoire** : avant d'installer une brique, l'agent est arrêté si elle a une faille grave connue ou si elle est malveillante ; après chaque installation, le projet est revérifié.
3. **Une commande pour vous et pour l'intégration continue** : `vigie check`, qui échoue quand une faille grave est trouvée.

**Limites, à lire** : seules les failles publiques des briques publiées sont couvertes — pas les erreurs de votre propre code, pas les mauvais réglages, pas les failles encore inconnues. « Rien de connu aujourd'hui » ne veut pas dire « sûr ». Quand une base ne répond pas, Vigie le dit et ne conclut jamais « tout va bien ». Ce qui sort de votre machine : les noms et versions des briques, jamais votre code.

## License

MIT
