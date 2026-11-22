# Vigie

**Make your coding agent check known vulnerabilities, every time, across several public databases.**

Vigie is a small MCP server plus a hook. Your agent gives it package names and versions; Vigie cross-checks several public sources and answers: what is wrong, how urgent it is, and what to do.

- No account, no API key, free.
- No dependency: plain Node.js (18+), nothing to `npm install`. Small enough to read before you trust it.
- Several sources, one report. A source that is down is named in the report; Vigie never says "all clear" when it could not check.

*Français plus bas.*

## Sources

| Source | What it brings |
|---|---|
| [OSV.dev](https://osv.dev) (Google / OpenSSF) | Known vulnerabilities and malicious packages in open source packages, matched on the exact version. Aggregates GitHub advisories, PyPA, RustSec, Go and others. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Whether a vulnerability is exploited in real attacks. |
| [EPSS](https://www.first.org/epss/) (FIRST.org) | Probability that a vulnerability gets exploited soon. |
| [CERT-FR](https://www.cert.ssi.gouv.fr) (ANSSI, French government) | Latest French government alerts and advisories. |

Adding a source is one file in `src/providers/`.

## Tools given to the agent

- `check_packages` — check exact package versions (npm, PyPI, Maven, Go, crates.io, NuGet, Packagist, RubyGems).
- `check_project` — read a project folder's dependency files (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `package.json`, `requirements.txt`, `poetry.lock`, `uv.lock`, `Cargo.lock`, `go.mod`) and check everything found.
- `check_technologies` — keyword watch for what is not a package ("PostgreSQL", "nginx", "Windows Server"): CERT-FR bulletins and exploited vulnerabilities.
- `vulnerability_details` — everything known about one id (CVE, GHSA…).
- `list_sources`.

## Install

Clone this repository, then:

**1. Connect the MCP server** (Claude Code):

```sh
claude mcp add vigie -- node /absolute/path/to/vigie/src/server.mjs
```

Any MCP client works: the command is `node /absolute/path/to/vigie/src/server.mjs` (stdio).

**2. Make the check mandatory** with the hook. In `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "node /absolute/path/to/vigie/bin/vigie-hook.mjs", "timeout": 60 }] }
    ],
    "PostToolUse": [
      { "matcher": "Edit|Write|MultiEdit", "hooks": [{ "type": "command", "command": "node /absolute/path/to/vigie/bin/vigie-hook.mjs", "timeout": 60 }] }
    ]
  }
}
```

- Before any `npm install x`, `pnpm add`, `yarn add`, `pip install`, `uv add`, `poetry add`: the packages are checked, and the install is **blocked** if one has a high-priority known vulnerability or is malicious. The agent receives the report and the fix.
- After any edit of a dependency file: the project is checked and the agent is told what to fix.
- If the databases are unreachable the hook lets the command through. Set `VIGIE_STRICT=1` to block instead.

**3. Add the rule** to your agent instructions (`CLAUDE.md`, `AGENTS.md`…):

```
Before adding or upgrading a dependency, call Vigie `check_packages` with the exact version.
Before saying a task is done, if dependency files changed, call Vigie `check_project`.
A "vulnerable" verdict must be fixed or explained to me. An "incomplete" verdict must be told to me.
```

## Limits — read this

- Vigie only knows **publicly disclosed** vulnerabilities in **published packages**. It does not find flaws in your own code, misconfiguration, or vulnerabilities nobody has reported yet.
- CERT-FR only exposes its latest bulletins: `check_technologies` matches product names, not your exact version, and an empty answer proves nothing.
- With `package.json` alone (no lockfile), indirect dependencies are not checked. Vigie says so in the report.
- The first call of the day downloads the catalogues (about 30 seconds); results are cached in `~/.cache/vigie` afterwards.
- What leaves your machine: package names and versions, sent to the public APIs above. Never your code.

## Tests

```sh
npm test
```

---

## En français

Vigie oblige votre agent de code à vérifier les failles connues, à chaque fois, dans plusieurs bases publiques : OSV.dev (Google), CISA KEV (failles réellement exploitées), EPSS (probabilité d'exploitation) et le CERT-FR (ANSSI).

L'agent donne les noms et versions des briques utilisées ; Vigie répond ce qui ne va pas, à quel point c'est urgent et quoi faire. Sans compte, sans clé, gratuit, sans aucune dépendance.

Trois gestes : brancher le connecteur, poser le crochet qui bloque l'installation d'une brique dangereuse, ajouter la règle dans les consignes de l'agent (voir « Install » ci-dessus).

Limites : seules les failles publiques des briques publiées sont couvertes — pas les erreurs de votre propre code, pas les mauvais réglages, pas les failles encore inconnues.

## License

MIT
