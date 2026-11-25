# Vigie — setup instructions for coding agents

> You are a coding agent (Claude Code, Codex, Cursor, Gemini CLI, Copilot, Windsurf/Devin…).
> A person pasted a prompt asking you to install Vigie. Follow these steps in order.
> The person may not be technical: speak plainly, ask only what is strictly needed,
> and **ask before any sensitive action** (password prompt, admin rights, deleting or overwriting files,
> sending data anywhere). Never print, log or store secrets.

## 0. What Vigie is

Vigie is a lookout for known vulnerabilities. It gives you (the agent) five tools to check package versions against public databases (OSV.dev, CISA KEV, EPSS, CERT-FR; plus deps.dev for release signals when single packages are checked or installed), and a hook that stops you before you install a package with a serious known vulnerability, then checks the project after each install.

What it changes on the machine:
- one folder with Vigie's code: `~/.vigie`, or the folder the `VIGIE_HOME` variable names when it is already set (about half a megabyte, no dependency to install);
- in the project you are in: an MCP server entry, a hook entry and a short rule block in the agent's instruction file. Nothing else in the project is touched, and its code is never modified;
- a cache of public vulnerability data in `~/.cache/vigie` (or the folder `VIGIE_CACHE_DIR` names when it is set).

What leaves the machine: package names and versions, sent to those public databases. Never code, file paths or personal data. No account, no API key.

## 1. Check prerequisites

- Node.js 18 or later: `node --version` → `v18.0.0` or higher.
- git 2.25 or later: `git --version`.
- Internet access to the public databases: `node -e "fetch('https://api.osv.dev/v1/vulns/GHSA-35jh-r3h4-6jhm').then(r=>console.log(r.status))"` → `200`.

If something is missing, explain it in one sentence and offer to install it (ask first). If the network check fails behind a company proxy, say so: Vigie cannot work without reaching these databases, and will answer "INCOMPLETE" rather than "all clear".

## 2. Install

Idempotent: running it twice updates Vigie instead of breaking anything.

```sh
VIGIE_HOME="${VIGIE_HOME:-$HOME/.vigie}"; echo "Vigie's folder: $VIGIE_HOME"
if [ -d "$VIGIE_HOME/.git" ]; then git -C "$VIGIE_HOME" pull --ff-only; else git clone --depth 1 --filter=blob:none --sparse https://github.com/Connected-Mate/vigie "$VIGIE_HOME" && git -C "$VIGIE_HOME" sparse-checkout set bin src; fi
node "$VIGIE_HOME/bin/vigie.mjs" --version
```

Expected: the folder, then a version number such as `1.0.0`. There is nothing to `npm install`.

**Run this block as it is written; do not shorten it to `~/.vigie`.** When `VIGIE_HOME` is already set in your environment, the person (or their company) chose that folder for Vigie and the first line keeps it. `~/.vigie` is only the default when nothing is set. If Vigie prints `Warning: VIGIE_HOME is set to …`, it was put in another folder than the chosen one: install it in the chosen folder and use that one.

The clone brings only the program (`bin/`, `src/` and the files at the root of the repository), about half a megabyte; the website and the videos stored in the same repository are left out. If git refuses `--sparse` or `--filter`, it is older than 2.25: offer to update it, or use a plain `git clone --depth 1 https://github.com/Connected-Mate/vigie "$VIGIE_HOME"` and tell the person it takes about 40 MB.

`VIGIE_HOME` is a plain shell variable: if your shell does not keep variables between commands, run the first line of the block again at the start of each command below, or write the full path it printed.

## 3. Configure

**First look at the folder you are working in.** Run:

```sh
node "$VIGIE_HOME/bin/vigie.mjs" check . ; echo "exit=$?"
```

Exit code of `check`: `0` = nothing serious, `1` = serious findings (this is a result, not a failed step), `2` = the check could not be completed.

- **Path A — the folder is a project with dependency files** (the report starts with `Project:` and lists files such as `package-lock.json`, `requirements.txt`, `uv.lock`, `Cargo.lock`, `go.mod`…): install Vigie on top of it, without changing its code, then show the person their own project's report (step 4).
- **Path B — no dependency file** (the report says `No dependency file found` and `VERDICT: INCOMPLETE — nothing to check in this folder`): tell the person plainly that this folder has no project Vigie can check, and offer two things: a demonstration check (step 4, path B), and installing Vigie for all their projects (`--user` below) so it is ready when they open one. Do not create a project they did not ask for.

Then connect Vigie to the agent. Choices made for you: project-level by default (only this project changes; easy to review and undo). Use `--user` only if the person wants Vigie in all their projects — ask them, because it edits their personal agent settings.

### Claude Code (tested end to end)

```sh
node "$VIGIE_HOME/bin/vigie.mjs" setup claude            # this project
node "$VIGIE_HOME/bin/vigie.mjs" setup claude --user     # or: all projects (then run the `claude mcp add` line it prints)
```

It writes, without touching anything else already there:
- `.mcp.json` → the `vigie` MCP server (`node …/src/server.mjs`);
- `.claude/settings.json` → the hook, before `Bash` and after `Bash|Edit|Write|MultiEdit`;
- `CLAUDE.md` → a short rule block (a heading and four rules) between `<!-- vigie:start -->` and `<!-- vigie:end -->`.

Tell the person to restart Claude Code in this folder and accept the "new MCP server" question once. `claude mcp list`, run from the project folder, must then show `vigie`.

Last run on 2026-11-25 with Claude Code 2.1.332 on macOS: a headless agent given the prompt of the website followed this guide from the public repository, in a project with dependency files and in an empty folder; a second session in that project then listed the `vigie` server as connected and was stopped by the hook on `npm install lodash@4.17.20`. Not run inside an agent on Windows or Linux (the tests run there in CI).

### Gemini CLI and Cursor (configuration format checked against their documentation on 2026-11-22; not run inside these agents)

```sh
node "$VIGIE_HOME/bin/vigie.mjs" setup gemini    # .gemini/settings.json (mcpServers + BeforeTool hook) and GEMINI.md
node "$VIGIE_HOME/bin/vigie.mjs" setup cursor    # .cursor/mcp.json, .cursor/hooks.json (beforeShellExecution) and AGENTS.md
```

### Codex CLI (MCP server seen and called by Codex 0.165 in a test; hook not run)

```sh
codex mcp add vigie -- node "$VIGIE_HOME/src/server.mjs"
```

Hook, in `~/.codex/config.toml` (Codex asks the person to review and trust it with `/hooks` before it runs):

```toml
[[hooks.PreToolUse]]
matcher = "^Bash$"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "node /absolute/path/to/.vigie/bin/vigie-hook.mjs"
timeout = 30
```

Add the rule block of step "Rule" below to `AGENTS.md`.

### GitHub Copilot (format checked against the documentation; not run)

- Copilot CLI: `copilot mcp add vigie -- node "$VIGIE_HOME/src/server.mjs"`
- VS Code: `.vscode/mcp.json` → `{ "servers": { "vigie": { "type": "stdio", "command": "node", "args": ["/absolute/path/to/.vigie/src/server.mjs"] } } }`
- Hook: `.github/hooks/vigie.json` → `{ "version": 1, "hooks": { "preToolUse": [ { "type": "command", "bash": "node /absolute/path/to/.vigie/bin/vigie-hook.mjs", "timeoutSec": 30 } ] } }`
- Rule block in `.github/copilot-instructions.md`.

### Windsurf / Devin Desktop (format checked against the documentation; not run)

- `devin mcp add vigie -- node "$VIGIE_HOME/src/server.mjs"`, or `.devin/mcp_config.json` → `{ "mcpServers": { "vigie": { "command": "node", "args": ["/absolute/path/to/.vigie/src/server.mjs"] } } }`
- Hook: `.devin/hooks.v1.json` → `{ "PreToolUse": [ { "matcher": "exec", "hooks": [ { "type": "command", "command": "node /absolute/path/to/.vigie/bin/vigie-hook.mjs" } ] } ] }`
- Rule block in `AGENTS.md`.

### Any other MCP client

The server is `node /absolute/path/to/.vigie/src/server.mjs` (stdio, no environment variable needed). The hook is `node /absolute/path/to/.vigie/bin/vigie-hook.mjs`: it reads the tool event as JSON on standard input and answers with exit code 2 and a message on standard error when the command must be stopped.

### Rule (when you add it by hand)

```
## Vigie — known vulnerabilities
- Before adding or upgrading a dependency, call the Vigie tool `check_packages` with the exact version.
- Before saying a task is done, if dependency files changed, call Vigie `check_project` on the project folder.
- A "vulnerable" verdict must be fixed or explained to me. An "incomplete" verdict must be told to me: never present unchecked packages as safe.
- Never edit `.vigieignore` yourself: accepting a known risk is my decision.
```

### Optional settings (only if the person asks)

- `VIGIE_STRICT=1` in the hook's environment: block installs when the databases cannot be reached (default: let them through and say so).
- `VIGIE_CACHE_DIR`: another folder for the cache. It must be set in the environment the agent starts the hook and the server with (for example the `env` block of the agent's settings); setting it only while running `setup` is not enough.
- `.vigieignore` in a project: one advisory id (`GHSA-…`, `CVE-…`) or `name@version` per line, for a risk the person has decided to accept. Accepted entries stay listed in every report. Never add one yourself.

## 4. Prove it works

1. **The hook stops a dangerous install** (nothing is installed by this test):

   ```sh
   echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"'"$PWD"'","tool_input":{"command":"npm install lodash@4.17.20"}}' | node "$VIGIE_HOME/bin/vigie-hook.mjs"; echo "exit=$?"
   ```

   Expected: a message starting with `Vigie blocked this command`, then `exit=2`.

2. **The MCP server answers:**

   ```sh
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"check","version":"1"}}}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | node "$VIGIE_HOME/src/server.mjs" | grep -o '"name":"[a-z_]*"'
   ```

   Expected: `vigie`, then the five tools `check_packages`, `check_project`, `check_technologies`, `vulnerability_details`, `list_sources`.

3. **The report.**
   - Path A: run `node "$VIGIE_HOME/bin/vigie.mjs" check .` and show the person the verdict line of their own project, the packages marked `[ACT NOW]` or `[HIGH]` with their "What to do" line, and offer to apply the fixes (do not change their dependency files without their yes). The labels are priorities for action, not raw severities: `[ACT NOW]` = exploited in real attacks, malicious package or open CERT-FR alert; `[HIGH]` = critical or high severity, or a high exploit probability; then `[MEDIUM]` and `[LOW]`.
   - Path B: run `node "$VIGIE_HOME/bin/vigie.mjs" check npm:lodash@4.17.20` as a demonstration. Expected: `VERDICT: 4 known vulnerabilities in 1 of 1 package version(s)` (the count can grow over time) and a `What to do: Upgrade lodash to …` line.

Report to the person in one or two plain sentences: what is installed and where (the real folders: `setup` prints `Vigie's code is in …`, and the cache is in `~/.cache/vigie` unless `VIGIE_CACHE_DIR` is set), that their agent will now be stopped before installing a package with a serious known vulnerability, what the check of their project found, and how to remove it (step 5). Say clearly that Vigie only knows publicly disclosed vulnerabilities in published packages: it does not review their own code.

## 5. Uninstall

```sh
node "$VIGIE_HOME/bin/vigie.mjs" setup claude --remove          # in each project where it was set up (or gemini / cursor)
node "$VIGIE_HOME/bin/vigie.mjs" setup claude --user --remove   # if it was set up for all projects; then: claude mcp remove --scope user vigie
```

Then, after asking the person (these delete folders): remove `~/.vigie` (the code, or the folder `VIGIE_HOME` pointed to) and `~/.cache/vigie` (the cache, or the folder `VIGIE_CACHE_DIR` pointed to). For agents configured by hand, remove the `vigie` entries and the rule block you added.

## Troubleshooting

- **`VERDICT: INCOMPLETE`** → a database could not be reached, or the folder has no dependency file. The "Sources" lines of the report name what failed. Check the network, then run again. Never tell the person the project is safe on an incomplete verdict.
- **`Vigie could not check … Not blocked`** shown by the hook → same cause; the install went through unverified. Run `check_project` once the network is back.
- **Claude Code does not show the Vigie tools** → restart it in the project folder and accept the project MCP server; `claude mcp list`, run from that folder, must show `vigie`.
- **`… is not valid JSON: fix or move it first`** during setup → an existing settings file is broken. Vigie never overwrites it, and nothing at all was written by that run: show the person, fix the file with them, run setup again.
- **`Warning: VIGIE_HOME is set to …, but this Vigie runs from …`** → Vigie was installed in another folder than the one chosen with `VIGIE_HOME`. Install it in the chosen folder (step 2), run `setup` again from there, and offer to delete the other copy (ask first).
- **The hook blocks a package the person really wants** → explain the finding to them. If they accept the risk, they add the advisory id to `.vigieignore` themselves (or tell you explicitly to do it).
- **Company proxy or offline machine** → Vigie needs `api.osv.dev`, `www.cisa.gov`, `api.first.org`, `www.cert.ssi.gouv.fr`, `api.deps.dev`, and for installs `registry.npmjs.org` / `pypi.org`.
