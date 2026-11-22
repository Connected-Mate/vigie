# Security

## Reporting a problem in Vigie

Please do not open a public issue for a security problem in Vigie itself. Use GitHub's private reporting: the **Security** tab of https://github.com/Connected-Mate/vigie → **Report a vulnerability**. You should get an answer within a week.

Useful to include: the version (`vigie --version`), what you did, what happened, what you expected.

## What Vigie does on your machine

- It runs with your user's rights and has **no dependency**: what you clone is all that runs.
- It reads dependency files (lockfiles, manifests) in the folder you point it at. It never reads your source code, and never follows symbolic links out of the project.
- It sends **package names and versions** to these public services, over HTTPS, without any account or key: `api.osv.dev`, `www.cisa.gov`, `api.first.org`, `www.cert.ssi.gouv.fr`, `api.deps.dev`, and — only to work out which version an install would bring — `registry.npmjs.org` and `pypi.org`. Nothing else leaves the machine: no code, no file path, no telemetry.
- It writes only to its cache folder (`~/.cache/vigie`, or `VIGIE_CACHE_DIR`), and, when you run `vigie setup`, to the agent configuration files that command lists on screen.
- Text coming back from the databases is shown to the agent as data inside a report. Vigie never executes anything it downloads.

## What Vigie is not

A guardrail, not a sandbox, and not a code review. It knows publicly disclosed vulnerabilities in published packages; see "Limits" in the README.
