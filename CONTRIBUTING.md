# Contributing

Thank you for looking. Vigie is small on purpose: plain Node.js (18+), no dependency, readable in one sitting.

## Run it

```sh
git clone https://github.com/Connected-Mate/vigie && cd vigie
npm test                              # offline, no network, nothing to install
node bin/vigie.mjs check npm:lodash@4.17.20
```

## Before a pull request

- `npm test` passes, and what you change comes with a test. Tests never touch the network: answers from the databases are simulated.
- No new dependency. If something needs one, open an issue first.
- A report must stay honest: when a source cannot be reached, Vigie says so and never concludes "all clear".
- Documentation states only what was really run. "Checked against the documentation, not run" is a fine label; a guess is not.

## Where things are

- `src/providers/` — one file per source (OSV.dev, CISA KEV, EPSS, CERT-FR, deps.dev). Adding a source is one file.
- `src/projet.mjs` — reading dependency files. `src/versions.mjs` — version ordering per ecosystem.
- `src/analyse.mjs` — priorities and the report. `src/server.mjs` — the MCP server.
- `bin/vigie-hook.mjs` — the hook. `bin/vigie.mjs` — the command line. `src/setup.mjs` — `vigie setup`.
- `marketing/site/` builds the site into `docs/` (`python3 marketing/site/build_site.py`); `docs/` is not edited by hand.

## Reporting

- A bug or an idea: [open an issue](https://github.com/Connected-Mate/vigie/issues).
- A security problem in Vigie itself: not in a public issue, see [SECURITY.md](SECURITY.md).

By contributing you agree that your contribution is released under the [MIT license](LICENSE).
