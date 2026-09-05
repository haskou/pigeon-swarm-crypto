# Working agreement

- Write commits, PRs and documentation in English. Use conventional commits and
  PR titles with gitmoji, following existing repository history.
- Preserve user changes and secrets. Do not add local `.npmrc` files to commits.
- Keep explanations in documentation; avoid unnecessary comments in code.
- Keep cryptographic behavior in this package and generic value types in
  `@haskou/value-objects`. Never introduce the reverse dependency.
- Preserve persisted formats, authenticated data and derivation contexts unless
  an explicitly versioned migration covers existing data.
- Follow [CONTRIBUTING.md](CONTRIBUTING.md) for verification and release branches.
- Read the relevant managed skill under `.agents/skills/`: `ddd-engineer` for
  boundaries and review, and `haskou-value-objects` for value semantics.
- Update managed skills with `npx github:haskou/ddd-engineer-skills update`; keep
  their manifest and files together, without overwriting local modifications.
- Keep architecture, cryptographic changes and final verification with the
  primary reviewer. Read-only inventory and mechanical investigations may be
  delegated to the local Pi worker.
