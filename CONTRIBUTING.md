# Contributing

Keep changes focused on Pigeon Swarm cryptographic behavior, public API boundaries
and compatibility. Generic value validation belongs in `value-objects`. Preserve
existing wire formats unless the change includes an explicit migration.

## Validation

Run focused tests first, then `yarn lint`, `yarn test:coverage` and `yarn build`.
CI enforces complete statement, branch, function and line coverage. Coverage is a
regression check, not a security audit.

For cryptographic changes, include known-answer or interoperability tests and
negative cases for tampered data, incorrect keys and invalid parameters. Verify
public package exports and browser consumers when changing packaging or runtime
dependencies. Keep old implementation dependencies confined to tests.

Document the affected format, backwards compatibility, limits and validation in
the pull request. Use English and the repository's conventional title format, for
example `fix(crypto): 🐛 Preserve protected-key compatibility`.

## Release process

The CI workflow publishes queued merged PRs according to their source branches:
`fix/*` produces a patch release, `feat/*` a minor release and `break/*` a major
release. Other branch prefixes run checks without adding a release to the queue.

Publishing uses npm Trusted Publishing for `haskou/pigeon-swarm-crypto` and
`.github/workflows/ci.yml`. Confirm that the npm package trusts this repository,
not another package's repository. A failed publication can leave a version tag;
the workflow resumes that version rather than replacing an existing npm release.

After publication, verify the npm version and its public exports before updating
consumers. Do not assume a merged PR or a Git tag means a package is available.
