# @haskou/pigeon-swarm-crypto

Cryptographic primitives, key handling, and wire-format compatibility for Pigeon Swarm.

This package is intentionally Pigeon Swarm-specific. It depends on `@haskou/value-objects` for generic representation types; `@haskou/value-objects` must never depend on this package.

## Status

Bootstrap only. Cryptographic behavior will be migrated from `@haskou/value-objects` in reviewable follow-up pull requests.

## Development

```bash
yarn install
yarn test
yarn test:coverage
yarn build
```

## Release flow

Pull requests merged from `fix/*`, `feat/*`, and `break/*` branches publish patch, minor, and major releases respectively, matching the release flow used by `@haskou/value-objects`. Other branch prefixes run CI without publishing.

The initial version is `0.0.0`; the first merged `feat/*` release becomes `0.1.0`.

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE.txt](LICENSE.txt).
