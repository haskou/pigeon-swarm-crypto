const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { builtinModules } = require('node:module');

// Bundlers resolve every bare import left in the MLS bundles. One the package
// neither depends on nor declares as an optional peer fails the consumer's
// build, even when only an unused cipher suite would load it.
const manifest = JSON.parse(readFileSync('package.json', 'utf8'));
const dependencies = new Set(Object.keys(manifest.dependencies ?? {}));
const peers = manifest.peerDependencies ?? {};
const peerMeta = manifest.peerDependenciesMeta ?? {};
const builtins = new Set(builtinModules);
const specifier =
  /(?:\bimport\(|\bfrom |\brequire\()\s*["']([^"'./][^"']*)["']/g;

const packageName = (id) =>
  id.startsWith('@') ? id.split('/').slice(0, 2).join('/') : id.split('/')[0];

const importsOf = (source) =>
  new Set([...source.matchAll(specifier)].map(([, id]) => id));

// The scanner must see every form a bundler or minifier leaves behind, so an
// undeclared package cannot hide behind spacing or a side-effect import.
assert.deepEqual(
  [
    ...importsOf(
      [
        'import "side-effect";',
        'import"minified-side-effect";',
        'import { a } from "spaced";',
        'import{b}from"minified";',
        'export*from"re-exported";',
        "import x from 'single-quoted';",
        'await import("dynamic");',
        'await import ( "spaced-dynamic" );',
        'require("required");',
        'require ( "spaced-required" );',
        'import "@scope/side-effect/deep";',
        'import "node:crypto";',
        'import "./relative";',
        'Array.from("text");',
        'new Error("read from" + x + "here");',
      ].join('\n'),
    ),
  ].sort(),
  [
    '@scope/side-effect/deep',
    'dynamic',
    'minified',
    'minified-side-effect',
    'node:crypto',
    're-exported',
    'required',
    'side-effect',
    'single-quoted',
    'spaced',
    'spaced-dynamic',
    'spaced-required',
  ],
);

for (const name of Object.keys(peerMeta)) {
  assert.ok(peers[name], `${name} has peer metadata but is not a peer`);
}

for (const bundle of ['dist/mls/index.mjs', 'dist/mls/index.cjs']) {
  const imported = importsOf(readFileSync(bundle, 'utf8'));

  for (const id of imported) {
    const name = packageName(id.replace(/^node:/, ''));

    if (builtins.has(name)) continue;
    assert.ok(
      dependencies.has(name) || peers[name],
      `${bundle} imports ${id}, which package.json does not declare`,
    );
  }
}

console.log('MLS bundle imports are declared');
