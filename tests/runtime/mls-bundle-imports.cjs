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

for (const name of Object.keys(peerMeta)) {
  assert.ok(peers[name], `${name} has peer metadata but is not a peer`);
}

for (const bundle of ['dist/mls/index.mjs', 'dist/mls/index.cjs']) {
  const imported = new Set(
    [...readFileSync(bundle, 'utf8').matchAll(specifier)].map(([, id]) => id),
  );

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
