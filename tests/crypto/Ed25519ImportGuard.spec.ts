import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import * as ts from 'typescript';

const sourceRoot = join(__dirname, '..', '..', 'src');
const adapter = join('internal', 'CryptoAdapter.ts');
const bindingModule = /^@noble\/curves\/ed25519(\.js)?$/;
const curveModule = /curve|ed25519/;
const curveText = /ed25519|curve|@noble/;
const allowedName = 'x25519';

const exportedName = (
  element: ts.ImportSpecifier | ts.ExportSpecifier,
): string => (element.propertyName ?? element.name).text;

const allowedDeclaration = (
  node: ts.ImportDeclaration | ts.ExportDeclaration,
): boolean => {
  if (!bindingModule.test(moduleSpecifierOf(node) ?? '')) return false;

  if (ts.isImportDeclaration(node)) {
    const clause = node.importClause;
    const named = clause?.namedBindings;

    return (
      clause !== undefined &&
      clause.name === undefined &&
      named !== undefined &&
      ts.isNamedImports(named) &&
      named.elements.length > 0 &&
      named.elements.every((element) => exportedName(element) === allowedName)
    );
  }

  const clause = node.exportClause;

  return (
    clause !== undefined &&
    ts.isNamedExports(clause) &&
    clause.elements.length > 0 &&
    clause.elements.every((element) => exportedName(element) === allowedName)
  );
};

const moduleSpecifierOf = (
  node: ts.ImportDeclaration | ts.ExportDeclaration,
): string | undefined =>
  node.moduleSpecifier !== undefined && ts.isStringLiteral(node.moduleSpecifier)
    ? node.moduleSpecifier.text
    : undefined;

const isStringLike = (
  node: ts.Node,
): node is
  | ts.StringLiteralLike
  | ts.TemplateHead
  | ts.TemplateMiddle
  | ts.TemplateTail =>
  ts.isStringLiteralLike(node) ||
  ts.isTemplateHead(node) ||
  ts.isTemplateMiddle(node) ||
  ts.isTemplateTail(node);

const isLiteralSpecifier = (call: ts.CallExpression): boolean => {
  const [specifier] = call.arguments;

  return specifier !== undefined && ts.isStringLiteralLike(specifier);
};

const isLiteralRequire = (identifier: ts.Identifier): boolean =>
  ts.isCallExpression(identifier.parent) &&
  identifier.parent.expression === identifier &&
  isLiteralSpecifier(identifier.parent);

const unsafeNames: Record<string, true> = {
  eval: true,
  Function: true,
  createRequire: true,
  _load: true,
  getBuiltinModule: true,
  runInThisContext: true,
  runInNewContext: true,
  runInContext: true,
  compileFunction: true,
};
const unsafeStrings: Record<string, true> = {
  ...unsafeNames,
  require: true,
};
const forbiddenModules: Record<string, true> = {
  vm: true,
  'node:vm': true,
  module: true,
  'node:module': true,
};
const loaderRoots: Record<string, true> = {
  globalThis: true,
  global: true,
  self: true,
  window: true,
  process: true,
  module: true,
  Module: true,
  require: true,
};

const isUnsafeName = (text: string): boolean =>
  Object.hasOwn(unsafeNames, text) || text === 'require';

// `.constructor` reaches the Function constructor from any function value.
const isConstructorAccess = (identifier: ts.Identifier): boolean =>
  identifier.text === 'constructor' &&
  ts.isPropertyAccessExpression(identifier.parent) &&
  identifier.parent.name === identifier;

const isLoaderCall = (call: ts.CallExpression): boolean =>
  call.expression.kind === ts.SyntaxKind.ImportKeyword ||
  (ts.isIdentifier(call.expression) && call.expression.text === 'require');

const isForbiddenModuleCall = (call: ts.CallExpression): boolean => {
  const [specifier] = call.arguments;

  return (
    isLoaderCall(call) &&
    specifier !== undefined &&
    ts.isStringLiteralLike(specifier) &&
    Object.hasOwn(forbiddenModules, specifier.text)
  );
};

const isUnsafeReference = (identifier: ts.Identifier): boolean =>
  isUnsafeName(identifier.text) &&
  !(identifier.text === 'require' && isLiteralRequire(identifier));

// Names an import or export brings into or out of the module scope.
const importedNames = (
  node: ts.ImportDeclaration | ts.ExportDeclaration,
): string[] => {
  if (ts.isImportDeclaration(node)) {
    const clause = node.importClause;
    const named =
      clause?.namedBindings !== undefined &&
      ts.isNamedImports(clause.namedBindings)
        ? clause.namedBindings.elements
        : [];

    return [
      ...(clause?.name !== undefined ? [clause.name.text] : []),
      ...named.map((element) => (element.propertyName ?? element.name).text),
    ];
  }

  const clause = node.exportClause;

  return clause !== undefined && ts.isNamedExports(clause)
    ? clause.elements.map(
        (element) => (element.propertyName ?? element.name).text,
      )
    : [];
};

const isVerifyCall = (identifier: ts.Identifier): boolean => {
  const access = identifier.parent;

  if (
    !ts.isPropertyAccessExpression(access) &&
    !ts.isElementAccessExpression(access)
  )
    return false;
  if (
    access.expression !== identifier ||
    !ts.isCallExpression(access.parent) ||
    access.parent.expression !== access
  )
    return false;

  return ts.isPropertyAccessExpression(access)
    ? access.name.text === 'verify'
    : ts.isStringLiteralLike(access.argumentExpression) &&
        access.argumentExpression.text === 'verify';
};

// Counts uses of the adapter's ed25519 binding. Calls to `.verify` (by dot or
// string index) are counted as verify calls. Other `ed25519.<member>` accesses
// are listed by member name. Any other use, such as destructuring or passing
// the binding as a value, is counted as bare.
const memberOf = (identifier: ts.Identifier): string | undefined => {
  const access = identifier.parent;

  if (
    ts.isPropertyAccessExpression(access) &&
    access.expression === identifier
  ) {
    // Two levels deep for namespaces such as `ed25519.utils.toMontgomery`.
    const outer = access.parent;

    return ts.isPropertyAccessExpression(outer) && outer.expression === access
      ? `${access.name.text}.${outer.name.text}`
      : access.name.text;
  }
  if (
    ts.isElementAccessExpression(access) &&
    access.expression === identifier &&
    ts.isStringLiteralLike(access.argumentExpression)
  )
    return access.argumentExpression.text;

  return undefined;
};

export const ed25519Uses = (
  fileName: string,
  source: string,
): {
  verifyCalls: number;
  members: string[];
  bare: number;
  verifyOptions: string[];
} => {
  const sourceFile = ts.createSourceFile(
    fileName,
    source,
    ts.ScriptTarget.Latest,
    true,
  );
  const uses = {
    verifyCalls: 0,
    members: [] as string[],
    bare: 0,
    verifyOptions: [] as string[],
  };
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node)) return;

    if (
      ts.isIdentifier(node) &&
      node.text === 'ed25519' &&
      !(ts.isPropertyAccessExpression(node.parent) && node.parent.name === node)
    ) {
      const member = memberOf(node);

      if (isVerifyCall(node)) {
        uses.verifyCalls += 1;
        const call = node.parent.parent as ts.CallExpression;
        uses.verifyOptions.push(call.arguments[3]?.getText(sourceFile) ?? '');
      } else if (member === undefined) uses.bare += 1;
      else uses.members.push(member);
    }

    ts.forEachChild(node, visit);
  };

  visit(sourceFile);

  return uses;
};

// The names the adapter imports from @noble/curves, one entry per clause
// element as written. Aliases, default and namespace imports all appear, so
// the adapter test can require the exact list.
export const adapterImportNames = (source: string): string[] => {
  const sourceFile = ts.createSourceFile(
    'adapter.ts',
    source,
    ts.ScriptTarget.Latest,
    true,
  );

  return sourceFile.statements
    .filter(ts.isImportDeclaration)
    .filter((node) => bindingModule.test(moduleSpecifierOf(node) ?? ''))
    .flatMap((node) => {
      const clause = node.importClause;
      const named = clause?.namedBindings;
      const defaultName =
        clause?.name !== undefined ? [`default ${clause.name.text}`] : [];

      if (named === undefined) return defaultName;
      if (ts.isNamespaceImport(named)) return [...defaultName, 'namespace'];

      return [
        ...defaultName,
        ...named.elements.map((element) => element.getText(sourceFile)),
      ];
    });
};

// Outside the adapter, the only permitted reference to @noble/curves' ed25519
// module is a static import or re-export of x25519. Rejected routes: a module
// name in a string; an import, export or require of `node:vm` or `module`; an
// import or export naming `require`, `createRequire`, `eval`, `Function`,
// `_load`, `getBuiltinModule` or a vm run method; a `require` reference other
// than a direct call with a string-literal specifier; a bare `createRequire`,
// `eval`, `Function`, `_load`, `getBuiltinModule` or `.constructor` identifier;
// the same names as string literals (for example `module['require']`); a
// computed key on a loader root such as `module[name]`; and `import()` with a
// non-literal specifier. This is a static text scan. Computed access through a
// value it cannot resolve is out of its reach.
export const ed25519Violations = (
  fileName: string,
  source: string,
): string[] => {
  const sourceFile = ts.createSourceFile(
    fileName,
    source,
    ts.ScriptTarget.Latest,
    true,
  );
  const violations: string[] = [];
  const report = (node: ts.Node): void => {
    const position = sourceFile.getLineAndCharacterOfPosition(
      node.getStart(sourceFile),
    );

    const entry = `${fileName}:${position.line + 1}`;
    if (!violations.includes(entry)) violations.push(entry);
  };
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      const specifier = moduleSpecifierOf(node);

      if (
        specifier !== undefined &&
        curveModule.test(specifier) &&
        !allowedDeclaration(node)
      )
        report(node);
      if (specifier !== undefined && Object.hasOwn(forbiddenModules, specifier))
        report(node);

      if (importedNames(node).some(isUnsafeName)) report(node);

      return;
    }

    if (
      ts.isIdentifier(node) &&
      (isUnsafeReference(node) || isConstructorAccess(node))
    )
      report(node);

    if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword &&
      !isLiteralSpecifier(node)
    )
      report(node);

    if (ts.isCallExpression(node) && isForbiddenModuleCall(node)) report(node);

    if (
      ts.isElementAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      Object.hasOwn(loaderRoots, node.expression.text) &&
      !ts.isStringLiteralLike(node.argumentExpression)
    )
      report(node);

    if (isStringLike(node) && curveText.test(node.text)) report(node);

    if (
      ts.isStringLiteralLike(node) &&
      (Object.hasOwn(unsafeStrings, node.text) || node.text === 'constructor')
    )
      report(node);

    ts.forEachChild(node, visit);
  };

  visit(sourceFile);

  return violations;
};

const sourceFiles = (): string[] =>
  readdirSync(sourceRoot, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && /\.[cm]?[jt]sx?$/.test(entry.name))
    .map((entry) => relative(sourceRoot, join(entry.parentPath, entry.name)));

const sourceOf = (file: string): string =>
  readFileSync(join(sourceRoot, file), 'utf8');

describe('Ed25519 import allowlist', () => {
  it('lets only the adapter reach the ed25519 binding', () => {
    const violations = sourceFiles()
      .filter((file) => file !== adapter)
      .flatMap((file) => ed25519Violations(file, sourceOf(file)));

    expect(violations).toEqual([]);
  });

  it('pins the adapter import to exactly { ed25519, x25519 }', () => {
    expect(adapterImportNames(sourceOf(adapter))).toEqual([
      'ed25519',
      'x25519',
    ]);
  });

  describe('adapter verify call count (AST)', () => {
    const adapterMembers = [
      'getPublicKey',
      'sign',
      'Point.fromBytes',
      'utils.randomSecretKey',
      'utils.toMontgomery',
      'utils.toMontgomerySecret',
    ];

    it.each([
      [
        'plain call with options',
        'ed25519.verify(a, b, c, { zip215: false });',
        {
          verifyCalls: 1,
          members: [],
          bare: 0,
          verifyOptions: ['{ zip215: false }'],
        },
      ],
      [
        'element access call with options',
        "ed25519['verify'](a, b, c, { zip215: false });",
        {
          verifyCalls: 1,
          members: [],
          bare: 0,
          verifyOptions: ['{ zip215: false }'],
        },
      ],
      [
        'verify without options',
        'ed25519.verify(a, b, c);',
        { verifyCalls: 1, members: [], bare: 0, verifyOptions: [''] },
      ],
      [
        'allowlisted member call',
        'ed25519.sign(a, b);',
        { verifyCalls: 0, members: ['sign'], bare: 0, verifyOptions: [] },
      ],
      [
        'allowlisted member pair',
        'ed25519.utils.toMontgomery(a);',
        {
          verifyCalls: 0,
          members: ['utils.toMontgomery'],
          bare: 0,
          verifyOptions: [],
        },
      ],
      [
        'comment only',
        '// ed25519.verify(a, b, c);',
        { verifyCalls: 0, members: [], bare: 0, verifyOptions: [] },
      ],
      [
        'destructured alias',
        'const { verify } = ed25519;',
        { verifyCalls: 0, members: [], bare: 1, verifyOptions: [] },
      ],
      [
        'detached reference',
        'const check = ed25519.verify;',
        { verifyCalls: 0, members: ['verify'], bare: 0, verifyOptions: [] },
      ],
      [
        'passed as a value',
        'use(ed25519);',
        { verifyCalls: 0, members: [], bare: 1, verifyOptions: [] },
      ],
    ])('%s', (_label, source, counts) => {
      expect(ed25519Uses('fixture.ts', source)).toEqual(counts);
    });

    it('pins the adapter to the allowlisted member pairs and one zip215-off verify', () => {
      const uses = ed25519Uses(adapter, sourceOf(adapter));
      const members = [...new Set(uses.members)].sort();

      expect(uses.verifyCalls).toBe(1);
      expect(uses.verifyOptions).toEqual(['{ zip215: false }']);
      expect(uses.bare).toBe(0);
      expect(members).toEqual([...adapterMembers].sort());
    });
  });

  it.each([
    [
      'named x25519 import',
      "import { x25519 } from '@noble/curves/ed25519.js';",
      [],
    ],
    [
      'aliased x25519 import',
      "import { x25519 as dh } from '@noble/curves/ed25519';",
      [],
    ],
    [
      'x25519 re-export',
      "export { x25519 } from '@noble/curves/ed25519.js';",
      [],
    ],
    [
      'aliased createRequire import',
      "import { createRequire as cr } from 'node:module';",
      [1],
    ],
    [
      'Function constructor',
      "const make = new Function('return require');",
      [1],
    ],
    ['Function alias', 'const make = Function;', [1]],
    ['bracket module require', "module['require'](name);", [1]],
    ['Module._load', 'Module._load(name);', [1]],
    ['getBuiltinModule', "process.getBuiltinModule('node:module');", [1]],
    ['loader name string', "const loader = 'createRequire';", [1]],
    [
      'ed25519 named import',
      "import { ed25519 } from '@noble/curves/ed25519.js';",
      [1],
    ],
    [
      'mixed named import',
      "import { ed25519, x25519 } from '@noble/curves/ed25519.js';",
      [1],
    ],
    [
      'aliased binding import',
      "import { ed25519 as curve } from '@noble/curves/ed25519.js';",
      [1],
    ],
    [
      'namespace import',
      "import * as curves from '@noble/curves/ed25519.js';",
      [1],
    ],
    ['default import', "import curves from '@noble/curves/ed25519.js';", [1]],
    [
      'default with x25519',
      "import curves, { x25519 } from '@noble/curves/ed25519.js';",
      [1],
    ],
    ['side-effect import', "import '@noble/curves/ed25519.js';", [1]],
    [
      'binding re-export',
      "export { ed25519 } from '@noble/curves/ed25519.js';",
      [1],
    ],
    ['star re-export', "export * from '@noble/curves/ed25519.js';", [1]],
    [
      'namespace re-export',
      "export * as curves from '@noble/curves/ed25519.js';",
      [1],
    ],
    [
      'other curve module',
      "import { x25519 } from '@noble/curves/abstract/edwards.js';",
      [1],
    ],
    ['curve root import', "import { ed25519 } from '@noble/curves';", [1]],
    [
      'require call',
      "const { ed25519 } = require('@noble/curves/ed25519.js');",
      [1],
    ],
    [
      'dynamic import',
      "const curves = await import('@noble/curves/ed25519.js');",
      [1],
    ],
    [
      'template dynamic import',
      'const curves = await import(`@noble/curves/ed25519.js`);',
      [1],
    ],
    ['require.resolve', "require.resolve('@noble/curves/ed25519.js');", [1]],
    [
      'createRequire',
      "createRequire(import.meta.url)('@noble/curves/ed25519.js');",
      [1],
    ],
    [
      'concatenated specifier',
      "require('@noble/' + 'curves/ed25519.js');",
      [1],
    ],
    ['template specifier', 'require(`@noble/curves/${"ed25519.js"}`);', [1]],
    [
      'import equals',
      "import curves = require('@noble/curves/ed25519.js');",
      [1],
    ],
    ['identifier require', 'require(name);', [1]],
    [
      'split specifier',
      "require('@no' + 'ble/cu' + 'rves/ed' + '25519.js');",
      [1],
    ],
    ['identifier import', 'import(path);', [1]],
    ['module.require', 'module.require(name);', [1]],
    ['require alias', 'const load = require;', [1]],
    ['createRequire property', 'const load = mod.createRequire;', [1]],
    ['eval call', "eval('1 + 1');", [1]],
    ['local require binding', "const local = require('./local');", []],
    ['literal relative require', "require('./local');", []],
    ['literal node import', "import('node:crypto');", []],
    [
      'unrelated package',
      "import { sha256 } from '@noble/hashes/sha2.js';",
      [],
    ],
    ['constructor escape', "(() => {}).constructor('return require')();", [1]],
    ['string constructor key', "fn['constructor']('x');", [1]],
    ['computed loader key', 'module[name]("node:vm");', [1]],
    ['computed global key', 'globalThis[name](code);', [1]],
    ['vm literal require', "require('node:vm').runInThisContext(code);", [1]],
    ['vm literal import', "import('vm');", [1]],
    ['vm static import', "import { runInThisContext } from 'node:vm';", [1]],
    ['vm run name', 'vm.runInNewContext(code);', [1]],
    ['class constructor', 'class A { constructor() {} }', []],
    ['literal global property', 'const c = globalThis.crypto.subtle;', []],
  ])('%s', (_label, source, lines) => {
    expect(
      ed25519Violations('fixture.ts', source).map((violation) =>
        Number(violation.split(':').pop()),
      ),
    ).toEqual(lines);
  });
});
