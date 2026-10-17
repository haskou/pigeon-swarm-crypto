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

const isModuleLoader = (callee: ts.Expression): boolean =>
  callee.kind === ts.SyntaxKind.ImportKeyword ||
  (ts.isIdentifier(callee) &&
    (callee.text === 'require' || callee.text === 'createRequire')) ||
  (ts.isPropertyAccessExpression(callee) &&
    (callee.name.text === 'require' ||
      (ts.isIdentifier(callee.expression) &&
        callee.expression.text === 'require')));

const isCreateRequire = (callee: ts.Expression): boolean =>
  ts.isIdentifier(callee) && callee.text === 'createRequire';

// Outside the adapter, the only permitted reference to @noble/curves' ed25519
// module is a static import or re-export of x25519. Every other route to the
// binding is rejected: a module name appearing as a string, or any require,
// require.resolve, module.require, createRequire or import() whose specifier
// is not a plain literal (so concatenation, templates and variables fail).
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

      return;
    }

    if (ts.isCallExpression(node) && isModuleLoader(node.expression)) {
      const [specifier] = node.arguments;

      if (
        isCreateRequire(node.expression) ||
        specifier === undefined ||
        !ts.isStringLiteralLike(specifier)
      )
        report(node);
    }

    if (isStringLike(node) && curveText.test(node.text)) report(node);

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

  it('keeps the adapter as the one module importing the binding', () => {
    expect(sourceOf(adapter)).toMatch(
      /import \{ ed25519, x25519 \} from '@noble\/curves\/ed25519\.js';/,
    );
  });

  it('keeps exactly one ed25519.verify call, inside the adapter', () => {
    expect(sourceOf(adapter).match(/\bed25519\s*\.\s*verify\b/g)).toHaveLength(
      1,
    );
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
    ['literal relative require', "require('./local');", []],
    ['literal node import', "import('node:crypto');", []],
    [
      'unrelated package',
      "import { sha256 } from '@noble/hashes/sha2.js';",
      [],
    ],
  ])('%s', (_label, source, lines) => {
    expect(
      ed25519Violations('fixture.ts', source).map((violation) =>
        Number(violation.split(':').pop()),
      ),
    ).toEqual(lines);
  });
});
