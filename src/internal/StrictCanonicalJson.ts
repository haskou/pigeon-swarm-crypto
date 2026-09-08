import { Buffer } from 'buffer';
import canonicalize from 'canonicalize';
import {
  createScanner,
  parseTree,
  SyntaxKind,
  type Node,
  type ParseError,
} from 'jsonc-parser';

import { InvalidPrivateOperationError } from '../errors/InvalidPrivateOperationError';

export class StrictCanonicalJson {
  private static checkBounds(json: string): void {
    const scanner = createScanner(json, true);
    let depth = 0;
    let tokens = 0;
    for (
      let token = scanner.scan();
      token !== SyntaxKind.EOF;
      token = scanner.scan()
    ) {
      if (
        token === SyntaxKind.OpenBraceToken ||
        token === SyntaxKind.OpenBracketToken
      )
        depth++;

      if (
        token === SyntaxKind.CloseBraceToken ||
        token === SyntaxKind.CloseBracketToken
      )
        depth--;

      if (depth > 32 || ++tokens > 8192)
        throw new InvalidPrivateOperationError();
    }
  }

  private static checkProperties(node: Node): void {
    const pending = [node];
    while (pending.length) {
      const current = pending.pop()!;

      if (
        current.type === 'string' &&
        /[\uD800-\uDFFF]/u.test(current.value as string)
      )
        throw new InvalidPrivateOperationError();
      const children = current.children ?? [];

      if (current.type === 'object') {
        const names = children.map(
          (property) => property.children![0].value as string,
        );

        if (new Set(names).size !== names.length)
          throw new InvalidPrivateOperationError();
      }
      pending.push(...children);
    }
  }

  public static parse(json: string): Record<string, unknown> {
    if (json.length > 262144 || Buffer.byteLength(json, 'utf8') > 262144)
      throw new InvalidPrivateOperationError();
    this.checkBounds(json);
    const errors: ParseError[] = [];
    const tree = parseTree(json, errors, {
      allowTrailingComma: false,
      disallowComments: true,
    });

    if (!tree || tree.type !== 'object' || errors.length)
      throw new InvalidPrivateOperationError();
    this.checkProperties(tree);
    const value = JSON.parse(json) as Record<string, unknown>;
    this.serialize(value);

    return value;
  }

  public static serialize(value: Record<string, unknown>): string {
    return canonicalize(value)!;
  }
}
