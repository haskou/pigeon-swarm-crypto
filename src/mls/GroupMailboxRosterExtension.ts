import type { GroupMailboxRosterFields } from './GroupMailboxRosterFields';
import type { MlsContextExtension } from './MlsContextExtension';

import { StrictCanonicalJson } from '../internal/StrictCanonicalJson';
import { InvalidMlsExtensionError } from './InvalidMlsExtensionError';

/**
 * The GroupContext extension 0xf421 of a group conversation: its roster as
 * RFC 8785 canonical JSON with a closed set of keys and sorted identity lists.
 */
export class GroupMailboxRosterExtension {
  private static readonly VERSION = 1;
  private static readonly MAX_PARTICIPANTS = 256;
  private static readonly MAX_IDENTITY_LENGTH = 1024;
  private static readonly MAX_NAME_LENGTH = 80;
  private static readonly KEYS =
    'adminIds,conversationId,creatorId,memberIds,name,version';

  private static readonly CONVERSATION_ID =
    /^group:[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

  private static readonly LONE_SURROGATE = /\p{Cs}/u;
  private static readonly decoder = new TextDecoder('utf-8', { fatal: true });
  public static readonly EXTENSION_TYPE = 0xf421;
  public static readonly MAX_BYTES = 1_048_576;

  private static text(value: unknown, maximumLength: number): boolean {
    return (
      typeof value === 'string' &&
      value !== '' &&
      value.length <= maximumLength &&
      value.trim() === value &&
      !GroupMailboxRosterExtension.LONE_SURROGATE.test(value)
    );
  }

  private static identities(value: unknown): value is string[] {
    return (
      Array.isArray(value) &&
      value.length <= GroupMailboxRosterExtension.MAX_PARTICIPANTS &&
      value.every((identityId) =>
        GroupMailboxRosterExtension.text(
          identityId,
          GroupMailboxRosterExtension.MAX_IDENTITY_LENGTH,
        ),
      ) &&
      new Set(value).size === value.length
    );
  }

  private static roles({
    adminIds,
    creatorId,
    memberIds,
  }: Record<keyof GroupMailboxRosterFields, unknown>): boolean {
    return (
      GroupMailboxRosterExtension.identities(memberIds) &&
      GroupMailboxRosterExtension.identities(adminIds) &&
      memberIds.includes(creatorId as string) &&
      !adminIds.includes(creatorId as string) &&
      adminIds.every((adminId) => memberIds.includes(adminId))
    );
  }

  private static valid(value: unknown): value is GroupMailboxRosterFields {
    if (
      typeof value !== 'object' ||
      value === null ||
      Object.keys(value).sort().join(',') !== GroupMailboxRosterExtension.KEYS
    )
      return false;
    const fields = value as Record<keyof GroupMailboxRosterFields, unknown>;

    return (
      fields.version === GroupMailboxRosterExtension.VERSION &&
      typeof fields.conversationId === 'string' &&
      GroupMailboxRosterExtension.CONVERSATION_ID.test(fields.conversationId) &&
      GroupMailboxRosterExtension.text(
        fields.name,
        GroupMailboxRosterExtension.MAX_NAME_LENGTH,
      ) &&
      GroupMailboxRosterExtension.roles(fields)
    );
  }

  private static sorted(values: readonly string[]): string[] {
    return [...values].sort((left, right) => (left < right ? -1 : 1));
  }

  private static canonical(fields: GroupMailboxRosterFields): string {
    return StrictCanonicalJson.serialize({
      adminIds: GroupMailboxRosterExtension.sorted(fields.adminIds),
      conversationId: fields.conversationId,
      creatorId: fields.creatorId,
      memberIds: GroupMailboxRosterExtension.sorted(fields.memberIds),
      name: fields.name,
      version: fields.version,
    });
  }

  public static encode(fields: GroupMailboxRosterFields): Uint8Array {
    if (!GroupMailboxRosterExtension.valid({ ...fields }))
      throw new InvalidMlsExtensionError();

    return new TextEncoder().encode(
      GroupMailboxRosterExtension.canonical(fields),
    );
  }

  public static decode(bytes: Uint8Array): GroupMailboxRosterFields {
    if (bytes.length > GroupMailboxRosterExtension.MAX_BYTES)
      throw new InvalidMlsExtensionError();
    let text: string;
    let value: unknown;

    try {
      text = GroupMailboxRosterExtension.decoder.decode(bytes);
      value = JSON.parse(text);
    } catch {
      throw new InvalidMlsExtensionError();
    }

    if (
      !GroupMailboxRosterExtension.valid(value) ||
      GroupMailboxRosterExtension.canonical(value) !== text
    )
      throw new InvalidMlsExtensionError();

    return value;
  }

  /** The roster of a GroupContext holding exactly this one extension. */
  public static read(
    extensions: readonly MlsContextExtension[],
  ): GroupMailboxRosterFields {
    const [extension] = extensions;

    if (
      extensions.length !== 1 ||
      extension.extensionType !== GroupMailboxRosterExtension.EXTENSION_TYPE
    )
      throw new InvalidMlsExtensionError();

    return GroupMailboxRosterExtension.decode(extension.extensionData);
  }
}
