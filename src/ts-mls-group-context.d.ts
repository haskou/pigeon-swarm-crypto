declare module 'ts-mls/groupContext.js' {
  import { GroupContext } from 'ts-mls';

  export function encodeGroupContext(context: GroupContext): Uint8Array;
}
