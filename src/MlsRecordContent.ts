export interface MlsRecordContent {
  epoch?: number;
  groupId: string;
  kind: string;
  payload: string;
  recipientIdentityId?: string;
}
