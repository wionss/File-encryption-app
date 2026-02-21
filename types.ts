
export enum OperationMode {
  ENCRYPT = 'ENCRYPT',
  DECRYPT = 'DECRYPT'
}

export interface FileState {
  file: File | null;
  name: string;
  size: number;
  type: string;
}

export interface EncryptionResult {
  data: Uint8Array;
  fileName: string;
}

export interface CryptoMetadata {
  iv: Uint8Array;
  content: Uint8Array;
}
