
/**
 * Advanced Crypto Service with Integrity Sealing
 * Structure: [MAGIC_BYTES (8B)][SALT (16B)][IV (12B)][META_LEN (4B)][ENC_META][ENC_CONTENT]
 */

const PBKDF2_ITERATIONS = 100000;
const SALT_SIZE = 16;
const IV_SIZE = 12;
const MAGIC_BYTES = new TextEncoder().encode("SECUREV2"); // Header to identify legitimate files

export interface FileMetadata {
  origin: string;
  timestamp: number;
  originalName: string;
  legitimacyToken: string;
}

/**
 * Reads a file as an ArrayBuffer with progress reporting
 */
async function readFileWithProgress(file: File, onProgress?: (percent: number) => void): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onprogress = (event) => {
      if (event.lengthComputable && onProgress) {
        const percent = Math.round((event.loaded / event.total) * 100);
        onProgress(percent);
      }
    };
    reader.onload = () => resolve(reader.result as ArrayBuffer);
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

async function deriveKey(keyFile: File, password: string, salt: Uint8Array): Promise<CryptoKey> {
  const fileBuffer = await keyFile.arrayBuffer();
  const passwordBuffer = new TextEncoder().encode(password);
  const combined = new Uint8Array(fileBuffer.byteLength + passwordBuffer.byteLength);
  combined.set(new Uint8Array(fileBuffer), 0);
  combined.set(passwordBuffer, fileBuffer.byteLength);

  const baseKey = await crypto.subtle.importKey('raw', combined, 'PBKDF2', false, ['deriveKey']);

  return await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Generic encryption for small data (like the Vault JSON)
 */
export async function encryptData(data: Uint8Array, password: string, salt?: Uint8Array): Promise<Uint8Array> {
  const usedSalt = salt || crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
  
  // For vault, we use a dummy "key file" (just the password again) to reuse deriveKey logic
  // or we can simplify. Let's simplify for the vault case.
  const passwordBuffer = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: usedSalt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  
  const result = new Uint8Array(MAGIC_BYTES.length + usedSalt.length + iv.length + encrypted.byteLength);
  let offset = 0;
  result.set(MAGIC_BYTES, offset); offset += MAGIC_BYTES.length;
  result.set(usedSalt, offset); offset += usedSalt.length;
  result.set(iv, offset); offset += iv.length;
  result.set(new Uint8Array(encrypted), offset);
  
  return result;
}

/**
 * Generic decryption for small data
 */
export async function decryptData(encryptedData: Uint8Array, password: string): Promise<Uint8Array> {
  const magic = encryptedData.slice(0, MAGIC_BYTES.length);
  if (new TextDecoder().decode(magic) !== "SECUREV2") throw new Error("Invalid Source");

  let offset = MAGIC_BYTES.length;
  const salt = encryptedData.slice(offset, offset + SALT_SIZE); offset += SALT_SIZE;
  const iv = encryptedData.slice(offset, offset + IV_SIZE); offset += IV_SIZE;
  const content = encryptedData.slice(offset);

  const passwordBuffer = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, content);
  return new Uint8Array(decrypted);
}

export async function encryptFile(
  targetFile: File, 
  keyFile: File, 
  password: string = "", 
  onProgress?: (percent: number) => void
): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
  const key = await deriveKey(keyFile, password, salt);

  const metadata: FileMetadata = {
    origin: "SecureFile Crypt Authenticated",
    timestamp: Date.now(),
    originalName: targetFile.name,
    legitimacyToken: crypto.randomUUID()
  };
  
  const targetData = await readFileWithProgress(targetFile, onProgress);

  const encMeta = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(metadata))
  );

  const encContent = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    targetData
  );

  if (onProgress) onProgress(100);

  const metaLen = new Uint32Array([encMeta.byteLength]);
  const totalSize = MAGIC_BYTES.length + salt.length + iv.length + 4 + encMeta.byteLength + encContent.byteLength;
  const result = new Uint8Array(totalSize);

  let offset = 0;
  result.set(MAGIC_BYTES, offset); offset += MAGIC_BYTES.length;
  result.set(salt, offset); offset += salt.length;
  result.set(iv, offset); offset += iv.length;
  result.set(new Uint8Array(metaLen.buffer), offset); offset += 4;
  result.set(new Uint8Array(encMeta), offset); offset += encMeta.byteLength;
  result.set(new Uint8Array(encContent), offset);

  return result;
}

export async function decryptFile(
  encryptedBlob: File, 
  keyFile: File, 
  password: string = "", 
  onProgress?: (percent: number) => void
): Promise<{data: Uint8Array, meta: FileMetadata}> {
  const fullDataRaw = await readFileWithProgress(encryptedBlob, onProgress);
  const fullData = new Uint8Array(fullDataRaw);
  
  const magic = fullData.slice(0, MAGIC_BYTES.length);
  if (new TextDecoder().decode(magic) !== "SECUREV2") {
    throw new Error("Invalid Source");
  }

  let offset = MAGIC_BYTES.length;
  const salt = fullData.slice(offset, offset + SALT_SIZE); offset += SALT_SIZE;
  const iv = fullData.slice(offset, offset + IV_SIZE); offset += IV_SIZE;
  const metaLen = new Uint32Array(fullData.slice(offset, offset + 4).buffer)[0]; offset += 4;
  const encMeta = fullData.slice(offset, offset + metaLen); offset += metaLen;
  const encContent = fullData.slice(offset);

  const key = await deriveKey(keyFile, password, salt);

  try {
    const decMetaBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encMeta);
    const meta: FileMetadata = JSON.parse(new TextDecoder().decode(decMetaBuf));
    const decContent = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encContent);
    
    if (onProgress) onProgress(100);
    return { data: new Uint8Array(decContent), meta };
  } catch (error) {
    throw new Error("Integrity Failure");
  }
}

/**
 * Opens a save picker and returns the handle if supported.
 */
export async function getSaveHandle(suggestedName: string, mimeType: string): Promise<any | null> {
  if ('showSaveFilePicker' in window) {
    try {
      return await (window as any).showSaveFilePicker({
        suggestedName: suggestedName,
        types: [{
          description: 'Secure Storage File',
          accept: { [mimeType]: [`.${suggestedName.split('.').pop()}`] },
        }],
      });
    } catch (err: any) {
      if (err.name === 'AbortError') throw err;
      return null;
    }
  }
  return null;
}

/**
 * Writes data directly to a FileSystemFileHandle or triggers legacy download.
 */
export async function writeDataToDestination(
  data: Uint8Array | Blob, 
  handle: any | null, 
  suggestedName: string, 
  mimeType: string
) {
  const blob = data instanceof Blob ? data : new Blob([data], { type: mimeType });

  if (handle) {
    try {
      const writable = await handle.createWritable();
      await writable.write(blob);
      await writable.close();
      return;
    } catch (err) {
      console.warn("Writing to handle failed, falling back to legacy", err);
    }
  }

  // Legacy fallback
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.style.display = 'none'; a.href = url; a.download = suggestedName;
  document.body.appendChild(a); a.click();
  window.URL.revokeObjectURL(url); document.body.removeChild(a);
}

export function generateRandomKeyFile(): File {
  const randomBytes = crypto.getRandomValues(new Uint8Array(256));
  const blob = new Blob([randomBytes], { type: 'application/octet-stream' });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  return new File([blob], `master-key-${timestamp}.key`, { type: 'application/octet-stream' });
}
