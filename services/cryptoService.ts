
/**
 * Advanced Crypto Service with Integrity Sealing
 * Structure: [MAGIC_BYTES (8B)][SALT (16B)][IV (12B)][META_LEN (4B)][ENC_META][ENC_CONTENT]
 */

const PBKDF2_ITERATIONS = 100000;
const SALT_SIZE = 16;
const IV_SIZE = 12;
const TAG_SIZE = 16;
const CHUNK_SIZE = 1024 * 1024; // 1MB chunks for streaming
const MAGIC_V2 = new TextEncoder().encode("SECUREV2"); // Legacy format
const MAGIC_V3 = new TextEncoder().encode("SECUREV3"); // New Streaming format

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

function incrementIV(iv: Uint8Array): Uint8Array {
  const newIv = new Uint8Array(iv);
  for (let i = newIv.length - 1; i >= 0; i--) {
    newIv[i] = (newIv[i] + 1) & 0xFF;
    if (newIv[i] !== 0) break;
  }
  return newIv;
}

/**
 * Generic encryption for small data (like the Vault JSON)
 */
export async function encryptData(data: Uint8Array, password: string, salt?: Uint8Array): Promise<Uint8Array> {
  const usedSalt = salt || crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
  
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
  
  const result = new Uint8Array(MAGIC_V2.length + usedSalt.length + iv.length + encrypted.byteLength);
  let offset = 0;
  result.set(MAGIC_V2, offset); offset += MAGIC_V2.length;
  result.set(usedSalt, offset); offset += usedSalt.length;
  result.set(iv, offset); offset += iv.length;
  result.set(new Uint8Array(encrypted), offset);
  
  return result;
}

/**
 * Generic decryption for small data
 */
export async function decryptData(encryptedData: Uint8Array, password: string): Promise<Uint8Array> {
  const magic = encryptedData.slice(0, MAGIC_V2.length);
  const magicStr = new TextDecoder().decode(magic);
  if (magicStr !== "SECUREV2" && magicStr !== "SECUREV3") throw new Error("Invalid Source");

  let offset = MAGIC_V2.length;
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
  const totalSize = MAGIC_V2.length + salt.length + iv.length + 4 + encMeta.byteLength + encContent.byteLength;
  const result = new Uint8Array(totalSize);

  let offset = 0;
  result.set(MAGIC_V2, offset); offset += MAGIC_V2.length;
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
  
  const magic = fullData.slice(0, MAGIC_V2.length);
  if (new TextDecoder().decode(magic) !== "SECUREV2") {
    throw new Error("Invalid Source");
  }

  let offset = MAGIC_V2.length;
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
 * STREAMING IMPLEMENTATION
 * This allows processing multi-gigabyte files with constant RAM usage (~50MB)
 */

export async function encryptFileStream(
  targetFile: File,
  keyFile: File,
  password: string = "",
  onProgress?: (percent: number) => void
): Promise<ReadableStream> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const initialIv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
  const key = await deriveKey(keyFile, password, salt);

  const metadata: FileMetadata = {
    origin: "SecureFile Crypt Authenticated (Stream)",
    timestamp: Date.now(),
    originalName: targetFile.name,
    legitimacyToken: crypto.randomUUID()
  };

  const encMeta = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: initialIv },
    key,
    new TextEncoder().encode(JSON.stringify(metadata))
  );

  const metaLen = new Uint32Array([encMeta.byteLength]);
  const chunkSizeBuf = new Uint32Array([CHUNK_SIZE]);

  let currentIv = incrementIV(initialIv);
  let bytesProcessed = 0;
  const totalSize = targetFile.size;

  const fileStream = targetFile.stream();
  const reader = fileStream.getReader();

  return new ReadableStream({
    async start(controller) {
      // Write Header
      controller.enqueue(MAGIC_V3);
      controller.enqueue(salt);
      controller.enqueue(initialIv);
      controller.enqueue(new Uint8Array(chunkSizeBuf.buffer));
      controller.enqueue(new Uint8Array(metaLen.buffer));
      controller.enqueue(new Uint8Array(encMeta));
    },

    async pull(controller) {
      const { done, value } = await reader.read();
      
      if (done) {
        if (onProgress) onProgress(100);
        controller.close();
        return;
      }

      // SubtleCrypto encrypts the whole chunk. 
      // If the chunk from the file stream is not exactly CHUNK_SIZE, it's fine (last chunk).
      // However, usually ReadableStream gives chunks of varying sizes.
      // We should ideally buffer them to CHUNK_SIZE for consistency, but AES-GCM works on any size.
      // To keep it simple, we encrypt whatever the reader gives us.
      
      const encryptedChunk = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: currentIv },
        key,
        value
      );

      // Each chunk in the stream will be: [CHUNK_ENC_LEN (4B)][ENC_DATA_WITH_TAG]
      const chunkLenBuf = new Uint32Array([encryptedChunk.byteLength]);
      controller.enqueue(new Uint8Array(chunkLenBuf.buffer));
      controller.enqueue(new Uint8Array(encryptedChunk));

      currentIv = incrementIV(currentIv);
      bytesProcessed += value.byteLength;
      if (onProgress) onProgress(Math.round((bytesProcessed / totalSize) * 100));
    },

    cancel() {
      reader.cancel();
    }
  });
}

export async function decryptFileStream(
  encryptedFile: File,
  keyFile: File,
  password: string = "",
  onProgress?: (percent: number) => void
): Promise<{ stream: ReadableStream, meta: FileMetadata }> {
  const reader = encryptedFile.stream().getReader();
  
  // Helper to read exactly N bytes from the stream
  async function readBytes(n: number, existingBuffer: Uint8Array | null = null): Promise<{ data: Uint8Array, leftover: Uint8Array | null }> {
    let result = existingBuffer || new Uint8Array(0);
    while (result.length < n) {
      const { done, value } = await reader.read();
      if (done) break;
      const newResult = new Uint8Array(result.length + value.length);
      newResult.set(result);
      newResult.set(value, result.length);
      result = newResult;
    }
    return { 
      data: result.slice(0, n), 
      leftover: result.length > n ? result.slice(n) : null 
    };
  }

  // 1. Read Header
  let { data: magic, leftover } = await readBytes(MAGIC_V3.length);
  const magicStr = new TextDecoder().decode(magic);
  
  if (magicStr === "SECUREV2") {
    // FALLBACK TO LEGACY DECRYPTION
    // Since this is a stream, we need to read the whole file to use the old decryptFile
    // This is the only way for legacy files.
    const fullFile = await encryptedFile.arrayBuffer();
    const result = await decryptFile(encryptedFile, keyFile, password, onProgress);
    return {
      stream: new ReadableStream({
        start(controller) {
          controller.enqueue(result.data);
          controller.close();
        }
      }),
      meta: result.meta
    };
  }

  if (magicStr !== "SECUREV3") throw new Error("Invalid Source");

  let saltRes = await readBytes(SALT_SIZE, leftover);
  const salt = saltRes.data;
  
  let ivRes = await readBytes(IV_SIZE, saltRes.leftover);
  const initialIv = ivRes.data;

  let chunkSizeRes = await readBytes(4, ivRes.leftover);
  // We don't strictly need CHUNK_SIZE for decryption if we store individual chunk lengths, 
  // but it's good for metadata.
  
  let metaLenRes = await readBytes(4, chunkSizeRes.leftover);
  const metaLen = new Uint32Array(metaLenRes.data.buffer)[0];

  let encMetaRes = await readBytes(metaLen, metaLenRes.leftover);
  const encMeta = encMetaRes.data;
  let streamLeftover = encMetaRes.leftover;

  const key = await deriveKey(keyFile, password, salt);

  let meta: FileMetadata;
  try {
    const decMetaBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: initialIv }, key, encMeta);
    meta = JSON.parse(new TextDecoder().decode(decMetaBuf));
  } catch (e) {
    throw new Error("Integrity Failure");
  }

  let currentIv = incrementIV(initialIv);
  let bytesProcessed = 0;
  const totalSize = encryptedFile.size;

  const stream = new ReadableStream({
    async pull(controller) {
      // Read next chunk length
      let chunkLenRes = await readBytes(4, streamLeftover);
      if (chunkLenRes.data.length < 4) {
        if (onProgress) onProgress(100);
        controller.close();
        return;
      }
      const chunkLen = new Uint32Array(chunkLenRes.data.buffer)[0];
      
      // Read the encrypted chunk
      let encChunkRes = await readBytes(chunkLen, chunkLenRes.leftover);
      const encChunk = encChunkRes.data;
      streamLeftover = encChunkRes.leftover;

      try {
        const decryptedChunk = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: currentIv },
          key,
          encChunk
        );
        controller.enqueue(new Uint8Array(decryptedChunk));
        
        currentIv = incrementIV(currentIv);
        // Progress is a bit tricky here because we don't know the exact original size easily 
        // without storing it in meta, but we can use the encrypted file size as a proxy.
        bytesProcessed += chunkLen + 4; 
        if (onProgress) onProgress(Math.min(99, Math.round((bytesProcessed / totalSize) * 100)));
      } catch (e) {
        controller.error(new Error("Integrity Failure"));
      }
    },
    cancel() {
      reader.cancel();
    }
  });

  return { stream, meta };
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
  data: Uint8Array | Blob | ReadableStream, 
  handle: any | null, 
  suggestedName: string, 
  mimeType: string
) {
  if (handle) {
    try {
      const writable = await handle.createWritable();
      if (data instanceof ReadableStream) {
        await data.pipeTo(writable);
      } else {
        await writable.write(data instanceof Blob ? data : new Blob([data], { type: mimeType }));
        await writable.close();
      }
      return;
    } catch (err) {
      console.warn("Writing to handle failed, falling back to legacy", err);
    }
  }

  // Legacy fallback for non-streaming or if handle fails
  let blob: Blob;
  if (data instanceof ReadableStream) {
    // This is the "bad" case for RAM, but necessary for legacy browsers
    const chunks = [];
    const reader = data.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    blob = new Blob(chunks, { type: mimeType });
  } else {
    blob = data instanceof Blob ? data : new Blob([data], { type: mimeType });
  }

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
