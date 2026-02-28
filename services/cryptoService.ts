
/**
 * Advanced Crypto Service with Integrity Sealing
 * Structure: [MAGIC_BYTES (8B)][SALT (16B)][IV (12B)][META_LEN (4B)][ENC_META][ENC_CONTENT]
 */

const PBKDF2_ITERATIONS = 100000;
const SALT_SIZE = 16;
const IV_SIZE = 12;
const TAG_SIZE = 16;
const CHUNK_SIZE = 1024 * 1024; // 1MB chunks for streaming
const MAGIC_BYTES = new TextEncoder().encode("SECUREV2"); // Header to identify legitimate files

export interface FileMetadata {
  origin: string;
  timestamp: number;
  originalName: string;
  legitimacyToken: string;
  totalSize: number;
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

async function hashFileStreaming(file: File): Promise<Uint8Array> {
  const CHUNK_SIZE_HASH = 1024 * 1024; // 1MB chunks
  let currentHash = new Uint8Array(32); // Initial seed (SHA-256 size)
  let offset = 0;
  
  while (offset < file.size) {
    const chunk = file.slice(offset, offset + CHUNK_SIZE_HASH);
    const buffer = await chunk.arrayBuffer();
    const dataToHash = new Uint8Array(currentHash.length + buffer.byteLength);
    dataToHash.set(currentHash);
    dataToHash.set(new Uint8Array(buffer), currentHash.length);
    
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataToHash);
    currentHash = new Uint8Array(hashBuffer);
    offset += CHUNK_SIZE_HASH;
  }
  
  return currentHash;
}

async function deriveKey(keyFile: File, password: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyFileHash = await hashFileStreaming(keyFile);
  const passwordBuffer = new TextEncoder().encode(password);
  const combined = new Uint8Array(keyFileHash.length + passwordBuffer.byteLength);
  combined.set(keyFileHash, 0);
  combined.set(passwordBuffer, keyFileHash.length);

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
    legitimacyToken: crypto.randomUUID(),
    totalSize: targetFile.size
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
    
    if (decContent.byteLength !== meta.totalSize) {
      throw new Error("Integrity Failure: File size mismatch");
    }

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
    legitimacyToken: crypto.randomUUID(),
    totalSize: targetFile.size
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
      controller.enqueue(MAGIC_BYTES);
      controller.enqueue(salt);
      controller.enqueue(initialIv);
      controller.enqueue(new Uint8Array(chunkSizeBuf.buffer));
      controller.enqueue(new Uint8Array(metaLen.buffer));
      controller.enqueue(new Uint8Array(encMeta));
    },

    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        
        if (done) {
          if (onProgress) onProgress(100);
          controller.close();
          reader.releaseLock();
          return;
        }

        const encryptedChunk = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: currentIv },
          key,
          value
        );

        const chunkLenBuf = new Uint32Array([encryptedChunk.byteLength]);
        controller.enqueue(new Uint8Array(chunkLenBuf.buffer));
        controller.enqueue(new Uint8Array(encryptedChunk));

        currentIv = incrementIV(currentIv);
        bytesProcessed += value.byteLength;
        if (onProgress) onProgress(Math.round((bytesProcessed / totalSize) * 100));
      } catch (e) {
        reader.releaseLock();
        controller.error(e);
      }
    },

    cancel() {
      reader.cancel();
      reader.releaseLock();
    }
  });
}

// Helper to read exactly N bytes from the stream efficiently
async function readBytes(reader: ReadableStreamDefaultReader<Uint8Array>, n: number, existingBuffer: Uint8Array | null = null): Promise<{ data: Uint8Array, leftover: Uint8Array | null }> {
  if (existingBuffer && existingBuffer.length >= n) {
    return { 
      data: existingBuffer.slice(0, n), 
      leftover: existingBuffer.length > n ? existingBuffer.slice(n) : null 
    };
  }

  let result = existingBuffer || new Uint8Array(0);
  
  try {
    while (result.length < n) {
      const { done, value } = await reader.read();
      if (done) break;
      
      const newResult = new Uint8Array(result.length + value.length);
      newResult.set(result);
      newResult.set(value, result.length);
      result = newResult;
    }
    
    const data = result.slice(0, n);
    const leftover = result.length > n ? result.slice(n) : null;
    
    // Help GC
    result = null as any;
    
    return { data, leftover };
  } catch (e) {
    throw e;
  }
}

export async function decryptFileStream(
  encryptedFile: File,
  keyFile: File,
  password: string = "",
  onProgress?: (percent: number) => void
): Promise<{ stream: ReadableStream, meta: FileMetadata }> {
  const reader = encryptedFile.stream().getReader();
  let streamLeftover: Uint8Array | null = null;
  
  try {
    // 1. Read Header
    let magicRes = await readBytes(reader, MAGIC_BYTES.length, streamLeftover);
    if (new TextDecoder().decode(magicRes.data) !== "SECUREV2") throw new Error("Invalid Source");
    streamLeftover = magicRes.leftover;

    let saltRes = await readBytes(reader, SALT_SIZE, streamLeftover);
    const salt = saltRes.data;
    streamLeftover = saltRes.leftover;
    
    let ivRes = await readBytes(reader, IV_SIZE, streamLeftover);
    const initialIv = ivRes.data;
    streamLeftover = ivRes.leftover;

    let chunkSizeRes = await readBytes(reader, 4, streamLeftover);
    streamLeftover = chunkSizeRes.leftover;
    
    let metaLenRes = await readBytes(reader, 4, streamLeftover);
    const metaLen = new Uint32Array(metaLenRes.data.buffer)[0];
    streamLeftover = metaLenRes.leftover;

    let encMetaRes = await readBytes(reader, metaLen, streamLeftover);
    const encMeta = encMetaRes.data;
    streamLeftover = encMetaRes.leftover;

    const key = await deriveKey(keyFile, password, salt);

    let meta: FileMetadata;
    try {
      const decMetaBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: initialIv }, key, encMeta);
      meta = JSON.parse(new TextDecoder().decode(decMetaBuf));
    } catch (e) {
      throw new Error("Integrity Failure");
    }

    let currentIv = incrementIV(initialIv);
    let decryptedBytesProcessed = 0;
    let encryptedBytesProcessed = 0;
    const totalEncryptedSize = encryptedFile.size;

    const stream = new ReadableStream({
      async pull(controller) {
        try {
          // Read next chunk length
          let chunkLenRes = await readBytes(reader, 4, streamLeftover);
          if (chunkLenRes.data.length < 4) {
            if (decryptedBytesProcessed < meta.totalSize) {
              controller.error(new Error("Integrity Failure: File is incomplete or truncated"));
              return;
            }
            if (onProgress) onProgress(100);
            controller.close();
            reader.releaseLock();
            return;
          }
          const chunkLen = new Uint32Array(chunkLenRes.data.buffer)[0];
          streamLeftover = chunkLenRes.leftover;
          
          // Read the encrypted chunk
          let encChunkRes = await readBytes(reader, chunkLen, streamLeftover);
          const encChunk = encChunkRes.data;
          streamLeftover = encChunkRes.leftover;

          const decryptedChunk = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: currentIv },
            key,
            encChunk
          );
          const decryptedData = new Uint8Array(decryptedChunk);
          controller.enqueue(decryptedData);
          
          currentIv = incrementIV(currentIv);
          decryptedBytesProcessed += decryptedData.length;
          encryptedBytesProcessed += chunkLen + 4; 
          if (onProgress) onProgress(Math.min(99, Math.round((encryptedBytesProcessed / totalEncryptedSize) * 100)));
        } catch (e) {
          reader.releaseLock();
          controller.error(e);
        }
      },
      cancel() {
        reader.cancel();
        reader.releaseLock();
      }
    });

    return { stream, meta };
  } catch (e) {
    reader.releaseLock();
    throw e;
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
    // RAM Spike Warning: This buffers everything in memory.
    // We should warn the user if the file is large.
    const chunks: Uint8Array[] = [];
    const reader = data.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
      }
      blob = new Blob(chunks, { type: mimeType });
    } finally {
      reader.releaseLock();
    }
  } else {
    blob = data instanceof Blob ? data : new Blob([data], { type: mimeType });
  }

  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.style.display = 'none'; a.href = url; a.download = suggestedName;
  document.body.appendChild(a); a.click();
  
  // Cleanup
  setTimeout(() => {
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    blob = null as any;
  }, 100);
}

export function generateRandomKeyFile(): File {
  const randomBytes = crypto.getRandomValues(new Uint8Array(256));
  const blob = new Blob([randomBytes], { type: 'application/octet-stream' });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  return new File([blob], `master-key-${timestamp}.key`, { type: 'application/octet-stream' });
}
