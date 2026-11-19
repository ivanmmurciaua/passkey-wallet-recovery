import { argon2id } from "@noble/hashes/argon2";

// Encrypted backup of the recovery key K (offered right after step 2). The user keeps a
// password-protected file; when rotating, importing it + the password yields the same K,
// so recovery needs no third party.
//
// KDF: Argon2id (memory-hard). AEAD: AES-256-GCM via Web Crypto (no extra deps).
// Blob = versioned JSON envelope.

const KDF = "argon2id" as const;
// One-time export → can afford strong params. ~64 MiB, 3 passes.
const ARGON = { t: 3, m: 65536, p: 1, dkLen: 32 } as const;
const SALT_LEN = 16;
const IV_LEN = 12;

export interface KeyBackupBlob {
  v: 1;
  kdf: typeof KDF;
  t: number;
  m: number;
  p: number;
  salt: string; // base64
  iv: string; // base64
  ct: string; // base64 (ciphertext + GCM tag)
}

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const byte of bytes) s += String.fromCharCode(byte);
  return btoa(s);
}

function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Copy into a fresh plain ArrayBuffer so Web Crypto's BufferSource typing is
// satisfied (TS 5.7+ Uint8Array is generic over ArrayBufferLike, which Web
// Crypto rejects). Cheap, and these buffers are tiny.
function ab(u: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(u.byteLength);
  new Uint8Array(buf).set(u);
  return buf;
}

async function deriveAesKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const pwdBytes = new TextEncoder().encode(password);
  const keyBytes = argon2id(pwdBytes, salt, {
    t: ARGON.t,
    m: ARGON.m,
    p: ARGON.p,
    dkLen: ARGON.dkLen,
  });
  return crypto.subtle.importKey("raw", ab(keyBytes), "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

// Encrypt K_recovery under a password → JSON blob string (downloadable file).
export async function exportKRecovery(
  kRecovery: string,
  password: string,
): Promise<string> {
  if (!password) throw new Error("A password is required to encrypt the backup");
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveAesKey(password, salt);

  const plaintext = new TextEncoder().encode(kRecovery.trim());
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv: ab(iv) }, key, ab(plaintext));

  const blob: KeyBackupBlob = {
    v: 1,
    kdf: KDF,
    t: ARGON.t,
    m: ARGON.m,
    p: ARGON.p,
    salt: b64(salt),
    iv: b64(iv),
    ct: b64(new Uint8Array(ctBuf)),
  };
  return JSON.stringify(blob, null, 2);
}

// Decrypt a backup blob with the password → K_recovery string.
export async function importKRecovery(
  blobJson: string,
  password: string,
): Promise<string> {
  let blob: KeyBackupBlob;
  try {
    blob = JSON.parse(blobJson);
  } catch {
    throw new Error("Backup file is not valid JSON");
  }
  if (blob.v !== 1 || blob.kdf !== KDF) {
    throw new Error("Unsupported backup format");
  }
  const salt = unb64(blob.salt);
  const pwdBytes = new TextEncoder().encode(password);
  const keyBytes = argon2id(pwdBytes, salt, {
    t: blob.t,
    m: blob.m,
    p: blob.p,
    dkLen: 32,
  });
  const key = await crypto.subtle.importKey("raw", ab(keyBytes), "AES-GCM", false, [
    "decrypt",
  ]);

  let ptBuf: ArrayBuffer;
  try {
    ptBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ab(unb64(blob.iv)) },
      key,
      ab(unb64(blob.ct)),
    );
  } catch {
    throw new Error("Wrong password or corrupted backup");
  }
  return new TextDecoder().decode(ptBuf);
}
