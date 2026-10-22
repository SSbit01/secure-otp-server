import { BASE64URL_OPTIONS } from "@/lib/base64";
import { textDecoder, textEncoder } from "@/lib/text";

const IV_BYTES = 12;
const SYMMETRIC_ENCRYPTION_ALGORITHM_NAME = "AES-GCM";

export const KEY_ENCRYPTION_PARAMS: AesKeyGenParams = Object.freeze({
  name: SYMMETRIC_ENCRYPTION_ALGORITHM_NAME,
  length: 256
});

export const KEY_ENCRYPTION_USAGES: KeyUsage[] = ["encrypt", "decrypt"];

Object.freeze(KEY_ENCRYPTION_USAGES);

/**
 * Before encrypting and decrypting values, a symmetric `CryptoKey` must be created.
 */
export async function createDek(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey(
    KEY_ENCRYPTION_PARAMS,
    true,
    KEY_ENCRYPTION_USAGES
  );
}

/**
 * Encrypts a value with a `CryptoKey` previously generated with `createDek`.
 *
 * @throws {DOMException} Raised when:
 * - The provided key is not valid.
 * - The operation failed (e.g. AES-GCM plaintext longer than 2^39−256 bytes).
 */
export async function encryptTextSymmetrically(
  key: CryptoKey,
  text: string,
  additionalData?: BufferSource
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));

  const encryptedText = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: SYMMETRIC_ENCRYPTION_ALGORITHM_NAME, iv, additionalData },
      key,
      textEncoder.encode(text)
    )
  );

  const result = new Uint8Array(IV_BYTES + encryptedText.length);

  result.set(iv);
  result.set(encryptedText, IV_BYTES);

  return result.toBase64(BASE64URL_OPTIONS);
}

/**
 * @throws {DOMException} Raised when:
 * - The provided key is not valid.
 * - The operation failed.
 */
export async function decryptTextSymmetrically(key: CryptoKey, ciphertext: string, additionalData?: BufferSource): Promise<string> {
  const data = Uint8Array.fromBase64(ciphertext, BASE64URL_OPTIONS);

  return textDecoder.decode(
    await crypto.subtle.decrypt(
      {
        name: SYMMETRIC_ENCRYPTION_ALGORITHM_NAME,
        iv: data.subarray(0, IV_BYTES),
        additionalData
      },
      key,
      data.subarray(IV_BYTES)
    )
  );
}
