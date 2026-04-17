import { BASE64URL_OPTIONS } from "@/lib/base64";
import { textDecoder, textEncoder } from "@/lib/text";

const IV_BYTES = 12;
const SYMMETRIC_ENCRYPTION_ALGORITHM_NAME = "AES-GCM";

/**
 * @type {AesKeyGenParams}
 */
export const KEY_ENCRYPTION_PARAMS = Object.freeze({
  name: SYMMETRIC_ENCRYPTION_ALGORITHM_NAME,
  length: 256
});

/**
 * @type {KeyUsage[]}
 */
export const KEY_ENCRYPTION_USAGES = ["encrypt", "decrypt"];

Object.freeze(KEY_ENCRYPTION_USAGES);

/**
 * Before encrypting and decrypting values, a symmetric `CryptoKey` must be created.
 *
 * @async
 * @function createDek
 * @returns {Promise<CryptoKey>} A `CryptoKey` containing a SHA-256 hash used to encrypt and decrypt strings.
 */
export async function createDek() {
  return await crypto.subtle.generateKey(
    KEY_ENCRYPTION_PARAMS,
    true,
    KEY_ENCRYPTION_USAGES
  );
}

/**
 * Encrypts a value with a `CryptoKey` previously generated with `createDek`.
 *
 * @async
 * @function encryptTextSymmetrically
 * @param {CryptoKey} key - Symmetric key generated with `createDek`.
 * @param {string} text - String value to be encrypted.
 * @param {BufferSource} [additionalData] - Additional data for authentication.
 * @returns {Promise<string>} The value encrypted and encoded as a Base64 string.
 * @throws {DOMException} Raised when:
 * - The provided key is not valid.
 * - The operation failed (e.g. AES-GCM plaintext longer than 2^39−256 bytes).
 */
export async function encryptTextSymmetrically(
  key,
  text,
  additionalData
) {
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
 * @async
 * @function decryptTextSymmetrically
 * @param {CryptoKey} key
 * @param {string} ciphertext
 * @param {BufferSource} [additionalData] - Additional data for authentication.
 * @returns {Promise<string>}
 * @throws {DOMException} Raised when:
 * - The provided key is not valid.
 * - The operation failed.
 */
export async function decryptTextSymmetrically(key, ciphertext, additionalData) {
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
