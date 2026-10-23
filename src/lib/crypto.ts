import { BASE64URL_OPTIONS } from "@/lib/base64";
import { textDecoder, textEncoder } from "@/lib/codec";

const IV_BYTES = 12;

const SYMMETRIC_ENCRYPTION_ALGORITHM_NAME = "AES-GCM";

const KEY_ENCRYPTION_PARAMS: AesKeyGenParams = Object.freeze({
  name: SYMMETRIC_ENCRYPTION_ALGORITHM_NAME,
  length: 256
});

const KEY_ENCRYPTION_USAGES: readonly KeyUsage[] = Object.freeze(["encrypt", "decrypt"]);

const KEY_WRAP_ALGORITHM_NAME = "AES-KW";

const KEY_WRAP_PARAMS: AesKeyGenParams = Object.freeze({
  name: KEY_WRAP_ALGORITHM_NAME,
  length: 256
});

const KEY_WRAP_USAGES: readonly KeyUsage[] = Object.freeze(["wrapKey", "unwrapKey"]);

/**
 * 32 (original DEK size) + 8 (AES-KW overhead) = 40
 */
export const WRAPPED_DEK_BYTES = KEY_ENCRYPTION_PARAMS.length / 8 + 8;

export async function createKek(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey(
    KEY_WRAP_PARAMS,
    true,
    KEY_WRAP_USAGES
  );
}

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

/**
 * This implementation generates a cryptographically secure 96-bit length random value by default.
 *
 * - Unlike UUIDv7 or ULID, this ID is not time-based, mitigating risks of timing attacks and timestamp leakage.
 *
 * @param length - The length of the ID to generate (18 by default; higher entropy than UUIDv4 [122 vs 144 bits]).
 */
export function generateRandomId(length = 18): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * @throws {InvalidAccessError} Raised when the wrapping key is not a key for the requested wrap algorithm.
 * @throws {NotSupported} Raised when trying to use an algorithm that is either unknown or isn't suitable for encryption or wrapping.
 * @throws {SyntaxError} Raised when `keyUsages` is empty but the unwrapped key is of type `secret` or `private`.
 * @throws {TypeError} Raised when trying to use an invalid format.
 */
export async function unwrapKey(wrappedKey: BufferSource, kek: CryptoKey): Promise<CryptoKey> {
  return await crypto.subtle.unwrapKey(
    "raw",
    wrappedKey,
    kek,
    KEY_WRAP_ALGORITHM_NAME,
    KEY_ENCRYPTION_PARAMS,
    false,
    KEY_ENCRYPTION_USAGES
  );
}

/**
 * @throws {InvalidAccessError} Raised when the wrapping key is not a key for the requested wrap algorithm.
 * @throws {NotSupported} Raised when trying to use an algorithm that is either unknown or isn't suitable for encryption or wrapping.
 * @throws {TypeError} Raised when trying to use an invalid format.
 */
export async function wrapKey(key: CryptoKey, kek: CryptoKey): Promise<ArrayBuffer> {
  return await crypto.subtle.wrapKey(
    "raw",
    key,
    kek,
    KEY_WRAP_ALGORITHM_NAME
  );
}
