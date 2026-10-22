import { KEY_ENCRYPTION_PARAMS, KEY_ENCRYPTION_USAGES } from "@/lib/crypto/symmetric/dek";

const KEY_WRAP_PARAMS: AesKeyGenParams = Object.freeze({
  name: "AES-KW",
  length: 256
});

const KEY_WRAP_USAGES: readonly KeyUsage[] = Object.freeze(["wrapKey", "unwrapKey"]);

export const WRAPPED_DEK_BYTES = 40;

export async function createKek(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey(
    KEY_WRAP_PARAMS,
    true,
    KEY_WRAP_USAGES
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
    KEY_WRAP_PARAMS
  );
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
    KEY_WRAP_PARAMS,
    KEY_ENCRYPTION_PARAMS,
    false,
    KEY_ENCRYPTION_USAGES
  );
}
