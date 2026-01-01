import { KEY_ENCRYPTION_PARAMS, KEY_ENCRYPTION_USAGES } from "@/lib/crypto/symmetric/dek"


const KEY_WRAP_ALGORITHM = Object.freeze({
  name: "AES-KW"
})

/**
 * @type {AesKeyGenParams}
 */
const KEY_WRAP_PARAMS = Object.freeze({
  ...KEY_WRAP_ALGORITHM,
  length: 256
})

/**
 * @type {readonly KeyUsage[]}
 */
const KEY_WRAP_USAGES = Object.freeze(["wrapKey", "unwrapKey"])


/**
 * AES-KW adds 8 extra bytes of authenticated integrity value (AIV).
 * That's why we need to add 8 to 32 (AES-256) = 40.
 */
export const WRAPPED_DEK_BYTES = 40


/**
 * @async
 * @function createKek
 * @returns {Promise<CryptoKey>}
 */
export async function createKek() {

  return await crypto.subtle.generateKey(
    KEY_WRAP_PARAMS,
    true,
    KEY_WRAP_USAGES
  )

}


/**
 * @async
 * @function wrapKey
 * @param {CryptoKey} key 
 * @param {CryptoKey} kek 
 * @returns {Promise<ArrayBuffer>}
 * @throws {InvalidAccessError} Raised when the wrapping key is not a key for the requested wrap algorithm.
 * @throws {NotSupported} Raised when trying to use an algorithm that is either unknown or isn't suitable for encryption or wrapping.
 * @throws {TypeError} Raised when trying to use an invalid format.
 */
export async function wrapKey(key, kek) {

  return await crypto.subtle.wrapKey(
    "raw",
    key,
    kek,
    KEY_WRAP_ALGORITHM
  )

}


/**
 * @async
 * @function unwrapKey
 * @param {BufferSource} wrappedKey 
 * @param {CryptoKey} kek 
 * @returns {Promise<CryptoKey>}
 * @throws {InvalidAccessError} Raised when the wrapping key is not a key for the requested wrap algorithm.
 * @throws {NotSupported} Raised when trying to use an algorithm that is either unknown or isn't suitable for encryption or wrapping.
 * @throws {SyntaxError} Raised when `keyUsages` is empty but the unwrapped key is of type `secret` or `private`.
 * @throws {TypeError} Raised when trying to use an invalid format.
 */
export async function unwrapKey(wrappedKey, kek) {

  return await crypto.subtle.unwrapKey(
    "raw",
    wrappedKey,
    kek,
    KEY_WRAP_PARAMS,
    KEY_ENCRYPTION_PARAMS,
    false,
    KEY_ENCRYPTION_USAGES
  )

}