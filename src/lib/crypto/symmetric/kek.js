import { KEY_ENCRYPTION_PARAMS, KEY_ENCRYPTION_USAGES } from "@/lib/crypto/symmetric/dek"


/**
 * @type {AesKeyGenParams}
 */
const KEY_WRAP_PARAMS = Object.freeze({
  name: "AES-KW",
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
 */
export async function wrapKey(key, kek) {

  return await crypto.subtle.wrapKey(
    "raw",
    key,
    kek,
    KEY_WRAP_PARAMS
  )

}


/**
 * @async
 * @function unwrapKey
 * @param {BufferSource} wrappedKey 
 * @param {CryptoKey} kek 
 * @returns {Promise<CryptoKey>}
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