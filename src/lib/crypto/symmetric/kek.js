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
 * @async
 * @function createKek
 * @returns {Promise<CryptoKey>}
 */
export async function createKek() {

  return (
    await crypto.subtle.generateKey(
      KEY_WRAP_PARAMS,
      true,
      KEY_WRAP_USAGES
    )
  )

}


/**
 * @async
 * @function unwrapKey
 * @param {Uint8Array<ArrayBuffer>} wrappedKey 
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