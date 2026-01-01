import { BASE64URL_OPTIONS } from "@/lib/base64"
import { textDecoder, textEncoder } from "@/lib/text"


const IV_BYTES = 12
const SYMMETRIC_ENCRYPTION_ALGORITHM_NAME = "AES-GCM"


/**
 * @type {AesKeyGenParams}
 */
export const KEY_ENCRYPTION_PARAMS = Object.freeze({
  name: SYMMETRIC_ENCRYPTION_ALGORITHM_NAME,
  length: 256
})

/**
 * @type {KeyUsage[]}
 */
export const KEY_ENCRYPTION_USAGES = ["encrypt", "decrypt"]


Object.freeze(KEY_ENCRYPTION_USAGES)


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
  )

}


/**
 * Encrypts a value with a `CryptoKey` previously generated with `createDek`.
 * 
 * @async
 * @function encryptTextSymmetrically
 * @param {CryptoKey} key - Symmetric key generated with `createDek`.
 * @param {string} text - String value to be encrypted.
 * @returns {Promise<Uint8Array<ArrayBuffer>>} The value encrypted.
 * @throws {DOMException} Raised when:
 * - The provided key is not valid.
 * - The operation failed (e.g., AES-GCM plaintext longer than 2^39−256 bytes).
 */
export async function encryptTextSymmetrically(
  key,
  text
) {

  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES))

  const encryptedText = new Uint8Array(await crypto.subtle.encrypt(
    { name: SYMMETRIC_ENCRYPTION_ALGORITHM_NAME, iv },
    key,
    textEncoder.encode(text)
  ))

  const result = new Uint8Array(IV_BYTES + encryptedText.length)

  result.set(iv)
  result.set(encryptedText, IV_BYTES)

  return result

}


/**
 * @async
 * @function decryptDataSymmetrically
 * @param {CryptoKey} key 
 * @param {Uint8Array<ArrayBuffer>} encryptedData 
 * @returns {Promise<string>}
 * @throws {DOMException} Raised when:
 * - The provided key is not valid.
 * - The operation failed.
 */
export async function decryptDataSymmetrically(key, encryptedData) {

  return textDecoder.decode(
    await crypto.subtle.decrypt(
      { name: SYMMETRIC_ENCRYPTION_ALGORITHM_NAME, iv: encryptedData.subarray(0, IV_BYTES) },
      key,
      encryptedData.subarray(IV_BYTES)
    )
  )

}