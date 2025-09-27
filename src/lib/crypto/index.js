import base64ToBytes from "../base64.js"


const encryptionAlgorithm = "AES-GCM"
const keyParams = {
  name: encryptionAlgorithm,
  length: 256
}
const ivBytesLength = 12



/** @type {KeyUsage[]} */
export const keyUsages = ["encrypt", "decrypt"]


/**
 * Before encrypting and decrypting values, a symmetric `CryptoKey` must be created.
 * 
 * @returns {Promise<CryptoKey>} A `CryptoKey` containing a SHA-256 hash used to encrypt and decrypt strings.
 */
export async function createSymmetricKey() {

  return (
    await crypto.subtle.generateKey(
      keyParams,
      true,
      keyUsages
    )
  )

}


/**
 * Before encrypting and decrypting values, a symmetric `CryptoKey` must be created.
 * This method also converts your value key to a SHA-256 hash.
 * 
 * @param   {string}             data          - String key to be hashed. A 32-byte high entropy string is recommended.
 * @param   {TextEncoder}        [textEncoder] - If you have an instance of a `TextEncoder`, you can reuse it.
 * @returns {Promise<CryptoKey>} A `CryptoKey` containing a SHA-256 hash used to encrypt and decrypt strings.
 * @throws  {TypeError}          Thrown if `value` is invalid.
 */
export async function createSymmetricKeyWithText(
  data,
  textEncoder = new TextEncoder()
) {

  return (
    await crypto.subtle.importKey(
      "raw",
      await crypto.subtle.digest("SHA-256", textEncoder.encode(data)),
      encryptionAlgorithm,
      false,
      keyUsages
    )
  )

}


/**
 * Encrypts a value with a `CryptoKey` previously generated with `createSymmetricKeyWithText`.
 * 
 * @param   {string}          value - String value to be encrypted.
 * @param   {CryptoKey}       key   - Symmetric key generated with `createSymmetricKeyWithText`.
 * @returns {Promise<string>} The value encrypted and encoded as a Base64 string.
 * @throws  {DOMException}    Raised when:
 * - The provided key is not valid.
 * - The operation failed (e.g., AES-GCM plaintext longer than 2^39−256 bytes).
 */
export async function encryptSymmetricallyText(
  value,
  key,
  textEncoder = new TextEncoder()
) {

  const iv = crypto.getRandomValues(new Uint8Array(ivBytesLength))

  return (
    base64ToBytes.encode(iv) +
    base64ToBytes.encode(new Uint8Array(
      await crypto.subtle.encrypt(
        { name: encryptionAlgorithm, iv },
        key,
        textEncoder.encode(value)
      )
    ))
  )

}


/**
 * Decrypts a value with a `CryptoKey` previously generated with `createSymmetricKeyWithText`.
 * 
 * @param   {string}          value         - Encrypted value to be decrypted.
 * @param   {CryptoKey}       key           - Symmetric key used to encrypt the value.
 * @param   {TextDecoder}     [textDecoder] - If you have an instance of a `TextDecoder`, you can reuse it.
 * @returns {Promise<string>} The value decrypted.
 * @throws  {TypeError}       Thrown if `value` is not a string.
 * @throws  {SyntaxError}     Thrown if `value` contains characters outside Base64 alphabet.
 * @throws  {DOMException}    Raised when:
 * - The provided key is not valid.
 * - The operation failed.
 */
export async function decryptSymmetricallyText(
  value,
  key,
  textDecoder = new TextDecoder()
) {

  const valueInt8Arr = base64ToBytes.decode(value)
  
  return (
    textDecoder.decode(
      await crypto.subtle.decrypt(
        { name: encryptionAlgorithm, iv: valueInt8Arr.subarray(0, ivBytesLength) },
        key,
        valueInt8Arr.subarray(ivBytesLength)
      )
    )
  )

}