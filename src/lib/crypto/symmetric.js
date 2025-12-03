import { base64Options } from "@/lib/base64"


const encryptionAlgorithm = "AES-GCM"

const ivBytesLength = 12

/**
 * @type {AesKeyGenParams}
 */
const keyParams = Object.freeze({
  name: encryptionAlgorithm,
  length: 256
})

/**
 * @type {readonly KeyUsage[]}
 */
const keyUsages = Object.freeze(["encrypt", "decrypt"])


/**
 * Before encrypting and decrypting values, a symmetric `CryptoKey` must be created.
 * 
 * @async
 * @function createSymmetricKey
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
 * Encrypts a value with a `CryptoKey` previously generated with `createSymmetricKeyFromText`.
 * 
 * @async
 * @function encryptTextSymmetrically
 * @param   {CryptoKey}       key           - Symmetric key generated with `createSymmetricKeyFromText`.
 * @param   {string}          text          - String value to be encrypted.
 * @param   {TextEncoder}     [textEncoder] - If you have an instance of a `TextEncoder`, you can reuse it.
 * @returns {Promise<string>} The value encrypted and encoded as a Base64 string.
 * @throws  {DOMException}    Raised when:
 * - The provided key is not valid.
 * - The operation failed (e.g., AES-GCM plaintext longer than 2^39−256 bytes).
 */
export async function encryptTextSymmetrically(
  key,
  text,
  textEncoder = new TextEncoder()
) {

  const iv = crypto.getRandomValues(new Uint8Array(ivBytesLength))

  return (
    iv.toBase64(base64Options) +
    new Uint8Array(
      await crypto.subtle.encrypt(
        { name: encryptionAlgorithm, iv },
        key,
        textEncoder.encode(text)
      )
    ).toBase64(base64Options)
  )

}


/**
 * Decrypts a value with a `CryptoKey` previously generated with `createSymmetricKeyFromText`.
 * 
 * @async
 * @function decryptTextSymmetrically
 * @param   {CryptoKey}       key           - Symmetric key used to encrypt the value.
 * @param   {string}          encryptedText - Encrypted value to be decrypted.
 * @param   {TextDecoder}     [textDecoder] - If you have an instance of a `TextDecoder`, you can reuse it.
 * @returns {Promise<string>} The value decrypted.
 * @throws  {TypeError}       Thrown if `encryptedText` is not a string.
 * @throws  {SyntaxError}     Thrown if `encryptedText` contains characters outside Base64 alphabet.
 * @throws  {DOMException}    Raised when:
 * - The provided key is not valid.
 * - The operation failed.
 */
export async function decryptTextSymmetrically(
  key,
  encryptedText,
  textDecoder = new TextDecoder()
) {

  const data = Uint8Array.fromBase64(encryptedText, base64Options)

  return textDecoder.decode(
    await crypto.subtle.decrypt(
      { name: encryptionAlgorithm, iv: data.subarray(0, ivBytesLength) },
      key,
      data.subarray(ivBytesLength)
    )
  )

}