const encryptionAlgorithm = "AES-GCM"

const keyParams = {
  name: encryptionAlgorithm,
  length: 256
}

const ivBytesLength = 12



/**
 * @type {readonly KeyUsage[]}
 */
export const keyUsages = Object.freeze(["encrypt", "decrypt"])


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
 * Encrypts a string value.
 * 
 * @async
 * @function encryptSymmetricallyText
 * @param {CryptoKey} key - Symmetric key for AES-GCM encryption.
 * @param {string} value - String value to be encrypted.
 * @returns {Promise<string>} The value encrypted and encoded as a Base64 string.
 * @throws {DOMException} Raised when:
 * - The provided key is not valid.
 * - The operation failed (e.g., AES-GCM plaintext longer than 2^39−256 bytes).
 */
export async function encryptSymmetricallyText(
  key,
  value,
  textEncoder = new TextEncoder()
) {

  const iv = crypto.getRandomValues(new Uint8Array(ivBytesLength))

  return (
    iv.toBase64() +
    new Uint8Array(
      await crypto.subtle.encrypt(
        { name: encryptionAlgorithm, iv },
        key,
        textEncoder.encode(value)
      )
    ).toBase64()
  )

}


/**
 * Decrypts a value into a string.
 * 
 * @async
 * @function decryptSymmetricallyText
 * @param {CryptoKey} key - Symmetric key used to encrypt the value.
 * @param {string} value - Encrypted value to be decrypted.
 * @param {TextDecoder} [textDecoder] - If you have an instance of a `TextDecoder`, you can reuse it.
 * @returns {Promise<string>} The value decrypted.
 * @throws {TypeError} Thrown if `value` is not a string.
 * @throws {SyntaxError} Thrown if `value` contains characters outside Base64 alphabet.
 * @throws {DOMException} Raised when:
 * - The provided key is not valid.
 * - The operation failed.
 */
export async function decryptSymmetricallyText(
  key,
  value,
  textDecoder = new TextDecoder()
) {

  const valueInt8Arr = Uint8Array.fromBase64(value)
  
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