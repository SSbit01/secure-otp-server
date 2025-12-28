import { BASE64URL_OPTIONS } from "@/lib/base64"


/** @type {Parameters<Uint8Array<ArrayBuffer>["toBase64"]>[0]} */
const DATA_BASE64_OPTIONS = {
  ...BASE64URL_OPTIONS,
  omitPadding: true
}


export const IV_BYTES = 12
export const SYMMETRIC_ENCRYPTION_ALGORITHM = "AES-GCM"


/**
 * @type {AesKeyGenParams}
 */
export const KEY_ENCRYPTION_PARAMS = Object.freeze({
  name: SYMMETRIC_ENCRYPTION_ALGORITHM,
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
 * @param   {CryptoKey}       key            - Symmetric key generated with `createDek`.
 * @param   {string}          text           - String value to be encrypted.
 * @param   {TextEncoder}     [textEncoder]  - If you have an instance of a `TextEncoder`, you can reuse it.
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

  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES))

  return (
    iv.toBase64(BASE64URL_OPTIONS) +
    new Uint8Array(
      await crypto.subtle.encrypt(
        { name: SYMMETRIC_ENCRYPTION_ALGORITHM, iv },
        key,
        textEncoder.encode(text)
      )
    ).toBase64(DATA_BASE64_OPTIONS)
  )

}