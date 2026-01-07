/**
 * @type {Parameters<Uint8Array<ArrayBuffer>["toBase64"]>[0]}
 */
export const BASE64URL_OPTIONS = Object.freeze({
  alphabet: "base64url",
  omitPadding: true
})


/**
 * @function bytesToBase64Length
 * @param {number} bytesLength - The number of bytes to convert
 * @returns {number} The length of the base64 string (without padding).
 */
export function bytesToBase64Length(bytesLength) {
  return Math.ceil(bytesLength / 3 * 4)
}