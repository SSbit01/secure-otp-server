export const regexBase64Url = /^[\w-]+$/;

export const BASE64URL_OPTIONS: Parameters<Uint8Array<ArrayBuffer>["toBase64"]>[0] = Object.freeze({
  alphabet: "base64url",
  omitPadding: true
});

export function bytesToBase64Length(bytesLength: number): number {
  return Math.ceil(bytesLength / 3 * 4);
}
