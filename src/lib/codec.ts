export const textDecoder = new TextDecoder();

export const textEncoder = new TextEncoder();

export function compressNumber(num: number) {
  return num.toString(36);
}

export function decompressNumber(compressedNumber: string) {
  return parseInt(compressedNumber, 36);
}
