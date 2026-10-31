const globalTextDecoder = new TextDecoder();

const globalTextEncoder = new TextEncoder();

export function compressNumber(num: number) {
  return num.toString(36);
}

export function decodeText(value: AllowSharedBufferSource): string {
  return globalTextDecoder.decode(value);
}

export function decompressNumber(compressedNumber: string) {
  return parseInt(compressedNumber, 36);
}

export function encodeText(value: string): Uint8Array<ArrayBuffer> {
  return globalTextEncoder.encode(value);
}
