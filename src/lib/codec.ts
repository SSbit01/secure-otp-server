export function compressNumber(num: number) {
  return num.toString(36);
}

export function decompressNumber(compressedNumber: string) {
  return parseInt(compressedNumber, 36);
}
