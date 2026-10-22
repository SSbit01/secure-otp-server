export function encodeCredential(credential: string): string {
  return encodeURI(credential);
}

export function decodeCredential(encodedCredential: string): string {
  return decodeURI(encodedCredential).trim();
}
