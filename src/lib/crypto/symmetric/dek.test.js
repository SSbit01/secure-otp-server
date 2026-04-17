import { describe, expect, test } from "bun:test";
import { createDek, decryptTextSymmetrically, encryptTextSymmetrically } from "@/lib/crypto/symmetric/dek";

function randomString() {
  return crypto.getRandomValues(new Uint8Array(24)).toBase64();
}

describe("DEK", () => {
  test("Generate a random symmetric CryptoKey", async () => {
    const key = await createDek();
    expect(key).toBeDefined();
  });

  test("Encrypt a random value", async () => {
    const key = await createDek();
    expect(await encryptTextSymmetrically(key, randomString())).toBeString();
  });

  test("Decrypt a random value", async () => {
    const symCryptoKey = await createDek();
    const randomValue = randomString();
    const ciphertext = await encryptTextSymmetrically(symCryptoKey, randomValue);
    const decrypted = await decryptTextSymmetrically(symCryptoKey, ciphertext);
    expect(randomValue).toBe(decrypted);
  });

  test("Check if encrypting and decrypting with different CryptoKey objects returns an error", async () => {
    const symCryptoKey = await createDek();
    const symCryptoKey2 = await createDek();
    const randomValue = randomString();
    const ciphertext = await encryptTextSymmetrically(symCryptoKey, randomValue);
    await expect(decryptTextSymmetrically(symCryptoKey2, ciphertext)).rejects.toThrow();
  });
});
