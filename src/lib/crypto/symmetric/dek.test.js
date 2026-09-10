import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { createDek, decryptTextSymmetrically, encryptTextSymmetrically } from "@/lib/crypto/symmetric/dek";

function randomString() {
  return crypto.getRandomValues(new Uint8Array(24)).toBase64();
}

describe("DEK", () => {
  test("Generate a random symmetric CryptoKey", async () => {
    const key = await createDek();
    assert.ok(key instanceof globalThis.CryptoKey);
  });

  test("Encrypt a random value", async () => {
    const key = await createDek();
    assert.strictEqual(typeof await encryptTextSymmetrically(key, randomString()), "string");
  });

  test("Decrypt a random value", async () => {
    const symCryptoKey = await createDek();
    const randomValue = randomString();
    const ciphertext = await encryptTextSymmetrically(symCryptoKey, randomValue);
    const decrypted = await decryptTextSymmetrically(symCryptoKey, ciphertext);
    assert.strictEqual(randomValue, decrypted);
  });

  test("Check if encrypting and decrypting with different CryptoKey objects returns an error", async () => {
    const symCryptoKey = await createDek();
    const symCryptoKey2 = await createDek();
    const randomValue = randomString();
    const ciphertext = await encryptTextSymmetrically(symCryptoKey, randomValue);
    await assert.rejects(decryptTextSymmetrically(symCryptoKey2, ciphertext));
  });
});
