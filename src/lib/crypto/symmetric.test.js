import { expect, test } from "bun:test"
import { createRandomId } from "@/lib/crypto/id"
import { createSymmetricKey, encryptTextSymmetrically, decryptTextSymmetrically } from "./symmetric"


test("Generate a random symmetric CryptoKey", async () => {
  const key = await createSymmetricKey()
  expect(key).toBeDefined()
})

test("Encrypt a random value", async () => {
  const key = await createSymmetricKey()
  expect(await encryptTextSymmetrically(key, createRandomId())).toBeString()
})

test("Decrypt a random value", async () => {
  const symCryptoKey = await createSymmetricKey()
  const randomValue = createRandomId()
  const ciphertext = await encryptTextSymmetrically(symCryptoKey, randomValue)
  const decrypted = await decryptTextSymmetrically(symCryptoKey, ciphertext)
  expect(randomValue).toBe(decrypted)
})

test("Check if encrypting and decrypting with different CryptoKey objects returns an error", async () => {
  const symCryptoKey = await createSymmetricKey()
  const symCryptoKey2 = await createSymmetricKey()
  const randomValue = createRandomId()
  const ciphertext = await encryptTextSymmetrically(symCryptoKey, randomValue)
  await expect(decryptTextSymmetrically(symCryptoKey2, ciphertext)).rejects.toThrow()
})