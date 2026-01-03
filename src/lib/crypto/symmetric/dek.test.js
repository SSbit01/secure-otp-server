import { describe, expect, test } from "bun:test"

import { createDek, encryptTextSymmetrically, decryptTextSymmetrically } from "@/lib/crypto/symmetric/dek"
import { createRandomIdString } from "@/lib/crypto/id"



describe("DEK", () => {

  test("Generate a random symmetric CryptoKey", async () => {
    const key = await createDek()
    expect(key).toBeDefined()
  })
  
  test("Encrypt a random value", async () => { 
    const key = await createDek()
    expect(await encryptTextSymmetrically(key, createRandomIdString())).toBeString()
  })
  
  test("Decrypt a random value", async () => {
    const symCryptoKey = await createDek()
    const randomValue = createRandomIdString()
    const ciphertext = await encryptTextSymmetrically(symCryptoKey, randomValue)
    const decrypted = await decryptTextSymmetrically(symCryptoKey, ciphertext)
    expect(randomValue).toBe(decrypted)
  })
  
  test("Check if encrypting and decrypting with different CryptoKey objects returns an error", async () => {
    const symCryptoKey = await createDek()
    const symCryptoKey2 = await createDek()
    const randomValue = createRandomIdString()
    const ciphertext = await encryptTextSymmetrically(symCryptoKey, randomValue)
    await expect(decryptTextSymmetrically(symCryptoKey2, ciphertext)).rejects.toThrow()
  })

})